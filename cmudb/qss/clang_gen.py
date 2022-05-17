import clang_parser
import clang


OMIT_PREPEND_FIELDS = [
    "plan_node_id",
    "startup_cost",
    "total_cost",
]


def construct_with_indent(indent, output):
    return ("\t" * indent) + output


def get_num_key(field_name):
    # This assumes that "X_Y" --> "X_numY" is the key for identifying the length.
    components = field_name.split("_")
    components[-1] = "Num" + components[-1]
    key = ("_".join(components[1:]))
    return key


def is_pointer_array_field(field_name, fields):
    key = get_num_key(field_name)
    for field in fields:
        if field.name == key:
            return True
    return False


def generate_explain(field_map, prefix, obj, pg_type, fields, indent):
    stmts = []
    for field in fields:
        # These are the allowed pointers that we will recursively expand.
        allowed_pointers = {
            "struct ScanKeyData *": "ScanKeyData",
            "IndexRuntimeKeyInfo *": "IndexRuntimeKeyInfo"
        }

        # Fields of these types are skipped.
        exclusions = [
            clang.cindex.TypeKind.CONSTANTARRAY,
            clang.cindex.TypeKind.INCOMPLETEARRAY,
            clang.cindex.TypeKind.POINTER,
            clang.cindex.TypeKind.RECORD,
        ]

        signed_numeric = [
            clang.cindex.TypeKind.CHAR_S,
            clang.cindex.TypeKind.SHORT,
            clang.cindex.TypeKind.INT,
            clang.cindex.TypeKind.LONG,
            clang.cindex.TypeKind.ENUM,
        ]

        unsigned_numeric = [
            clang.cindex.TypeKind.UCHAR,
            clang.cindex.TypeKind.USHORT,
            clang.cindex.TypeKind.UINT,
            clang.cindex.TypeKind.ULONG
        ]

        field_name = prefix + field.name
        field_access = obj + "." + field.name

        if (pg_type == "Scan" or pg_type == "SeqScan") and field.name == "scanrelid":
            # For this we add a feature that describes the real scan table OID.
            # The table RTI is encoded in scanrelid.
            field_name = prefix + "scanrelid_oid"
            stmts.append(construct_with_indent(indent, f"ExplainPropertyInteger(\"{field_name}\", NULL, GetScanTableOid({field_access}, estate), es);"));
            continue

        if field.name in OMIT_PREPEND_FIELDS:
            field_name = field.name

        if field.canonical_type_kind in signed_numeric:
            # Outputs an integer property in the EXPLAIN output.
            stmts.append(construct_with_indent(indent, f"ExplainPropertyInteger(\"{field_name}\", NULL, {field_access}, es);"))

        elif field.canonical_type_kind in unsigned_numeric:
            # Outputs an unsigned integer property in the EXPLAIN output.
            stmts.append(construct_with_indent(indent, f"ExplainPropertyUInteger(\"{field_name}\", NULL, {field_access}, es);"))

        elif field.canonical_type_kind == clang.cindex.TypeKind.BOOL:
            # Outputs a boolean property in the EXPLAIN output.
            stmts.append(construct_with_indent(indent, f"ExplainPropertyBool(\"{field_name}\", {field_access}, es);"))

        elif field.canonical_type_kind == clang.cindex.TypeKind.DOUBLE:
            # Outputs a double property in the EXPLAIN output.
            stmts.append(construct_with_indent(indent, f"ExplainPropertyFloat(\"{field_name}\", NULL, {field_access}, 9, es);"))

        elif field.canonical_type_kind == clang.cindex.TypeKind.RECORD and field.pg_type in field_map:
            # Expands an embeded struct directly.
            stmts.extend(generate_explain(field_map, field_name + "_", field_access, field.pg_type, field_map[field.pg_type], indent))

        elif field.canonical_type_kind == clang.cindex.TypeKind.POINTER and is_pointer_array_field(field_name, fields) and field.pg_type in allowed_pointers:
            # Encodes every element of a pointer to an in-memory array object.
            # Each element of the array is encoded as a sub object.
            conv_type = allowed_pointers[field.pg_type]
            num_key = obj + "." + get_num_key(field_name)
            stmts.append("")
            stmts.append(construct_with_indent(indent, f"ExplainOpenGroup(\"{field_name}\", \"{field_name}\", false, es);"))
            stmts.append(construct_with_indent(indent, f"if ({field_access})"" {"));
            stmts.append(construct_with_indent(indent+1, f"{field.pg_type} value = {field_access};"))
            stmts.append(construct_with_indent(indent+1, f"for (size_t i = 0; i < {num_key}; i++) ""{"))
            stmts.append(construct_with_indent(indent+2, f"ExplainOpenGroup(\"{field_name+conv_type}\", NULL, true, es);"))
            stmts.extend(generate_explain(field_map, field_name + "_", "(value[i])", conv_type, field_map[conv_type], indent+2))
            stmts.append(construct_with_indent(indent+2, f"ExplainCloseGroup(\"{field_name+conv_type}\", NULL, true, es);"))
            stmts.append(construct_with_indent(indent+1, "}"))
            stmts.append(construct_with_indent(indent, "}"));
            stmts.append(construct_with_indent(indent, f"ExplainCloseGroup(\"{field_name}\", \"{field_name}\", false, es);"))
            stmts.append("")

        elif field.pg_type == "List *":
            # Directly encode the "List *" as the length.
            stmts.append(construct_with_indent(indent, f"ExplainPropertyInteger(\"{field_name}_length\", NULL, {field_access} ? {field_access}->length : 0, es);"))

        elif field.canonical_type_kind == clang.cindex.TypeKind.POINTER and field.pg_type in allowed_pointers:
            # Directly expand a pointer's fields as subfields of the current object.
            conv_fields = field_map[allowed_pointers[field.pg_type]]
            stmts.append(construct_with_indent(indent, f"Assert({field_access} != NULL);"))
            stmts.extend(generate_explain(field_map, field_name + "_", f"(*({field_access}))", field.pg_type, conv_fields, indent))

        elif field.canonical_type_kind in exclusions:
            # If a type is in exclusions, we don't try to extract the feature.
            pass
        else:
            print(field)
            assert False

    return stmts


def generate_explain_structs(tags, struct_sets):
    functions = []
    for struct in tags:
        fields = struct_sets[struct]
        # Generate a function to write each Node object to the EXPLAIN output.
        fn_decl = [
            f"static void Write{struct}Explain(Node *obj, ExplainState *es, EState *estate)""{",
            construct_with_indent(1, f"{struct}* node = NULL;"),
            construct_with_indent(1, f"Assert(obj->type == T_{struct});"),
            construct_with_indent(1, f"node = ({struct}*)obj;"),
        ]

        fn_decl.extend(generate_explain(fields_subset, struct + "_", "(*node)", struct, fields, indent=1))
        fn_decl.append("}")
        fn_decl.append("\n")
        functions.append("\n".join(fn_decl))
    return "\n".join(functions)


def generate_explain_node_entry(structs, fn_decls):
    sig = "void ExplainEntry(Node *obj, ExplainState *es, EState *estate)"
    fn_decls.append(sig + ";\n")

    # Generic switch-case entry function to route.
    fn_decl = [
        sig + " {",
        construct_with_indent(1, "switch (obj->type) {"),
    ]

    fn_decl.extend([construct_with_indent(2, f"case T_{struct}: Write{struct}Explain(obj, es, estate); return;") for struct in structs])
    fn_decl.append(construct_with_indent(2, "default: abort();"))
    fn_decl.append(construct_with_indent(1, "}"))
    fn_decl.append("}")
    fn_decl.append("")
    return "\n".join(fn_decl)


def generate_node_to_name(structs, fn_decls):
    sig = "char* NodeToName(Node* obj)"
    fn_decls.append(sig + ";\n")

    # Generate switch-case entry to get a string identifier from a Node.
    fn_decl = [
        sig + " {",
        construct_with_indent(1, "switch (obj->type) {"),
    ]
    fn_decl.extend([construct_with_indent(2, f"case T_{struct}: return \"{struct}\";") for struct in structs])
    fn_decl.append(construct_with_indent(2, "default: abort();"))
    fn_decl.append(construct_with_indent(1, "}"))
    fn_decl.append("}")
    fn_decl.append("")
    return "\n".join(fn_decl)


if __name__ == "__main__":
    parser = clang_parser.ClangParser()

    # Get all nodes from NodeTag.
    assert "NodeTag" in parser.enum_map
    node_tags = parser.enum_map["NodeTag"]

    tags = [tag[2:] for (tag, _) in node_tags if tag.startswith("T_") and tag != "T_Invalid"]
    tags = [tag for tag in tags if tag in parser.def_map and ("plannodes.h" in parser.def_map[tag] or "execnodes.h" in parser.def_map[tag])]

    # These are structs that are not related to NodeTag but used by nodes. This list is conditionally
    # augmented so we don't generate functions for every struct in the system.
    aug_tags = ["ScanKeyData", "IndexRuntimeKeyInfo"]
    aug_tags.extend(tags)
    fields_subset = {tag:parser.fields[tag] for tag in aug_tags if tag in parser.fields}

    # Generate the various components.
    fn_sigs = []
    fn_decls = generate_explain_structs(tags, fields_subset)
    fn_explain_node_entry = generate_explain_node_entry(tags, fn_sigs)
    fn_node_to_name = generate_node_to_name(tags, fn_sigs)

    with open("qss_features.c.template", "r") as f:
        template = f.read()

    # Substitute into the placeholders and output.
    template = template.replace("SUBST_FN_DECLS", fn_decls)
    template = template.replace("SUBST_EXPLAIN_NODE_ENTRY", fn_explain_node_entry)
    template = template.replace("SUBST_NODE_TO_NAME", fn_node_to_name)
    with open("qss_features.c", "w") as f:
        f.write(template)

    with open("qss_features.h.template", "r") as f:
        template = f.read()

    template = template.replace("SUBST_FN_DECLS", "\n".join(fn_sigs))
    with open("qss_features.h", "w") as f:
        f.write(template)
