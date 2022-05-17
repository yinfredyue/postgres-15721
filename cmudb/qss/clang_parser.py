"""
clang_parser.py
Parse C code into a map which maps from (struct name) to
(base-class- and record-type- expanded fields list).
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Tuple

import clang.cindex

logger = logging.getLogger("qss")

# Expected path of this file: "postgres/cmudb/qss"

# Path to the Postgres root.
POSTGRES_PATH = Path(__file__).parent.parent.parent
# Path to the Postgres files to parse.
POSTGRES_FILES = (f"{POSTGRES_PATH}/src/backend/executor/execMain.c",)
# The arguments that Clang uses to parse header files.
CLANG_ARGS = [
    "-std=c17",
    f"-I{POSTGRES_PATH}/src/include",
    "-I/usr/lib/gcc/x86_64-linux-gnu/9/include",
    "-I/usr/local/include",
    "-I/usr/include/x86_64-linux-gnu",
    "-I/usr/include",
]


def convert_define_to_arg(input_define):
    """
    Convert from a #define to a command line arg.
    Parameters
    ----------
    input_define : str
        String in the format of "#define variable value".
    Returns
    -------
    output_str : str
        String in the format of "-Dvariable=value".
    """
    var_and_value = input_define.rstrip()[len("#define ") :]
    separator = var_and_value.find(" ")
    var = var_and_value[:separator]
    value = var_and_value[separator + 1 :]
    return f"-D{var}={value}"


# Grab the results of ./configure to make sure that we're passing the same
# preprocessor #defines to libclang as when compiling Postgres.
# #defines can affect struct sizing depending on machine environment.
with open(f"{POSTGRES_PATH}/config.log", encoding="utf-8") as config_file:
    for config_line in config_file:
        if config_line.startswith("#define "):
            CLANG_ARGS.append(convert_define_to_arg(config_line))


@dataclass
class Field:
    """A field of a struct, as parsed by Clang."""

    name: str
    pg_type: str
    canonical_type_kind: clang.cindex.TypeKind


class ClangParser:
    """
    On init, ClangParser parses the PostgreSQL source code to construct a
    mapping from struct name to a list of the struct fields, where the fields
    list has both base classes expanded and record types expanded.
    """

    def __init__(self):
        indexes: List[clang.cindex.Index] = []
        translation_units: List[clang.cindex.TranslationUnit] = []
        classes: Mapping[str, clang.cindex.Cursor] = {}
        enums: Mapping[str, clang.cindex.Cursor] = {}

        # Parse each postgres file's definitions into the classes map.
        # classes is a map to handle potential duplicate definitions
        # from parsing multiple translation units.
        for postgres_file in POSTGRES_FILES:
            # Parse the translation unit.
            index = clang.cindex.Index.create()
            tunit = index.parse(postgres_file, args=CLANG_ARGS)

            # Keep the index and translation unit alive for the rest of init.
            indexes.append(index)
            translation_units.append(tunit)

            # Add all relevant definitions to the classes map.
            for node in tunit.cursor.get_children():
                kind_ok = node.kind in [
                    clang.cindex.CursorKind.CLASS_DECL,
                    clang.cindex.CursorKind.STRUCT_DECL,
                    clang.cindex.CursorKind.UNION_DECL,
                ]

                kind_enum = node.kind in [
                    clang.cindex.CursorKind.ENUM_DECL,
                ]

                is_new = node.spelling not in classes
                # Fix forward declarations clobbering definitions.
                is_real_def = node.is_definition()

                # This is used to handle typedef Scan SeqScan. We can identify these cases with
                # the following rules:
                # 1- SeqScan will of type TYPEDEF_DECL
                # 2- SeqScan has only 1 child and the child is of TYPE_REF
                # 3- Child class must have already been seen
                is_class_ref = False
                if node.kind == clang.cindex.CursorKind.TYPEDEF_DECL:
                    num_child = 0
                    for child in node.get_children():
                        is_class_ref = child.kind == clang.cindex.CursorKind.TYPE_REF and child.spelling in classes
                        num_child = num_child + 1
                    is_class_ref = is_class_ref and num_child == 1

                if kind_ok and is_new and is_real_def:
                    classes[node.spelling] = node

                elif node.kind == clang.cindex.CursorKind.TYPEDEF_DECL and is_class_ref:
                    classes[node.spelling] = node

                elif kind_enum and is_new and is_real_def:
                    enums[node.spelling] = node

        # To construct the field map, we will construct the following objects:
        # 1. _classes
        #       Extract a list of all classes in the translation units.
        # 2. _bases
        #       Extract a mapping from class name to all base classes.
        # 3. fields
        #       Extract a mapping from class name to all the fields,
        #       but base classes not expanded, record types not expanded.
        # 4. enum_map
        #       Extract a mapping of all enumerations in the code base where the value is a
        #       list of (enum_name, enum_value) pairs.
        # 5. def_map
        #       Extract a mapping from class name to file defining it.

        # _classes : list of all classes in the translation unit
        self._classes: List[clang.cindex.Cursor] = classes.values()
        self._classes = sorted(self._classes, key=lambda node: node.spelling)
        self.def_map = {node.spelling:str(node.location.file) for node in self._classes}

        # _bases : class name -> list of base classes for the class, for C++ inheritance.
        self._bases: Mapping[str, List[clang.cindex.Cursor]] = {
            node.spelling: [
                child.referenced
                for child in node.get_children()
                if child.kind == clang.cindex.CursorKind.CXX_BASE_SPECIFIER
            ]
            for node in self._classes
        }

        # fields : class name -> list of fields in the class
        self.fields: Mapping[str, List[Field]] = {
            node.spelling: [
                Field(
                    child.displayname,
                    child.type.spelling
                    if child.type.get_canonical().kind != clang.cindex.TypeKind.RECORD
                    else child.type.get_canonical().get_declaration().spelling,
                    child.type.get_canonical().kind,
                )
                for child in node.get_children()
                if child.kind == clang.cindex.CursorKind.FIELD_DECL
            ]
            for node in self._classes
        }

        for node in self._classes:
            # In the case typedef Scan SeqScan, we want SeqScan to have the same fields
            # within self.fields as Scan>
            if node.kind == clang.cindex.CursorKind.TYPEDEF_DECL:
                for child in node.get_children():
                    assert child.kind == clang.cindex.CursorKind.TYPE_REF
                    self.fields[node.spelling] = self.fields[child.spelling]

        self.enum_map: Mapping[str, List[Tuple[str, int]]] = {
            node: [(child.spelling, child.enum_value) for child in enum.get_children()] for node, enum in enums.items()
        }
