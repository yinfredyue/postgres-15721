// If you choose to use C++, read this very carefully:
// https://www.postgresql.org/docs/15/xfunc-c.html#EXTEND-CPP

#include <fstream>
#include <functional>
#include <locale>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rapidjson/document.h"

// clang-format off
extern "C" {
#include "../../../../src/include/postgres.h"
#include "../../../../src/include/fmgr.h"
#include "../../../../src/include/foreign/fdwapi.h"
#include "optimizer/paths.h"
#include "optimizer/pathnode.h"
#include "optimizer/cost.h"
#include "optimizer/optimizer.h"
#include "optimizer/planmain.h"
#include "foreign/foreign.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "optimizer/restrictinfo.h"
#include "catalog/pg_am_d.h"
#include "commands/defrem.h"
#include "unistd.h"
}
// clang-format on

// #define DEBUG

#ifndef DEBUG
#define elog(...)  // If not in DEBUG mode, disable logging
#endif

const uint EQUAL_INT = 96;
const uint NEQUAL_INT = 518;
const uint LESS_INT = 97;
const uint LESS_EQUAL_INT = 523;
const uint GREATER_INT = 521;
const uint GREATER_EQUAL_INT = 525;

const uint EQUAL_FLOAT = 1120;
const uint NEQUAL_FLOAT = 1121;
const uint LESS_FLOAT = 1122;
const uint LESS_EQUAL_FLOAT = 1124;
const uint GREATER_FLOAT = 1123;
const uint GREATER_EQUAL_FLOAT = 1125;

const uint EQUAL_STR = 98;
const uint NEQUAL_STR = 531;
const uint LESS_STR = 664;
const uint LESS_EQUAL_STR = 665;
const uint GREATER_STR = 666;
const uint GREATER_EQUAL_STR = 667;

/* Locale-enabled string comparison */
static std::locale LOCALE("en_US.UTF-8");
static const std::collate<char> &COLL = std::use_facet<std::collate<char>>(LOCALE);
static int locale_cmp(const std::string &s, const std::string &t) {
    return COLL.compare(s.data(), s.data() + s.size(), t.data(), t.data() + t.size());
};
static bool locale_eq(const std::string &s, const std::string &t) { return locale_cmp(s, t) == 0; };
static bool locale_lt(const std::string &s, const std::string &t) { return locale_cmp(s, t) < 0; };
static bool locale_le(const std::string &s, const std::string &t) { return locale_cmp(s, t) <= 0; };

/* ColumnInfo - information about a column in db721. */
class ColumnInfo {
   public:
    enum type { Int, Float, Str };
    struct BlockStat {
        int num;
        Datum min;
        Datum max;
        int min_len = 0;
        int max_len = 0;
    };

    std::string col_name;
    type t;
    int start_offset;
    int num_blocks;
    std::vector<BlockStat> block_stats;

    int value_length() const {
        switch (t) {
            case ColumnInfo::Int:
            case ColumnInfo::Float: {
                return 4;
            } break;
            case ColumnInfo::Str: {
                return 32;
            } break;
        }
        assert(false);
    }
};

/* Metadata - metadata of a db721 file */
class Metadata {
   public:
    std::string tablename;
    int max_values_per_block;
    std::vector<ColumnInfo> columns;
};

struct BlockFilter {
    int col;
    Datum value;
    uint opno;
};

class Db721FdwPlanState {
   public:
    char *filename;
    Metadata metadata;
};

/* cmp_value - return "x_datum op y_datum" as a bool */
static bool cmp_value(ColumnInfo::type t, Datum &x_datum, const int &op, Datum &y_datum) {
    switch (t) {
        case ColumnInfo::Int: {
            auto x = DatumGetInt32(x_datum);
            auto y = DatumGetInt32(y_datum);
            switch (op) {
                case EQUAL_INT:
                    return x == y;
                case NEQUAL_INT:
                    return x != y;
                case LESS_INT:
                    return x < y;
                case LESS_EQUAL_INT:
                    return x <= y;
                case GREATER_INT:
                    return x > y;
                case GREATER_EQUAL_INT:
                    return x >= y;
            }
        } break;
        case ColumnInfo::Float: {
            auto x = DatumGetFloat4(x_datum);
            auto y = DatumGetFloat8(y_datum);
            switch (op) {
                case EQUAL_FLOAT:
                    return x == y;
                case NEQUAL_FLOAT:
                    return x != y;
                case LESS_FLOAT:
                    return x < y;
                case LESS_EQUAL_FLOAT:
                    return x <= y;
                case GREATER_FLOAT:
                    return x > y;
                case GREATER_EQUAL_FLOAT:
                    return x >= y;
            }
        } break;
        case ColumnInfo::Str: {
            auto x = std::string(TextDatumGetCString(x_datum));
            auto y = std::string(TextDatumGetCString(y_datum));

            switch (op) {
                case EQUAL_STR:
                    return locale_eq(x, y);
                case NEQUAL_STR:
                    return !locale_eq(x, y);
                case LESS_STR:
                    return locale_lt(x, y);
                case GREATER_STR:
                    return locale_lt(y, x);
                case LESS_EQUAL_STR:
                    return locale_le(x, y);
                case GREATER_EQUAL_STR:
                    return locale_le(y, x);
            }
        } break;
    }

    assert(false);
}

class Db721FdwExecutionState {
   private:
    /* ColumnCursor - A cursor that iterates over values in blocks */
    struct ColumnCursor {
        int block_idx;
        int value_idx;
    };

    std::string filename;
    std::ifstream file;
    Metadata metadata;

    std::vector<ColumnCursor> cursors;
    std::vector<char *> block_cache;        /* Block cache for each columns */
    std::vector<int> used_cols;             /* Column indexes that needs to be read.
                                             * next() assumes that there's no duplicate in used_cols. */
    std::vector<BlockFilter> block_filters; /* block filters */
    std::unordered_set<int> blocks;         /* Blocks that pass filters (based on statistics) */

   public:
    const std::string get_filename() { return filename; }

    void open_file(const std::string &f) {
        filename = f;
        file.open(filename);
    }

    void set_metadata(Metadata meta) {
        metadata = meta;

        for (auto &col_info : metadata.columns) {
            cursors.push_back(ColumnCursor{-1, 0});
            block_cache.push_back((char *)palloc0(col_info.value_length() * metadata.max_values_per_block));
        }
    }

    void set_used_cols(List *used_cols_list) {
        ListCell *lc;
        foreach (lc, used_cols_list) {
            int col_idx = lfirst_int(lc);
            used_cols.push_back(col_idx);
            elog(DEBUG1, "target col: %d", col_idx);
        }
    }

    void set_block_filters(List *block_filters_list) {
        ListCell *lc;
        foreach (lc, block_filters_list) {
            auto filter = *((BlockFilter *)lfirst(lc));
            block_filters.push_back(filter);
        }
    }

    void set_blocks(List *blocks_list) {
        ListCell *lc;
        foreach (lc, blocks_list) {
            int block_idx = lfirst_int(lc);
            blocks.insert(block_idx);
        }
    }

    bool next(TupleTableSlot *slot) {
        while (true) {
            for (auto c = 0; c < metadata.columns.size(); c++) {
                slot->tts_isnull[c] = true;
            }

            for (auto c : used_cols) {
                const ColumnInfo &col_info = metadata.columns[c];
                ColumnCursor &cursor = cursors[c];

                const int value_length = col_info.value_length();

                // Must go to the next block
                if (cursor.block_idx < 0 || cursor.value_idx == col_info.block_stats[cursor.block_idx].num) {
                    do {
                        cursor.block_idx++;
                    } while (cursor.block_idx < col_info.num_blocks && blocks.find(cursor.block_idx) == blocks.end());
                    cursor.value_idx = 0;

                    // No more blocks to read
                    if (cursor.block_idx == col_info.num_blocks) {
                        return false;
                    }

                    // Read block into cache
                    int block_start_offset = col_info.start_offset;
                    for (int b = 0; b < cursor.block_idx; b++) {
                        block_start_offset += col_info.block_stats[b].num * value_length;
                    }
                    int num_values = col_info.block_stats[cursor.block_idx].num;

                    file.seekg(block_start_offset);
                    file.read(block_cache[c], num_values * value_length);
                }

                Datum datum;

                int local_value_offset = cursor.value_idx * value_length;  // offset within the block
                char *value_ptr = block_cache[c] + local_value_offset;

                switch (col_info.t) {
                    case ColumnInfo::Int: {
                        int v = *((int *)value_ptr);
                        elog(DEBUG5, "Read int value for col '%s': %d", col_info.col_name.c_str(), v);

                        datum = Int32GetDatum(v);
                    } break;
                    case ColumnInfo::Float: {
                        float v = *((float *)value_ptr);
                        elog(DEBUG5, "Read float value for col '%s': %f", col_info.col_name.c_str(), v);

                        datum = Float4GetDatum(v);
                    } break;
                    case ColumnInfo::Str: {
                        char *v = value_ptr;
                        elog(DEBUG5, "Read str value for col '%s': %s", col_info.col_name.c_str(), v);

                        datum = CStringGetTextDatum(v);
                    } break;
                }

                slot->tts_isnull[c] = false;
                slot->tts_values[c] = datum;

                cursor.value_idx++;
            }

            // Check filters
            bool filters_passed = true;
            for (auto filter : block_filters) {
                auto t = metadata.columns[filter.col].t;
                auto col_val = slot->tts_values[filter.col];
                if (!cmp_value(t, col_val, filter.opno, filter.value)) {
                    ExecClearTuple(slot);
                    filters_passed = false;
                    break;
                }
            }
            if (!filters_passed) {
                continue;
            }

            ExecStoreVirtualTuple(slot);
            return true;
        }

        assert(false);
    }
};

static void get_table_options(Oid relid, Db721FdwPlanState *fdw_private) {
    ForeignTable *table = GetForeignTable(relid);
    ListCell *lc;
    foreach (lc, table->options) {
        DefElem *def = (DefElem *)lfirst(lc);

        if (strcmp(def->defname, "filename") == 0) {
            fdw_private->filename = defGetString(def);
        } else if (strcmp(def->defname, "tablename") == 0) {
            fdw_private->metadata.tablename = defGetString(def);
        } else {
            elog(DEBUG1, "option '%s', value '%s'", def->defname, defGetString(def));
        }
    }
}

static Metadata parse_db721_meta(const char *filename) {
    Metadata parsed_meta;

    // Open file
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        elog(ERROR, "Cannot open file '%s'", filename);
    }

    // Read metadata size
    int metadata_size;
    lseek(fd, -4, SEEK_END);
    read(fd, &metadata_size, 4);
    elog(DEBUG5, "metadata size: %d", metadata_size);

    // Construct JSON doc
    rapidjson::Document doc;
    char *metadata = (char *)malloc(metadata_size + 1);
    lseek(fd, -4 - metadata_size, SEEK_END);
    read(fd, metadata, metadata_size);
    metadata[metadata_size] = '\0';
    elog(DEBUG1, "Metadata: '%s'", metadata);
    if (doc.Parse(metadata).HasParseError()) {
        elog(DEBUG1, "error: '%d'", doc.GetParseError());
    }
    free(metadata);
    close(fd);

    // Consume JSON
    parsed_meta.tablename = doc["Table"].GetString();
    parsed_meta.max_values_per_block = doc["Max Values Per Block"].GetInt();
    for (const auto &col : doc["Columns"].GetObject()) {
        ColumnInfo col_info;

        col_info.col_name = col.name.GetString();
        const auto col_info_obj = col.value.GetObject();

        const char *type_str = col_info_obj["type"].GetString();
        if (strcmp(type_str, "float") == 0) {
            col_info.t = ColumnInfo::Float;
        } else if (strcmp(type_str, "int") == 0) {
            col_info.t = ColumnInfo::Int;
        } else if (strcmp(type_str, "str") == 0) {
            col_info.t = ColumnInfo::Str;
        } else {
            elog(ERROR, "unexpected type: '%s'", type_str);
        }

        col_info.start_offset = col_info_obj["start_offset"].GetInt();
        col_info.num_blocks = col_info_obj["num_blocks"].GetInt();
        col_info.block_stats = std::vector<ColumnInfo::BlockStat>(col_info.num_blocks);

        ColumnInfo::BlockStat block_stat;
        for (const auto &block : col_info_obj["block_stats"].GetObject()) {
            const char *block_idx_str = block.name.GetString();
            const int block_idx = strtol(block_idx_str, NULL, 10);
            const auto stats_obj = block.value.GetObject();

            block_stat.num = stats_obj["num"].GetInt();
            switch (col_info.t) {
                case ColumnInfo::Int: {
                    const int min = stats_obj["min"].GetInt();
                    const int max = stats_obj["max"].GetInt();
                    block_stat.min = Int32GetDatum(min);
                    block_stat.max = Int32GetDatum(max);

                    elog(DEBUG5, "Block %d, num=%d, min=%d, max=%d, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         min, max, block_stat.min_len, block_stat.max_len);
                } break;
                case ColumnInfo::Float: {
                    const float min = stats_obj["min"].GetFloat();
                    const float max = stats_obj["max"].GetFloat();
                    block_stat.min = Float4GetDatum(min);
                    block_stat.max = Float4GetDatum(max);

                    elog(DEBUG5, "Block %d, num=%d, min=%f, max=%f, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         min, max, block_stat.min_len, block_stat.max_len);
                } break;
                case ColumnInfo::Str: {
                    const char *min = stats_obj["min"].GetString();
                    const char *max = stats_obj["max"].GetString();
                    block_stat.min = CStringGetTextDatum(min);
                    block_stat.max = CStringGetTextDatum(max);
                    block_stat.min_len = strlen(min);
                    block_stat.max_len = strlen(max);

                    elog(DEBUG5, "Block %d, num=%d, min=%s, max=%s, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         min, max, block_stat.min_len, block_stat.max_len);
                } break;
            }

            col_info.block_stats[block_idx] = block_stat;
        }

        elog(DEBUG5, "Parsed column metadata: name='%s', type='%d', start_offset=%d, num_blocks=%d",
             col_info.col_name.c_str(), col_info.t, col_info.start_offset, col_info.num_blocks);

        parsed_meta.columns.push_back(col_info);
    }

    return parsed_meta;
}

static void parse_db721_meta(Db721FdwPlanState *fdw_private) {
    fdw_private->metadata = parse_db721_meta(fdw_private->filename);
}

/* bms_to_list - convert a Bitmapset* to a List*, with f applied.
 * Note: the bms is destructed.
 */
static List *bms_to_list(Bitmapset *s, const std::function<int(int)> &f) {
    List *res = NIL;
    int i;
    while ((i = bms_first_member(s)) > -1) {
        res = lappend_int(res, f(i));
    }
    return res;
}

/* extract_used_cols - Extract column indexes necessary for query execution */
static List *extract_used_cols(RelOptInfo *baserel) {
    ListCell *lc;

    /*
     * Projection pushdown: get attrNumber of used columns.
     * Without predicate pushdown, for query 'SELECT x, y FROM tbl WHERE z > 1',
     * x, y, z must be in the tuple.
     * Reference: https://github.com/postgres/postgres/blob/master/contrib/postgres_fdw/postgres_fdw.c#L689
     */
    Bitmapset *s = NULL;
    // Target columns
    pull_varattnos((Node *)baserel->reltarget->exprs, baserel->relid, &s);
    // WHERE clause
    foreach (lc, baserel->baserestrictinfo) {
        RestrictInfo *rinfo = (RestrictInfo *)lfirst(lc);
        pull_varattnos((Node *)rinfo->clause, baserel->relid, &s);
    }

    return bms_to_list(s, [](int attnum) {
        // Attribute numbers are offset by FirstLowInvalidHeapAttributeNumber
        // (see pull_varattrnos comment), we restore that.
        // Also, Attribute numbers are 1-based. We convert it to 0-based.
        return attnum + FirstLowInvalidHeapAttributeNumber - 1;
    });
}

// Extract filters from qual clauses
// The return value is a List of BlockFilters. Pointers to clause that should
// be deleted from `scan_clauses` is stored in `to_del`.
// Reference:
// https://github.com/adjust/parquet_fdw/blob/365710ba977cd05fd1ea31cec208956fa9352800/src/parquet_impl.cpp#L151
static List *extract_filters(List *scan_clauses, std::vector<void *> &to_del) {
    List *filters = NIL;

    ListCell *lc;
    foreach (lc, scan_clauses) {
        void *del_ptr = lfirst(lc);  // for deletion from `scan_clauses`. `clause` might be different from `lfirst(lc)`
        Expr *clause = (Expr *)lfirst(lc);
        Const *c;
        Var *v;
        AttrNumber attnum;
        Oid opno;

        if (IsA(clause, RestrictInfo)) clause = ((RestrictInfo *)clause)->clause;

        if (IsA(clause, OpExpr)) {
            OpExpr *expr = (OpExpr *)clause;

            /* Only interested in binary opexprs */
            if (list_length(expr->args) != 2) continue;

            Expr *left = (Expr *)linitial(expr->args);
            Expr *right = (Expr *)lsecond(expr->args);

            /*
             * Extract Var from RelableType
             * What's RelableType? T_RelabelType is a node type in the query
             * plan that represents the operation of relabeling a column or
             * expression with a different data type.
             * For example, if a query has a column of type VARCHAR, but a
             * function in the query requires a TEXT type, the planner may add
             * a T_RelabelType node to convert the VARCHAR column to TEXT.
             *
             * We get the original Var (that represents a column) from `arg`,
             * so that we can access its AttrNumber.
             */
            if (IsA(left, RelabelType)) left = ((RelabelType *)left)->arg;
            if (IsA(right, RelabelType)) right = ((RelabelType *)right)->arg;

            /*
             * Looking for exprs like "expr OP const" or "const OP expr".
             * Convert all into "expr OP const" for further processing.
             * Only support Var.
             */
            if (IsA(right, Const)) {
                assert(IsA(left, Var));
                if (!IsA(left, Var)) continue;
                v = (Var *)left;
                attnum = v->varattno;
                c = (Const *)right;
                opno = expr->opno;
            } else if (IsA(left, Const)) {
                assert(IsA(right, Var));
                if (!IsA(right, Var)) continue;
                v = (Var *)right;
                attnum = v->varattno;
                c = (Const *)left;
                opno = get_commutator(expr->opno);  // Reverse order
            } else {
                continue;
            }

            BlockFilter *filter = (BlockFilter *)palloc0(sizeof(BlockFilter));
            filter->col = attnum - 1;
            filter->value = c->constvalue;
            filter->opno = opno;
            elog(DEBUG1, "Filter extracted. attnum: %hd, opno: %d, consttype: %d", attnum, opno, c->consttype);

            filters = lappend(filters, filter);
            to_del.push_back(del_ptr);
        }
    }

    return filters;
}

/*
 * cmp_block - check if a block is filtered using statistics
 * The predicate is "col op const_datum".
 */
static bool cmp_block(ColumnInfo::type t, ColumnInfo::BlockStat &block_stat, const int &op, Datum &const_datum) {
    switch (t) {
        case ColumnInfo::Int: {
            auto const_val = DatumGetInt32(const_datum);
            auto lower = DatumGetInt32(block_stat.min);
            auto upper = DatumGetInt32(block_stat.max);
            elog(DEBUG1, "INT const: %d, lower: %d, upper: %d", const_val, lower, upper);
            switch (op) {
                case EQUAL_INT:
                    return lower <= const_val && const_val <= upper;
                case NEQUAL_INT:
                    return true;
                case LESS_INT:
                    return lower < const_val;
                case LESS_EQUAL_INT:
                    return lower <= const_val;
                case GREATER_INT:
                    return const_val < upper;
                case GREATER_EQUAL_INT:
                    return const_val <= upper;
            }
        } break;
        case ColumnInfo::Float: {
            auto const_val = DatumGetFloat8(const_datum);  // Oid 701 in pg_type is float8, not float4
            auto lower = DatumGetFloat4(block_stat.min);
            auto upper = DatumGetFloat4(block_stat.max);
            elog(DEBUG1, "FLOAT const: %f, lower: %f, upper: %f", const_val, lower, upper);
            switch (op) {
                case EQUAL_FLOAT:
                    return lower <= const_val && const_val <= upper;
                case NEQUAL_FLOAT:
                    return true;
                case LESS_FLOAT:
                    return lower < const_val;
                case GREATER_FLOAT:
                    return const_val < upper;
                case LESS_EQUAL_FLOAT:
                    return lower <= const_val;
                case GREATER_EQUAL_FLOAT:
                    return const_val <= upper;
            }
        } break;
        case ColumnInfo::Str: {
            auto const_val = std::string(TextDatumGetCString(const_datum));  // Oid 25 in pg_type is text
            auto lower = std::string(TextDatumGetCString(block_stat.min));
            auto upper = std::string(TextDatumGetCString(block_stat.max));
            elog(DEBUG1, "STRING const: '%s', lower: '%s', upper: '%s'", const_val.c_str(), lower.c_str(),
                 upper.c_str());

            switch (op) {
                case EQUAL_STR:
                    return locale_le(lower, const_val) && locale_le(const_val, upper);
                case NEQUAL_STR:
                    return true;
                case LESS_STR:
                    return locale_lt(lower, const_val);
                case GREATER_STR:
                    return locale_lt(const_val, upper);
                case LESS_EQUAL_STR:
                    return locale_le(lower, const_val);
                case GREATER_EQUAL_STR:
                    return locale_le(const_val, upper);
            }
        } break;
    }

    assert(false);
}

/* filter_blocks - Filter blocks based on filters */
static List *filter_blocks(Metadata &metadata, List *filters) {
    List *blocks = NIL;

    ListCell *lc;
    auto num_blocks = metadata.columns[0].num_blocks;
    for (int b = 0; b < num_blocks; b++) {
        bool skip = false;

        foreach (lc, filters) {
            BlockFilter *filter = (BlockFilter *)lfirst(lc);
            ColumnInfo &col_info = metadata.columns[filter->col];
            Datum const_val = filter->value;

            if (!cmp_block(col_info.t, col_info.block_stats[b], filter->opno, const_val)) {
                skip = true;
                break;
            }
        }

        if (!skip) {
            blocks = lappend_int(blocks, b);
            elog(DEBUG1, "Block [%d] remains", b);
        }
    }
    return blocks;
}

extern "C" void db721_GetForeignRelSize(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid) {
    elog(DEBUG1, "db721_GetForeignRelSize called");
    Db721FdwPlanState *fdw_private = (Db721FdwPlanState *)palloc0(sizeof(Db721FdwPlanState));
    fdw_private->metadata.columns = std::vector<ColumnInfo>();  // Must init the hashunordered_map.

    get_table_options(foreigntableid, fdw_private);
    parse_db721_meta(fdw_private);

    baserel->fdw_private = fdw_private;

    // TODO: account for restriction clause in the plan
    int num_rows = 0;
    for (auto &col_info : fdw_private->metadata.columns) {
        int nrows = 0;
        for (auto b = 0; b < col_info.num_blocks; b++) {
            nrows += col_info.block_stats[b].num;
        }
        assert(num_rows == 0 || num_rows == nrows);
        num_rows = nrows;
    }
    baserel->rows = num_rows;
    elog(DEBUG1, "expected # of rows: %f", baserel->rows);
}

extern "C" void db721_GetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid) {
    elog(DEBUG1, "db721_GetForeignPaths called");
    Db721FdwPlanState *fdw_private = (Db721FdwPlanState *)baserel->fdw_private;
    Cost startup_cost = baserel->baserestrictcost.startup;
    Cost total_cost = baserel->rows * cpu_tuple_cost;

    Path *foreign_path = (Path *)create_foreignscan_path(root, baserel, NULL, baserel->rows, startup_cost, total_cost,
                                                         NULL, NULL, NULL, (List *)fdw_private);
    add_path(baserel, foreign_path);
    elog(DEBUG1, "startup_cost: %f, total_cost: %f. Path created and added.", startup_cost, total_cost);
}

extern "C" ForeignScan *db721_GetForeignPlan(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid,
                                             ForeignPath *best_path, List *tlist, List *scan_clauses,
                                             Plan *outer_plan) {
    elog(DEBUG1, "db721_GetForeignPlan called");
    Db721FdwPlanState *fdw_private = (Db721FdwPlanState *)baserel->fdw_private;

    // Filter clauses (remove pseudoconstants)
    scan_clauses = extract_actual_clauses(scan_clauses, false);
    elog(DEBUG1, "scan_clause size: %d", list_length(scan_clauses));

    // Filter blocks
    std::vector<void *> to_del;
    List *block_filters = extract_filters(scan_clauses, to_del);
    for (auto lc : to_del) {
        scan_clauses = list_delete(scan_clauses, lc);
    }
    elog(DEBUG1, "%d filters extracted, to_del size: %d, scan_clause size: %d", list_length(block_filters),
         to_del.size(), list_length(scan_clauses));
    List *blocks = filter_blocks(fdw_private->metadata, block_filters);
    elog(DEBUG1, "%d out of %d blocks remaining", list_length(blocks), fdw_private->metadata.columns[0].num_blocks);

    // Extract useful columns
    List *used_cols = extract_used_cols(baserel);

    // Pack fdw_private into params
    List *params = NIL;
    params = lappend(params, fdw_private->filename);
    params = lappend(params, used_cols);
    params = lappend(params, block_filters);
    params = lappend(params, blocks);

    return make_foreignscan(tlist, scan_clauses, baserel->relid, NIL, params, NIL, NIL, outer_plan);
}

extern "C" void db721_BeginForeignScan(ForeignScanState *node, int eflags) {
    elog(DEBUG1, "db721_BeginForeignScan called");
    ForeignScan *plan = (ForeignScan *)node->ss.ps.plan;
    List *fdw_private = plan->fdw_private;

    Db721FdwExecutionState *exec_state = new Db721FdwExecutionState();

    // Unpack fdw_private
    ListCell *lc;
    int i = 0;
    foreach (lc, fdw_private) {
        switch (i) {
            case 0: {
                exec_state->open_file((char *)lfirst(lc));
                exec_state->set_metadata(parse_db721_meta(exec_state->get_filename().c_str()));
            } break;
            case 1: {
                exec_state->set_used_cols((List *)lfirst(lc));
            } break;
            case 2: {
                exec_state->set_block_filters((List *)lfirst(lc));
            } break;
            case 3: {
                exec_state->set_blocks((List *)lfirst(lc));
            } break;
        }
        ++i;
    }

    node->fdw_state = exec_state;
}

extern "C" TupleTableSlot *db721_IterateForeignScan(ForeignScanState *node) {
    elog(DEBUG5, "db721_IterateForeignScan called");

    Db721FdwExecutionState *execution_state = (Db721FdwExecutionState *)node->fdw_state;

    TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
    ExecClearTuple(slot);

    execution_state->next(slot);
    return slot;
}

extern "C" void db721_ReScanForeignScan(ForeignScanState *node) { elog(DEBUG1, "db721_ReScanForeignScan called"); }

extern "C" void db721_EndForeignScan(ForeignScanState *node) {
    elog(DEBUG1, "db721_EndForeignScan called");
    delete (Db721FdwExecutionState *)node->fdw_state;
}