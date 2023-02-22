// If you choose to use C++, read this very carefully:
// https://www.postgresql.org/docs/15/xfunc-c.html#EXTEND-CPP

#include <fstream>
#include <string>
#include <unordered_map>
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
#include "optimizer/restrictinfo.h"
#include "commands/defrem.h"
#include "unistd.h"
}
// clang-format on

// #define DEBUG

#ifndef DEBUG
#define elog(...)  // If not in DEBUG mode, disable logging
#endif

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
    }
};

/* Metadata - metadata of a db721 file */
class Metadata {
   public:
    std::string tablename;
    int max_values_per_block;
    std::vector<ColumnInfo> columns;
};

class Db721FdwPlanState {
   public:
    char *filename;
    Metadata metadata;
};

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
    std::vector<char *> block_cache; /* Block cache for each columns */
    std::vector<int> used_cols;      /* Column indexes that needs to be read.
                                      * next() assumes that there's no duplicate in used_cols. */

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

    bool next(TupleTableSlot *slot) {
        for (auto c = 0; c < metadata.columns.size(); c++) {
            slot->tts_isnull[c] = true;
        }

        for (auto c : used_cols) {
            const ColumnInfo &col_info = metadata.columns[c];
            ColumnCursor &cursor = cursors[c];

            const int value_length = col_info.value_length();

            // Must go to the next block
            if (cursor.block_idx < 0 || cursor.value_idx == col_info.block_stats[cursor.block_idx].num) {
                cursor.block_idx++;
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

        ExecStoreVirtualTuple(slot);
        return true;
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
    elog(DEBUG1, "metadata size: %d", metadata_size);

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

                    elog(DEBUG1, "Block %d, num=%d, min=%d, max=%d, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         min, max, block_stat.min_len, block_stat.max_len);
                } break;
                case ColumnInfo::Float: {
                    const float min = stats_obj["min"].GetFloat();
                    const float max = stats_obj["max"].GetFloat();
                    block_stat.min = Float4GetDatum(min);
                    block_stat.max = Float4GetDatum(max);

                    elog(DEBUG1, "Block %d, num=%d, min=%f, max=%f, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         min, max, block_stat.min_len, block_stat.max_len);
                } break;
                case ColumnInfo::Str: {
                    const char *min = stats_obj["min"].GetString();
                    const char *max = stats_obj["max"].GetString();
                    block_stat.min = CStringGetDatum(min);
                    block_stat.max = CStringGetDatum(max);
                    block_stat.min_len = strlen(min);
                    block_stat.max_len = strlen(max);

                    elog(DEBUG1, "Block %d, num=%d, min=%s, max=%s, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         min, max, block_stat.min_len, block_stat.max_len);
                } break;
            }

            col_info.block_stats[block_idx] = block_stat;
        }

        elog(DEBUG1, "Parsed column metadata: name='%s', type='%d', start_offset=%d, num_blocks=%d",
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

    scan_clauses = extract_actual_clauses(scan_clauses, false);

    List *used_cols = extract_used_cols(baserel);

    // Pack fdw_private into params
    Db721FdwPlanState *fdw_private = (Db721FdwPlanState *)baserel->fdw_private;
    List *params = NIL;
    params = lappend(params, fdw_private->filename);
    params = lappend(params, used_cols);

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
                elog(DEBUG1, "file '%s' opened successfully", exec_state->get_filename().c_str());

                exec_state->set_metadata(parse_db721_meta(exec_state->get_filename().c_str()));
                elog(DEBUG1, "metadata parsed successfully");
            } break;
            case 1: {
                List *used_cols = (List *)lfirst(lc);
                exec_state->set_used_cols(used_cols);
            } break;
        }
        ++i;
    }

    node->fdw_state = exec_state;
}

extern "C" TupleTableSlot *db721_IterateForeignScan(ForeignScanState *node) {
    elog(DEBUG1, "db721_IterateForeignScan called");

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