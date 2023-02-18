// If you choose to use C++, read this very carefully:
// https://www.postgresql.org/docs/15/xfunc-c.html#EXTEND-CPP

#include <string>
#include <unordered_map>
#include <vector>

#include "../../../../src/include/rapidjson/document.h"
#include "../../../../src/include/rapidjson/stringbuffer.h"
#include "../../../../src/include/rapidjson/writer.h"
#include "dog.h"

// clang-format off
extern "C" {
#include "../../../../src/include/postgres.h"
#include "../../../../src/include/fmgr.h"
#include "../../../../src/include/foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "commands/defrem.h"
#include "unistd.h"
}
// clang-format on

struct ColumnInfo {
    enum type { Int, Float, Str };
    struct BlockStat {
        int num;
        Datum min;
        Datum max;
        int min_len = 0;
        int max_len = 0;
    };

    type t;
    int start_offset;
    int num_blocks;
    std::vector<BlockStat> block_stats;
};

struct Db721FdwPlanState {
    char *filename;
    char *tablename;
    int max_values_per_block;
    std::unordered_map<std::string, ColumnInfo> columns;
};

static void get_table_options(Oid relid, Db721FdwPlanState *fdw_private) {
    ForeignTable *table = GetForeignTable(relid);
    ListCell *lc;
    foreach (lc, table->options) {
        DefElem *def = (DefElem *)lfirst(lc);

        if (strcmp(def->defname, "filename") == 0) {
            fdw_private->filename = defGetString(def);
        } else if (strcmp(def->defname, "tablename") == 0) {
            fdw_private->tablename = defGetString(def);
        } else {
            elog(LOG, "option '%s', value '%s'", def->defname, defGetString(def));
        }
    }
}

static void parse_db721_meta(Db721FdwPlanState *fdw_private) {
    // Open file
    int fd = open(fdw_private->filename, O_RDONLY);
    if (fd == -1) {
        elog(ERROR, "Cannot open file '%s'", fdw_private->filename);
    }

    // Read metadata size
    int metadata_size;
    lseek(fd, -4, SEEK_END);
    read(fd, &metadata_size, 4);
    elog(LOG, "metadata size: %d", metadata_size);

    // Construct JSON doc
    rapidjson::Document doc;
    char *metadata = (char *)malloc(metadata_size + 1);
    lseek(fd, -4 - metadata_size, SEEK_END);
    read(fd, metadata, metadata_size);
    metadata[metadata_size] = '\0';
    elog(LOG, "Metadata: '%s'", metadata);
    if (doc.Parse(metadata).HasParseError()) {
        elog(LOG, "error: '%d'", doc.GetParseError());
    }
    free(metadata);

    // Consume JSON
    fdw_private->max_values_per_block = doc["Max Values Per Block"].GetInt();
    for (const auto &col : doc["Columns"].GetObject()) {
        ColumnInfo col_info;

        std::string col_name = col.name.GetString();
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

                    elog(LOG, "Block %d, num=%d, min=%d, max=%d, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         DatumGetInt32(block_stat.min), DatumGetInt32(block_stat.max), block_stat.min_len,
                         block_stat.max_len);
                } break;
                case ColumnInfo::Float: {
                    const float min = stats_obj["min"].GetFloat();
                    const float max = stats_obj["max"].GetFloat();
                    block_stat.min = Float4GetDatum(min);
                    block_stat.max = Float4GetDatum(max);

                    elog(LOG, "Block %d, num=%d, min=%f, max=%f, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         DatumGetFloat4(block_stat.min), DatumGetFloat4(block_stat.max), block_stat.min_len,
                         block_stat.max_len);
                } break;
                case ColumnInfo::Str: {
                    const char *min = stats_obj["min"].GetString();
                    const char *max = stats_obj["max"].GetString();
                    block_stat.min = CStringGetDatum(min);
                    block_stat.max = CStringGetDatum(max);
                    block_stat.min_len = strlen(min);
                    block_stat.max_len = strlen(max);

                    elog(LOG, "Block %d, num=%d, min=%s, max=%s, min_len=%d, max_len=%d", block_idx, block_stat.num,
                         DatumGetCString(block_stat.min), DatumGetCString(block_stat.max), block_stat.min_len,
                         block_stat.max_len);
                } break;
            }

            col_info.block_stats[block_idx] = block_stat;
        }

        elog(LOG, "Parsed column metadata: name='%s', type='%d', start_offset=%d, num_blocks=%d", col_name.c_str(),
             col_info.t, col_info.start_offset, col_info.num_blocks);

        fdw_private->columns[col_name] = col_info;
    }
}

extern "C" void db721_GetForeignRelSize(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid) {
    Db721FdwPlanState *fdw_private = (Db721FdwPlanState *)palloc0(sizeof(Db721FdwPlanState));
    fdw_private->columns = std::unordered_map<std::string, ColumnInfo>();  // Must init the hashmap.

    get_table_options(foreigntableid, fdw_private);
    parse_db721_meta(fdw_private);

    baserel->fdw_private = fdw_private;

    // TODO: account for restriction clause in the plan
    int num_rows = 0;
    for (auto &[_, col_info] : fdw_private->columns) {
        int nrows = 0;
        for (int b = 0; b < col_info.num_blocks; b++) {
            nrows += col_info.block_stats[b].num;
        }
        assert(num_rows == 0 || num_rows == nrows);
        num_rows = nrows;
    }
    baserel->rows = num_rows;
    elog(LOG, "expected # of rows: %f", baserel->rows);
}

extern "C" void db721_GetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid) {
    // TODO(721): Write me!
    Dog scout("Scout");
    elog(LOG, "db721_GetForeignPaths: %s", scout.Bark().c_str());
}

extern "C" ForeignScan *db721_GetForeignPlan(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid,
                                             ForeignPath *best_path, List *tlist, List *scan_clauses,
                                             Plan *outer_plan) {
    // TODO(721): Write me!
    return nullptr;
}

extern "C" void db721_BeginForeignScan(ForeignScanState *node, int eflags) {
    // TODO(721): Write me!
}

extern "C" TupleTableSlot *db721_IterateForeignScan(ForeignScanState *node) {
    // TODO(721): Write me!
    return nullptr;
}

extern "C" void db721_ReScanForeignScan(ForeignScanState *node) {
    // TODO(721): Write me!
}

extern "C" void db721_EndForeignScan(ForeignScanState *node) {
    // TODO(721): Write me!
}