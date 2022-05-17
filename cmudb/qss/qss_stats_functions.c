#include "qss.h"

#include "postgres.h"
#include "fmgr.h"

#include "catalog/pg_class.h"

struct QSS_StatEntry {
	Oid pg_class_oid;
	int pg_class_relpages;
	float pg_class_reltuples;
	int index_tree_height;
};

PG_FUNCTION_INFO_V1(qss_install_stats);
PG_FUNCTION_INFO_V1(qss_remove_stats);
PG_FUNCTION_INFO_V1(qss_clear_stats);

List* qss_installed_stats = NIL;

Datum qss_install_stats(PG_FUNCTION_ARGS) {
	MemoryContext oldcontext;
	ListCell *lc = NULL;
	Oid target = PG_GETARG_OID(0);
	int relpages = PG_GETARG_INT32(1);
	float reltuples = PG_GETARG_FLOAT4(2);
	int tree_height = PG_GETARG_INT32(3);
	bool found = false;

	oldcontext = MemoryContextSwitchTo(qss_MemoryContext);

	foreach(lc, qss_installed_stats) {
		struct QSS_StatEntry* entry = (struct QSS_StatEntry*)lfirst(lc);
		if (entry->pg_class_oid == target) {
			entry->pg_class_relpages = relpages;
			entry->pg_class_reltuples = reltuples;
			entry->index_tree_height = tree_height;
			found = true;
			break;
		}
	}

	if (!found) {
		struct QSS_StatEntry* entry = palloc0(sizeof(struct QSS_StatEntry));
		entry->pg_class_oid = target;
		entry->pg_class_relpages = relpages;
		entry->pg_class_reltuples = reltuples;
		entry->index_tree_height = tree_height;
		qss_installed_stats = lappend(qss_installed_stats, entry);
	}

	RelationCacheInvalidateEntry(target);
	MemoryContextSwitchTo(oldcontext);
	PG_RETURN_VOID();
}

Datum qss_remove_stats(PG_FUNCTION_ARGS) {
	MemoryContext oldcontext;
	bool result = false;
	ListCell *lc = NULL;
	Oid target = PG_GETARG_OID(0);
	oldcontext = MemoryContextSwitchTo(qss_MemoryContext);

	foreach (lc, qss_installed_stats) {
		struct QSS_StatEntry* entry = (struct QSS_StatEntry*)lfirst(lc);
		if (entry->pg_class_oid == target) {
			qss_installed_stats = list_delete_cell(qss_installed_stats, lc);
			pfree(entry);

			result = true;
			break;
		}
	}

	RelationCacheInvalidateEntry(target);
	MemoryContextSwitchTo(oldcontext);
	PG_RETURN_BOOL(result);
}

Datum qss_clear_stats(PG_FUNCTION_ARGS) {
	MemoryContext oldcontext;
	ListCell *lc = NULL;
	oldcontext = MemoryContextSwitchTo(qss_MemoryContext);

	while ((lc = list_head(qss_installed_stats)) != NULL) {
		struct QSS_StatEntry* entry = (struct QSS_StatEntry*)lfirst(lc);
		RelationCacheInvalidateEntry(entry->pg_class_oid);

		qss_installed_stats = list_delete_cell(qss_installed_stats, lc);
		pfree(entry);
	}

	list_free(qss_installed_stats);
	qss_installed_stats = NIL;

	MemoryContextSwitchTo(oldcontext);
	PG_RETURN_VOID();
}

void qss_GetRelationInfo(PlannerInfo* root, Oid target, bool inhparent, RelOptInfo* rel) {
	ListCell *lc = NULL;
	ListCell *ilc = NULL;

	if (qss_prev_get_relation_info) {
		// If there is a previous hook, let it edit first.
		qss_prev_get_relation_info(root, target, inhparent, rel);
	}

	foreach(lc, qss_installed_stats) {
		struct QSS_StatEntry* entry = (struct QSS_StatEntry*)lfirst(lc);
		if (entry->pg_class_oid == target) {
			rel->pages = entry->pg_class_relpages;
			rel->tuples = entry->pg_class_reltuples;
		}

		foreach (ilc, rel->indexlist) {
			IndexOptInfo* idx = (IndexOptInfo*) lfirst(ilc);
			if (entry->pg_class_oid == idx->indexoid) {
				idx->pages = entry->pg_class_relpages;
				idx->tuples = entry->pg_class_reltuples;
				if (entry->index_tree_height != 0) {
					idx->tree_height = entry->index_tree_height;
				}
			}
		}
	}
}
