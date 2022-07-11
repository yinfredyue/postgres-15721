#include "qss.h"
#include "qss_features.h"

#include "access/nbtree.h"
#include "access/heapam.h"
#include "access/relation.h"
#include "catalog/namespace.h"
#include "catalog/index.h"
#include "miscadmin.h"
#include "nodes/pg_list.h"
#include "utils/builtins.h"

#include "cmudb/tscout/sampling.h"
#include "cmudb/qss/qss.h"

/**
 CREATE UNLOGGED TABLE pg_catalog.pg_qss_plans(
	query_id BIGINT,
	generation INTEGER,
	db_id INTEGER,
	pid INTEGER,
	timestamp BIGINT,
	features TEXT,
	primary key(query_id, generation, db_id, pid)
 )
 */
#define QUERY_TABLE_NAME "pg_qss_plans"
#define QUERY_INDEX_NAME "pg_qss_plans_pkey"
#define QUERY_TABLE_COLUMNS 6

/**
 CREATE UNLOGGED TABLE pg_catalog.pg_qss_stats(
	query_id bigint,
	db_id integer,
	pid integer,
	timestamp bigint,
	plan_node_id int,

	counter0 float8,
	counter1 float8,
	counter2 float8,
	counter3 float8,
	counter4 float8,
	counter5 float8,
	counter6 float8,
	counter7 float8,
	counter8 float8,
	counter9 float8,
	params text
 )
 */
#define STATS_TABLE_NAME "pg_qss_stats"
#define STATS_TABLE_COLUMNS 16

// All memory for ExecutorInstrument is charged to the query context that is executing
// the query that we are attempting to instrument. We do not use qss_MemoryContext
// for allocating any of this memory.
struct ExecutorInstrument {
	TimestampTz statement_ts;
	int plan_separate_instr_id;
	List* statement_instrs;
	struct ExecutorInstrument* prev;
};

int nesting_level = 0;
struct ExecutorInstrument* top = NULL;

void qss_Clear() {
	// These should get freed by the query MemoryContext.
	top = NULL;
	nesting_level = 0;
}

/**
 * Search the btree index for a given key by the tuple.
 * Taken from and largely inspired by verify_nbtree.c:bt_rootdescend
 */
static bool IndexLookup(Snapshot snapshot, Relation heap_relation, Relation index_relation, IndexTuple itup) {
	bool unique = false;
	uint32 specToken = 0;
	BTInsertStateData insertstate;
	BTScanInsert itup_key;
	BTStack stack;

	itup_key = _bt_mkscankey(index_relation, itup);
	itup_key->scantid = NULL;

	insertstate.itup = itup;
	insertstate.itemsz = MAXALIGN(IndexTupleSize(itup));
	insertstate.itup_key = itup_key;
	insertstate.bounds_valid = false;
	insertstate.buf = InvalidBuffer;
	insertstate.postingoff = 0;

	stack = _bt_search_insert(index_relation, &insertstate);
	_bt_check_unique(index_relation, &insertstate, heap_relation, UNIQUE_CHECK_YES, &unique, &specToken, false /*raiseError*/);

	if (BufferIsValid(insertstate.buf)) {
		_bt_relbuf(index_relation, insertstate.buf);
	}

	if (stack) {
		_bt_freestack(stack);
	}
	pfree(itup_key);
	return !unique;
}

struct QSSInstrumentation* qss_AllocInstrumentation(EState* estate) {
	MemoryContext oldcontext = NULL;
	struct QSSInstrumentation* instr = NULL;
	if (top == NULL) {
		// No ExecutorStart yet.
		return NULL;
	}

	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	instr = palloc0(sizeof(struct QSSInstrumentation));
	InstrInit(&(instr->instrument), 0);
	instr->instrument.signature = QSSINSTRUMENTATION_SIGNATURE;
	instr->plan_node_id = top->plan_separate_instr_id;
	top->plan_separate_instr_id--;

	if (top->statement_instrs == NULL) {
		top->statement_instrs = list_make1(instr);
	} else {
		top->statement_instrs = lappend(top->statement_instrs, instr);
	}

	MemoryContextSwitchTo(oldcontext);
	return instr;
}

static void ReplaceInstrumentation(PlanState *ps) {
	NodeTag tag = nodeTag(ps);
	if (tag == T_IndexScanState ||
		tag == T_IndexOnlyScanState ||
		tag == T_ModifyTableState ||
		tag == T_LockRowsState ||
		tag == T_NestLoopState ||
		tag == T_AggState ||
		tag == T_BitmapIndexScanState ||
		tag == T_BitmapHeapScanState) {
		int options = 0;
		struct QSSInstrumentation* instr = palloc0(sizeof(struct QSSInstrumentation));
		if (ps->instrument != NULL) {
			options |= (ps->instrument->need_timer ? INSTRUMENT_TIMER : 0);
			options |= (ps->instrument->need_bufusage ? INSTRUMENT_BUFFERS : 0);
			options |= (ps->instrument->need_walusage ? INSTRUMENT_WAL : 0);
		}

		InstrInit(&(instr->instrument), options);
		instr->plan_node_id = ps->plan->plan_node_id;
		instr->instrument.signature = QSSINSTRUMENTATION_SIGNATURE;
		ps->instrument = &(instr->instrument);

		if (top->statement_instrs == NULL) {
			top->statement_instrs = list_make1(instr);
		} else {
			top->statement_instrs = lappend(top->statement_instrs, instr);
		}
	}

	if (outerPlanState(ps)) {
		ReplaceInstrumentation(outerPlanState(ps));
	}

	if (innerPlanState(ps)) {
		ReplaceInstrumentation(innerPlanState(ps));
	}
}

void qss_ExecutorStart(QueryDesc *query_desc, int eflags) {
	MemoryContext oldcontext = NULL;
	struct ExecutorInstrument* exec = NULL;
	nesting_level++;

	if (qss_prev_ExecutorStart != NULL) {
		qss_prev_ExecutorStart(query_desc, eflags);
	} else {
		standard_ExecutorStart(query_desc, eflags);
	}

	if (!qss_capture_enabled) {
		return;
	}

	if (query_desc->generation < 0) {
		// Ignore if the generation is less than 0.
		return;
	}

	if (query_desc->dest && query_desc->dest->mydest == DestSQLFunction) {
		// Omit all SQL Functions from executing this code fragment.
		return;
	}

	if (nesting_level != 1 && !tscout_capture_nested) {
		return;
	}

	Assert(query_desc->estate != NULL);
	oldcontext = MemoryContextSwitchTo(query_desc->estate->es_query_cxt);

	// Attach an instrument so we capture totaltime.
	if (qss_capture_query_runtime && query_desc->totaltime == NULL) {
		query_desc->totaltime = InstrAlloc(1, INSTRUMENT_TIMER, false);
	}

	// Push a new execution context...
	exec = palloc0(sizeof(struct ExecutorInstrument));
	exec->prev = top;
	top = exec;

	ReplaceInstrumentation(query_desc->planstate);

	// TODO(wz2): This is probably not going to capture re-runs but we're on REPEATABLE_READ.
	exec->statement_ts = GetCurrentStatementStartTimestamp();
	exec->plan_separate_instr_id = PLAN_INDEPENDENT_INSTR_ID_START;

	MemoryContextSwitchTo(oldcontext);
}

void qss_ExecutorEnd(QueryDesc *query_desc) {
	MemoryContext oldcontext;
	Oid plans_index_oid = -1;
	Oid plans_table_oid = -1;
	uint64 queryid = query_desc->plannedstmt->queryId;
	EState *estate = query_desc->estate;

	if (!qss_capture_enabled) {
		goto hook;
	}

	if (query_desc->dest && query_desc->dest->mydest == DestSQLFunction) {
		// Omit all SQL Functions from executing this code fragment.
		goto hook;
	}

	if (query_desc->generation < 0) {
		goto hook;
	}

	if (!tscout_capture_nested && nesting_level != 1) {
		goto hook;
	}

	/* Switch into per-query memory context */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	/* No handling for query 0. */
	if (queryid == UINT64CONST(0) || top == NULL) {
		goto exit;
	}

	// TODO(wz2): This time might bleed into the parent ExecutorEnd if it gets invoked.
	if (query_desc->totaltime != NULL) {
		InstrEndLoop(query_desc->totaltime);
	}

	plans_index_oid = RelnameGetRelid(QUERY_INDEX_NAME);
	plans_table_oid = RelnameGetRelid(QUERY_TABLE_NAME);
	if (plans_index_oid > 0 && plans_table_oid > 0) {
		Datum values[QUERY_TABLE_COLUMNS];
		bool is_nulls[QUERY_TABLE_COLUMNS];
		IndexTuple ind_tup = NULL;
		Relation table_relation = table_open(plans_table_oid, RowExclusiveLock);
		Relation index_relation = index_open(plans_index_oid, RowExclusiveLock);
		Assert(table_relation != NULL && index_relation != NULL);

		memset(is_nulls, 0, sizeof(is_nulls));
		values[0] = Int64GetDatumFast(queryid);
		values[1] = Int32GetDatum(query_desc->generation);
		values[2] = ObjectIdGetDatum(MyDatabaseId);
		values[3] = Int32GetDatum(MyProcPid);
		ind_tup = index_form_tuple(index_relation->rd_att, values, is_nulls);

		/* Insert new tuples to table and index if not found. */
		if (!IndexLookup(query_desc->estate->es_snapshot, table_relation, index_relation, ind_tup)) {
			HeapTuple heap_tup = NULL;
			ItemPointer tid = NULL;
			StringInfo serialized_plan = GetSerializedExplainOutput(query_desc);
			IndexInfo *index_info = BuildIndexInfo(index_relation);

			values[4] = Int64GetDatumFast(top->statement_ts);
			values[5] = PointerGetDatum(cstring_to_text_with_len(serialized_plan->data, serialized_plan->len));
			heap_tup = heap_form_tuple(table_relation->rd_att, values, is_nulls);
			simple_heap_insert(table_relation, heap_tup);

			/* Get new tid and add one entry to index. */
			tid = &(heap_tup->t_self);
			btinsert(index_relation, values, is_nulls, tid, table_relation, UNIQUE_CHECK_YES, false, index_info);

			pfree(serialized_plan->data);
			pfree(serialized_plan);
			pfree(heap_tup);
		}

		pfree(ind_tup);
		table_close(table_relation, RowExclusiveLock);
		index_close(index_relation, RowExclusiveLock);
	}

	if (qss_capture_exec_stats || qss_capture_query_runtime) {
		Datum values[STATS_TABLE_COLUMNS];
		bool is_nulls[STATS_TABLE_COLUMNS];
		Oid stats_table_oid = RelnameGetRelid(STATS_TABLE_NAME);
		if (stats_table_oid > 0) {
			ListCell* lc;
			Relation stats_table_relation = table_open(stats_table_oid, RowExclusiveLock);

			memset(values, 0, sizeof(values));
			memset(is_nulls, 0, sizeof(is_nulls));
			values[0] = Int64GetDatumFast(queryid);
			values[1] = ObjectIdGetDatum(MyDatabaseId);
			values[2] = Int32GetDatum(MyProcPid);
			values[3] = Int64GetDatumFast(top->statement_ts);
			if (qss_capture_query_runtime && query_desc->totaltime) {
				HeapTuple heap_tup = NULL;
				char* param_str = NULL;
				values[4] = Int32GetDatum(-1);
				values[5] = Float8GetDatum(query_desc->totaltime->total * 1000000.0);

				if (query_desc->params != NULL) {
					param_str = BuildParamLogString(query_desc->params, NULL, -1);
					if (param_str) {
						values[15] = CStringGetTextDatum(param_str);
					} else {
						is_nulls[15] = true;
					}
				} else {
					is_nulls[15] = true;
				}

				heap_tup = heap_form_tuple(stats_table_relation->rd_att, values, is_nulls);
				simple_heap_insert(stats_table_relation, heap_tup);
				pfree(heap_tup);

				if (param_str != NULL) {
					pfree(param_str);
				}
			}

			if (qss_capture_exec_stats) {
				foreach(lc, top->statement_instrs) {
					HeapTuple heap_tup = NULL;
					struct QSSInstrumentation *instr = (struct QSSInstrumentation*)lfirst(lc);
					values[4] = Int32GetDatum(instr->plan_node_id);
					values[5] = Float8GetDatum(instr->counter0);
					values[6] = Float8GetDatum(instr->counter1);
					values[7] = Float8GetDatum(instr->counter2);
					values[8] = Float8GetDatum(instr->counter3);
					values[9] = Float8GetDatum(instr->counter4);
					values[10] = Float8GetDatum(instr->counter5);
					values[11] = Float8GetDatum(instr->counter6);
					values[12] = Float8GetDatum(instr->counter7);
					values[13] = Float8GetDatum(instr->counter8);
					values[14] = Float8GetDatum(instr->counter9);
					is_nulls[15] = true;

					heap_tup = heap_form_tuple(stats_table_relation->rd_att, values, is_nulls);
					simple_heap_insert(stats_table_relation, heap_tup);
					pfree(heap_tup);
				}
			}

			table_close(stats_table_relation, RowExclusiveLock);
		}
	}

exit:
	if (top != NULL) {
		// Just pop the context. The memory should get freed by the MemoryContext.
		top = top->prev;
	}

	MemoryContextSwitchTo(oldcontext);

hook:
	if (qss_prev_ExecutorEnd != NULL) {
		qss_prev_ExecutorEnd(query_desc);
	} else {
		standard_ExecutorEnd(query_desc);
	}

	nesting_level--;
}
