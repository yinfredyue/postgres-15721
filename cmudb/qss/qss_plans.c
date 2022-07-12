#include "qss.h"
#include "qss_features.h"

#include "access/nbtree.h"
#include "access/heapam.h"
#include "access/relation.h"
#include "catalog/namespace.h"
#include "catalog/index.h"
#include "cmudb/qss/qss.h"
#include "commands/explain.h"
#include "miscadmin.h"
#include "nodes/pg_list.h"
#include "utils/builtins.h"

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
	elapsed_us float8,
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
	payload bigint,
	comment text
 )
 */
#define STATS_TABLE_NAME "pg_qss_stats"
#define STATS_TABLE_COLUMNS 18
#define STATS_TABLE_COMMENT_IDX 17

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

static void WriteInstrumentation(Plan *plan, Instrumentation *instr, Relation stats_table_relation, Datum *values, bool *nulls) {
	HeapTuple heap_tup = NULL;
	const char* nodeName = NULL;
	InstrEndLoop(instr);
	values[4] = Int32GetDatum(plan ? plan->plan_node_id : instr->plan_node_id);
	values[5] = Float8GetDatum(instr->total * 1000000.0);
	values[6] = Float8GetDatum(instr->counter0);
	values[7] = Float8GetDatum(instr->counter1);
	values[8] = Float8GetDatum(instr->counter2);
	values[9] = Float8GetDatum(instr->counter3);
	values[10] = Float8GetDatum(instr->counter4);
	values[11] = Float8GetDatum(instr->counter5);
	values[12] = Float8GetDatum(instr->counter6);
	values[13] = Float8GetDatum(instr->counter7);
	values[14] = Float8GetDatum(instr->counter8);
	values[15] = Float8GetDatum(instr->counter9);
	values[16] = Int64GetDatum(instr->payload);

	if (plan) {
		if (plan->type == T_ModifyTable) {
			ModifyTable* mt = (ModifyTable*)plan;
			if (mt->operation == CMD_INSERT) {
				nodeName = "ModifyTableInsert";
			} else if (mt->operation == CMD_UPDATE) {
				nodeName = "ModifyTableUpdate";
			} else {
				Assert(mt->operation == CMD_DELETE);
				nodeName = "ModifyTableDelete";
			}
		} else {
			nodeName = NodeToName((Node*)plan);
		}
	} else {
		nodeName = instr->ou ? instr->ou : "";
	}

	values[STATS_TABLE_COMMENT_IDX] = PointerGetDatum(cstring_to_text(nodeName));
	nulls[STATS_TABLE_COMMENT_IDX] = false;

	heap_tup = heap_form_tuple(stats_table_relation->rd_att, values, nulls);
	simple_heap_insert(stats_table_relation, heap_tup);
	pfree(heap_tup);
}

static void WritePlanInstrumentation(Plan *plan, PlanState *ps, Relation stats_table_relation, Datum *values, bool *nulls) {
	Instrumentation *instr = ps->instrument;
	if (instr != NULL) {
		WriteInstrumentation(plan, instr, stats_table_relation, values, nulls);
	}

	if (outerPlanState(ps) != NULL) {
		WritePlanInstrumentation(outerPlan(plan), outerPlanState(ps), stats_table_relation, values, nulls);
	}

	if (innerPlanState(ps) != NULL) {
		WritePlanInstrumentation(innerPlan(plan), innerPlanState(ps), stats_table_relation, values, nulls);
	}
}

// All memory for ExecutorInstrument is charged to the query context that is executing
// the query that we are attempting to instrument. We do not use qss_MemoryContext
// for allocating any of this memory.
struct ExecutorInstrument {
	TimestampTz statement_ts;
	List* statement_instrs;
	struct ExecutorInstrument* prev;
};

int nesting_level = 0;
struct ExecutorInstrument* top = NULL;

void qss_Clear() {
	// These should get freed by the query MemoryContext.
	ActiveQSSInstrumentation = NULL;
	top = NULL;
	nesting_level = 0;
}

Instrumentation* qss_AllocInstrumentation(EState* estate, const char *ou) {
	MemoryContext oldcontext = NULL;
	Instrumentation* instr = NULL;
	if (top == NULL) {
		// No ExecutorStart yet.
		return NULL;
	}

	if (!qss_capture_enabled ||
		!qss_capture_exec_stats ||
		!qss_output_noisepage) {
		// Not enabled.
		return NULL;
	}

	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	instr = palloc0(sizeof(Instrumentation));
	InstrInit(instr, INSTRUMENT_TIMER);
	instr->plan_node_id = PLAN_INDEPENDENT_ID;
	instr->ou = ou;

	if (top->statement_instrs == NULL) {
		top->statement_instrs = list_make1(instr);
	} else {
		top->statement_instrs = lappend(top->statement_instrs, instr);
	}

	MemoryContextSwitchTo(oldcontext);
	return instr;
}

void qss_ExecutorStart(QueryDesc *query_desc, int eflags) {
	MemoryContext oldcontext = NULL;
	struct ExecutorInstrument* exec = NULL;
	bool need_instrument;
	bool need_total;
	nesting_level++;

	need_total = qss_capture_enabled && (qss_capture_nested || nesting_level == 1);
	need_instrument = qss_capture_enabled &&
					  qss_capture_exec_stats &&
					  (qss_capture_nested || nesting_level == 1) &&
					  query_desc->generation >= 0 &&
					  (!query_desc->dest || query_desc->dest->mydest != DestSQLFunction);

	// Attach INSTRUMENT_TIMER if we want those statistics.
	if (need_instrument) {
		query_desc->instrument_options |= INSTRUMENT_TIMER;
	}

	// Initialize the plan.
	if (qss_prev_ExecutorStart != NULL) {
		qss_prev_ExecutorStart(query_desc, eflags);
	} else {
		standard_ExecutorStart(query_desc, eflags);
	}

	Assert(query_desc->estate != NULL);
	oldcontext = MemoryContextSwitchTo(query_desc->estate->es_query_cxt);
	exec = palloc0(sizeof(struct ExecutorInstrument));
	// TODO(wz2): This is probably not going to capture re-runs but we're on REPEATABLE_READ.
	exec->statement_ts = GetCurrentStatementStartTimestamp();
	exec->prev = top;
	top = exec;

	if (need_total && query_desc->totaltime == NULL) {
		// Attach an instrument so we capture totaltime.
		query_desc->totaltime = InstrAlloc(1, INSTRUMENT_TIMER, false, 0);
	}

	MemoryContextSwitchTo(oldcontext);
}

static void ProcessQueryExplain(QueryDesc *query_desc, bool instrument) {
	// Setup ExplainState
	ExplainState *es = NULL;
	es = NewExplainState();
	es->analyze = instrument;
	es->verbose = true;
	es->timing = true;
	es->format = EXPLAIN_FORMAT_JSON;

	// OUtput all relevant information.
	ExplainBeginOutput(es);
	ExplainQueryText(es, query_desc);
	ExplainPropertyInteger("start_time", NULL, top->statement_ts, es);
	ExplainPropertyFloat("elapsed_us", NULL, query_desc->totaltime->total * 1000000.0, 9, es);
	ExplainPrintPlan(es, query_desc);
	if (es->analyze)
		ExplainPrintTriggers(es, query_desc);
	ExplainEndOutput(es);

	if (es->str->len > 0 && es->str->data[es->str->len - 1] == '\n')
		es->str->data[--es->str->len] = '\0';

	/* Fix JSON to output an object */
	es->str->data[0] = '{';
	es->str->data[es->str->len - 1] = '}';
	ereport(LOG, (errmsg("%s", es->str->data), errhidestmt(true)));
}

static void ProcessQueryInternalTable(QueryDesc *query_desc, bool instrument) {
	Datum values[STATS_TABLE_COLUMNS];
	bool is_nulls[STATS_TABLE_COLUMNS];
	Oid plans_index_oid = RelnameGetRelid(QUERY_INDEX_NAME);
	Oid plans_table_oid = RelnameGetRelid(QUERY_TABLE_NAME);
	Oid stats_table_oid = RelnameGetRelid(STATS_TABLE_NAME);
	if (plans_index_oid > 0 && plans_table_oid > 0) {
		IndexTuple ind_tup = NULL;
		Relation table_relation = table_open(plans_table_oid, RowExclusiveLock);
		Relation index_relation = index_open(plans_index_oid, RowExclusiveLock);
		Assert(table_relation != NULL && index_relation != NULL);

		memset(is_nulls, 0, sizeof(is_nulls));
		values[0] = Int64GetDatumFast(query_desc->plannedstmt->queryId);
		values[1] = Int32GetDatum(query_desc->generation);
		values[2] = ObjectIdGetDatum(MyDatabaseId);
		values[3] = Int32GetDatum(MyProcPid);
		ind_tup = index_form_tuple(index_relation->rd_att, values, is_nulls);
		if (!IndexLookup(query_desc->estate->es_snapshot, table_relation, index_relation, ind_tup)) {
			HeapTuple heap_tup = NULL;
			ItemPointer tid = NULL;
			ExplainState *es = NULL;
			IndexInfo *index_info = BuildIndexInfo(index_relation);

			// Store the statement timestamp.
			values[4] = Int64GetDatumFast(top->statement_ts);

			// Make the query plan.
			es = NewExplainState();
			es->analyze = true;
			es->format = EXPLAIN_FORMAT_NOISEPAGE;
			ExplainBeginOutput(es);
			OutputPlanToExplain(query_desc, es);
			ExplainEndOutput(es);
			values[5] = PointerGetDatum(cstring_to_text_with_len(es->str->data, es->str->len));

			heap_tup = heap_form_tuple(table_relation->rd_att, values, is_nulls);
			simple_heap_insert(table_relation, heap_tup);

			/* Get new tid and add one entry to index. */
			tid = &(heap_tup->t_self);
			btinsert(index_relation, values, is_nulls, tid, table_relation, UNIQUE_CHECK_YES, false, index_info);
			pfree(heap_tup);
		}

		pfree(ind_tup);
		table_close(table_relation, RowExclusiveLock);
		index_close(index_relation, RowExclusiveLock);
	}

	if (stats_table_oid > 0) {
		ListCell* lc;
		Relation stats_table_relation = table_open(stats_table_oid, RowExclusiveLock);

		memset(values, 0, sizeof(values));
		memset(is_nulls, 0, sizeof(is_nulls));
		values[0] = Int64GetDatumFast(query_desc->plannedstmt->queryId);
		values[1] = ObjectIdGetDatum(MyDatabaseId);
		values[2] = Int32GetDatum(MyProcPid);
		values[3] = Int64GetDatumFast(top->statement_ts);
		if (query_desc->totaltime) {
			HeapTuple heap_tup = NULL;
			char* param_str = NULL;
			values[4] = Int32GetDatum(-1);
			values[5] = Float8GetDatum(query_desc->totaltime->total * 1000000.0);

			if (query_desc->params != NULL) {
				param_str = BuildParamLogString(query_desc->params, NULL, -1);
				if (param_str) {
					values[STATS_TABLE_COMMENT_IDX] = CStringGetTextDatum(param_str);
					is_nulls[STATS_TABLE_COMMENT_IDX] = false;
				} else {
					is_nulls[STATS_TABLE_COMMENT_IDX] = true;
				}
			} else {
				is_nulls[STATS_TABLE_COMMENT_IDX] = true;
			}

			heap_tup = heap_form_tuple(stats_table_relation->rd_att, values, is_nulls);
			simple_heap_insert(stats_table_relation, heap_tup);
			pfree(heap_tup);

			if (param_str != NULL) {
				pfree(param_str);
			}
		}

		if (qss_capture_exec_stats && instrument) {
			foreach(lc, top->statement_instrs) {
				Instrumentation *instr = (Instrumentation*)lfirst(lc);
				if (instr != NULL) {
					WriteInstrumentation(NULL, instr, stats_table_relation, values, is_nulls);
				}
			}

			WritePlanInstrumentation(query_desc->planstate->plan, query_desc->planstate, stats_table_relation, values, is_nulls);
		}

		table_close(stats_table_relation, RowExclusiveLock);
	}
}

void qss_ExecutorEnd(QueryDesc *query_desc) {
	MemoryContext oldcontext;
	EState *estate = query_desc->estate;
	bool need_instrument;

	/* Switch into per-query memory context */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	need_instrument = qss_capture_enabled &&
					  qss_capture_exec_stats &&
					  (qss_capture_nested || nesting_level == 1) &&
					  query_desc->generation >= 0 &&
					  (!query_desc->dest || query_desc->dest->mydest != DestSQLFunction);

	if (qss_capture_enabled && query_desc->totaltime != NULL && top != NULL) {
		// End the loop on this counter.
		InstrEndLoop(query_desc->totaltime);

		if (qss_output_noisepage) {
			ProcessQueryInternalTable(query_desc, need_instrument);
		} else {
			ProcessQueryExplain(query_desc, need_instrument);
		}
	}

	if (top != NULL) {
		// Just pop the context. The memory should get freed by the MemoryContext.
		top = top->prev;
	}

	MemoryContextSwitchTo(oldcontext);

	if (qss_prev_ExecutorEnd != NULL) {
		qss_prev_ExecutorEnd(query_desc);
	} else {
		standard_ExecutorEnd(query_desc);
	}

	nesting_level--;
}
