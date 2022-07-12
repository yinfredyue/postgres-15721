#include "qss.h"
#include "qss_features.h"
#include "access/xact.h"
#include "commands/prepare.h"
#include "tcop/tcopprot.h"

static void qss_ExplainOnePlan(PlannedStmt *plan,
							   const char *queryString,
							   int generation,
							   IntoClause *into,
							   ParamListInfo params,
							   QueryEnvironment *queryEnv,
							   ExplainState *es) {
	QueryDesc *queryDesc;
	int eflags = 0;

	queryDesc = CreateQueryDesc(plan, queryString, generation, InvalidSnapshot, InvalidSnapshot, None_Receiver, params, queryEnv, 0);

	// If we don't do this, we can't get any useful information about the index keys
	// that are actually used to perform the index lookup.
	//
	// TODO(wz2): Note that this will actually break with hypothetical indexes. I think we will probably
	// have to bite the bullet at some point and fork hypopg if we continue to use that. Furthermore,
	// the current hypopg implementation cannot return modifications to insert/update indexes.
	eflags = 0;
	if (into) eflags |= GetIntoRelEFlags(into);

	// Run the executor.
	ExecutorStart(queryDesc, eflags);
	Assert(queryDesc->estate != NULL);

	// Finally, walks through the plan, dumping the output of the plan in a separate top-level group.
	OutputPlanToExplain(queryDesc, es);

	// Free the created query description resources.
	ExecutorFinish(queryDesc);
	ExecutorEnd(queryDesc);
	FreeQueryDesc(queryDesc);
}

void qss_ExplainOneUtility(Node *utilityStmt, IntoClause *into, ExplainState *es, const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv) {
	if (es->format == EXPLAIN_FORMAT_NOISEPAGE && IsA(utilityStmt, ExecuteStmt)) {
		ExecuteStmt *execstmt = (ExecuteStmt*)utilityStmt;
		PreparedStatement *entry;
		PlannedStmt *plan;
		const char *query_string;
		CachedPlan *cplan;

		/* Look it up in the hash table */
		entry = FetchPreparedStatement(execstmt->name, true);

		/* Shouldn't find a non-fixed-result cached plan */
		if (!entry->plansource->fixed_result)
			elog(ERROR, "EXPLAIN EXECUTE does not support variable-result cached plans");

		/* Get a generic plan. */
		cplan = GetCachedPlan(entry->plansource, NULL, CurrentResourceOwner, queryEnv);
		query_string = entry->plansource->query_string;
		if (list_length(cplan->stmt_list) != 1) {
			elog(ERROR, "QSS does not support multi-query or empty query EXPLAIN EXECUTE");
		}

		plan = lfirst_node(PlannedStmt, list_head(cplan->stmt_list));
		if (plan->commandType == CMD_UTILITY) {
			ExplainOneUtility(plan->utilityStmt, into, es, query_string, params, queryEnv);
		} else {
			qss_ExplainOnePlan(plan, query_string, cplan->generation, into, params, queryEnv, es);
		}

		ReleaseCachedPlan(cplan, CurrentResourceOwner);
	} else {
		ExplainOneUtility_hook = qss_prev_ExplainOneUtility;
		ExplainOneUtility(utilityStmt, into, es, queryString, params, queryEnv);
		qss_prev_ExplainOneUtility = ExplainOneUtility_hook;
		ExplainOneUtility_hook = qss_ExplainOneUtility;
	}
}

void qss_ExplainOneQuery(Query *query, int cursorOptions, IntoClause *into, ExplainState *es,
						 const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv) {
	PlannedStmt *plan;
	if (es->format == EXPLAIN_FORMAT_NOISEPAGE) {
		// If there is another advisor present, then let that advisor do whatever it needs to do.
		// Note that we don't actually execute the "real" ExplainOnePlan.
		if (qss_prev_ExplainOneQuery) {
			qss_prev_ExplainOneQuery(query, cursorOptions, into, es, queryString, params, queryEnv);
		}

		plan = pg_plan_query(query, queryString, cursorOptions, params);
		qss_ExplainOnePlan(plan, queryString, 0, into, params, queryEnv, es);
	} else {
		// Unregister the hook, invoke the original ExplainOneQuery() and then re-register the hook.
		ExplainOneQuery_hook = qss_prev_ExplainOneQuery;
		ExplainOneQuery(query, cursorOptions, into, es, queryString, params, queryEnv);
		qss_prev_ExplainOneQuery = ExplainOneQuery_hook;
		ExplainOneQuery_hook = qss_ExplainOneQuery;
	}
}
