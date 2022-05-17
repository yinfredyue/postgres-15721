#pragma once

#include "access/xact.h"
#include "miscadmin.h"
#include "cmudb/tscout/marker.h"
#include "cmudb/tscout/sampling.h"
#include "cmudb/qss/qss.h"

#define PLAN_NODE_ID(p) ((p) ? (p->plan_node_id) : PLAN_INVALID_ID)

#define TS_EXECUTOR_FEATURES(node_type, plan_node)                                                          \
	if (tscout_executor_running) {                                                                          \
		TS_MARKER(Exec##node_type##_features, (plan_node).plan_node_id, estate->es_plannedstmt->queryId,    \
				  MyDatabaseId, GetCurrentStatementStartTimestamp(),                                        \
				  PLAN_NODE_ID((plan_node).lefttree), PLAN_NODE_ID((plan_node).righttree));                 \
	}

#define TS_EXECUTOR_FLUSH(node_type, plan_node)                    \
  if (tscout_executor_running) {                                   \
	TS_MARKER(Exec##node_type##_flush, (plan_node)->plan_node_id); \
  }

/*
 * Wrapper to add TScout markers to an executor. In the executor file, rename
 * the current Exec<blah> function to WrappedExec<blah> and then add
 * TS_EXECUTOR_WRAPPER<blah> beneath it. See src/backend/executors for examples.
 *
 * Some executors cannot use this macro due to function signature differences.
 * If the macro below changes, be sure to update those executors as well. The
 * current list is:
 *
 * src/backend/executors/nodeBitmapAnd.c
 * src/backend/executors/nodeBitmapIndexscan.c
 * src/backend/executors/nodeBitmapOr.c
 * src/backend/executors/nodeSubplan.c
 * src/backend/executors/nodeHash.c
 * src/backend/executors/nodeHashjoin.c
 */
#define TS_EXECUTOR_WRAPPER(node_type)                                \
  static TupleTableSlot *Exec##node_type(PlanState *pstate) {         \
	if (tscout_executor_running) {                                    \
	  TupleTableSlot *result;                                         \
	  TS_MARKER(Exec##node_type##_begin, pstate->plan->plan_node_id); \
																	  \
	  result = WrappedExec##node_type(pstate);                        \
																	  \
	  TS_MARKER(Exec##node_type##_end, pstate->plan->plan_node_id);   \
	  return result;                                                  \
	}                                                                 \
	return WrappedExec##node_type(pstate);                            \
  }
