#ifndef __QSS_H__
#define __QSS_H__

#include "postgres.h"
#include "fmgr.h"

#include "commands/explain.h"
#include "commands/createas.h"
#include "nodes/parsenodes.h"
#include "optimizer/planner.h"
#include "optimizer/plancat.h"

extern ExplainOneQuery_hook_type qss_prev_ExplainOneQuery;
extern ExplainOneUtility_hook_type qss_prev_ExplainOneUtility;
extern ExecutorEnd_hook_type qss_prev_ExecutorEnd;
extern ExecutorStart_hook_type qss_prev_ExecutorStart;
extern get_relation_info_hook_type qss_prev_get_relation_info;

void qss_Clear(void);
void qss_ExecutorStart(QueryDesc *query_desc, int eflags);
void qss_ExecutorEnd(QueryDesc *query_desc);
void qss_ExplainOneQuery(Query *query, int cursorOptions, IntoClause *into, ExplainState *es, const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv);
void qss_ExplainOneUtility(Node *utilityStmt, IntoClause *into, ExplainState *es, const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv);
void qss_GetRelationInfo(PlannerInfo*, Oid, bool, RelOptInfo*);
Instrumentation* qss_AllocInstrumentation(struct EState* estate, const char *ou);

extern MemoryContext qss_MemoryContext;

#endif
