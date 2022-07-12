#pragma once

#include "c.h"  // bool
#include "postgres.h"
#include "executor/instrument.h"
#include "nodes/execnodes.h"

extern bool qss_capture_enabled;
extern bool qss_capture_exec_stats;
extern bool qss_capture_nested;
extern bool qss_output_noisepage;

#define PLAN_INVALID_ID (-1)

// This is the Plan ID that should be used to capture any actions that are separate
// from a plan invocation (i.e., triggers). Caller is responsible for ensuring that the
// action's counters are separate from any other action when using this ID.
#define PLAN_INDEPENDENT_ID (-2)

typedef Instrumentation* (*qss_AllocInstrumentation_type) (struct EState* estate, const char *ou);
typedef void (*qss_QSSClear_type)(void);
extern PGDLLIMPORT qss_AllocInstrumentation_type qss_AllocInstrumentation_hook;
extern PGDLLIMPORT qss_QSSClear_type qss_QSSClear_hook;
extern PGDLLIMPORT Instrumentation* ActiveQSSInstrumentation;

Instrumentation* AllocQSSInstrumentation(EState* estate, const char *ou);
void QSSClear(void);

#define QSSInstrumentAddCounter(node, i, val)                                                       \
	do {                                                                                            \
		PlanState* ps = (PlanState *)node;                                                          \
		Instrumentation* inst = ps ? ps->instrument : NULL;                                         \
		if (inst && qss_capture_exec_stats) {                                                       \
			inst->counter##i += val;                                                                \
		}                                                                                           \
	} while(0)

#define ActiveQSSInstrumentAddCounter(i, val)                                                       \
	do {                                                                                            \
		Instrumentation* inst = (Instrumentation*)ActiveQSSInstrumentation;                         \
		if (inst && qss_capture_exec_stats) {                                                       \
			inst->counter##i += val;                                                                \
		}                                                                                           \
	} while(0)
