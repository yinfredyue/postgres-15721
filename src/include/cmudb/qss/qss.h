#pragma once

#include "c.h"  // bool
#include "postgres.h"
#include "executor/instrument.h"
#include "nodes/execnodes.h"

extern bool qss_capture_enabled;
extern bool qss_capture_exec_stats;
extern bool qss_capture_query_runtime;

struct QSSInstrumentation {
	Instrumentation instrument;

    int plan_node_id;
    double counter0;
    double counter1;
    double counter2;
    double counter3;
    double counter4;
    double counter5;
    double counter6;
    double counter7;
    double counter8;
    double counter9;
};

#define QSSINSTRUMENTATION_SIGNATURE (0xFACADE)
#define IS_QSSINSTRUMENTATION(sig) ((sig) && (*(uint32_t*)sig == QSSINSTRUMENTATION_SIGNATURE))

#define PLAN_INVALID_ID (-1)

#define PLAN_REMOTE_RECEIVER_ID (-2)

// This is the Plan ID that should be used to capture any tscout actions that are separate
// from a plan invocation (i.e., triggers). Caller is responsible for ensuring that the
// action's counters are separate from any other action when using this ID.
#define PLAN_INDEPENDENT_ID (-3)

// This is the PLAN_INDEPENDENT_ID that is used to capture any plan invocation separate
// TScout action that also needs to be reconciled with QSS counters. IDs are decremented
// by 1 starting from this.
#define PLAN_INDEPENDENT_INSTR_ID_START (-4)

typedef struct QSSInstrumentation* (*qss_AllocInstrumentation_type) (struct EState* estate);
typedef void (*qss_QSSClear_type)(void);
extern PGDLLIMPORT qss_AllocInstrumentation_type qss_AllocInstrumentation_hook;
extern PGDLLIMPORT qss_QSSClear_type qss_QSSClear_hook;
extern PGDLLIMPORT struct QSSInstrumentation* ActiveQSSInstrumentation;

struct QSSInstrumentation* AllocQSSInstrumentation(EState* estate);
void QSSClear(void);

#define QSSInstrumentBeginTime(node)                                                                \
	do {                                                                                            \
		instr_time start, end;                                                                      \
		PlanState* ps = (PlanState *)node;                                                          \
		Instrumentation* inst = ps ? ps->instrument : NULL;                                         \
		if (inst && qss_capture_exec_stats && IS_QSSINSTRUMENTATION(inst)) {                        \
			INSTR_TIME_SET_CURRENT(start);                                                          \
		}                                                                                           \
	} while(0)

#define QSSInstrumentEndTimeMicrosec(node, i)                                                       \
	do {                                                                                            \
		PlanState* ps = (PlanState *)node;                                                          \
		Instrumentation* inst = ps ? ps->instrument : NULL;                                         \
		if (inst && qss_capture_exec_stats && IS_QSSINSTRUMENTATION(inst)) {                        \
			INSTR_TIME_SET_CURRENT(end);                                                            \
			INSTR_TIME_SUBTRACT(end, start);                                                        \
			((struct QSSInstrumentation*)inst)->counter##i += INSTR_TIME_GET_MICROSEC(end);         \
		}                                                                                           \
	} while(0)

#define QSSInstrumentAddCounter(node, i, val)                                                       \
	do {                                                                                            \
		PlanState* ps = (PlanState *)node;                                                          \
		Instrumentation* inst = ps ? ps->instrument : NULL;                                         \
		if (inst && qss_capture_exec_stats && IS_QSSINSTRUMENTATION(inst)) {                        \
			((struct QSSInstrumentation*)inst)->counter##i += val;                                  \
		}                                                                                           \
	} while(0)

#define ActiveQSSInstrumentAddCounter(i, val)                                                       \
	do {                                                                                            \
		Instrumentation* inst = (Instrumentation*)ActiveQSSInstrumentation;                         \
		if (inst && qss_capture_exec_stats && IS_QSSINSTRUMENTATION(inst)) {                        \
			((struct QSSInstrumentation*)inst)->counter##i += val;                                  \
		}                                                                                           \
	} while(0)
