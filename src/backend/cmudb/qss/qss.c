#include "cmudb/qss/qss.h"

bool qss_capture_enabled = false;
bool qss_capture_exec_stats = false;
bool qss_capture_query_runtime = false;

qss_AllocInstrumentation_type qss_AllocInstrumentation_hook = NULL;
qss_QSSClear_type qss_QSSClear_hook = NULL;
struct QSSInstrumentation* ActiveQSSInstrumentation = NULL;

struct QSSInstrumentation* AllocQSSInstrumentation(EState* estate) {
	if (qss_capture_exec_stats && qss_AllocInstrumentation_hook) {
		return qss_AllocInstrumentation_hook(estate);
	}

	return NULL;
}

void QSSClear() {
	if (qss_QSSClear_hook) {
		qss_QSSClear_hook();
	}

	ActiveQSSInstrumentation = NULL;
}
