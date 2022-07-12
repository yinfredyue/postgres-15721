#include "cmudb/qss/qss.h"

bool qss_capture_enabled = false;
bool qss_capture_exec_stats = false;
bool qss_capture_nested = false;
bool qss_output_noisepage = false;

qss_AllocInstrumentation_type qss_AllocInstrumentation_hook = NULL;
qss_QSSClear_type qss_QSSClear_hook = NULL;
Instrumentation* ActiveQSSInstrumentation = NULL;

Instrumentation* AllocQSSInstrumentation(EState* estate, const char *ou) {
	if (qss_capture_enabled && qss_capture_exec_stats && qss_output_noisepage && qss_AllocInstrumentation_hook) {
		return qss_AllocInstrumentation_hook(estate, ou);
	}

	return NULL;
}

void QSSClear() {
	if (qss_QSSClear_hook) {
		qss_QSSClear_hook();
	}

	ActiveQSSInstrumentation = NULL;
}
