#include "cmudb/tscout/sampling.h"

#include "utils/sampling.h"

bool tscout_executor_running = false;
double tscout_executor_sampling_rate = 1.0;
bool tscout_capture_receiver = true;
bool tscout_capture_nested = true;

void TScoutExecutorSample() { tscout_executor_running = anl_random_fract() <= tscout_executor_sampling_rate; }
