EXTENSION = qss
MODULE_big = qss
DATA = qss--0.0.1.sql
OBJS = qss_stats_functions.o qss_features.o qss_explain.o qss_plans.o qss.o
# If PG_CONFIG is not set, try the default NoisePage build folder.
PG_CONFIG ?= ../../build/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
