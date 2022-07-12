#!/usr/bin/python3
import binascii
import time
import csv
import argparse
import logging
import multiprocessing as mp
import re
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from distutils import util
from enum import Enum, auto, unique

import psutil
import setproctitle
import psycopg
from psycopg.rows import dict_row


logger = logging.getLogger("collector")


# Name of output file/target --> (query, frequent)
PG_COLLECTOR_TARGETS = {
    "pg_stats": ("SELECT EXTRACT(epoch from NOW())*1000000 as time, pg_stats.* FROM pg_stats WHERE schemaname = 'public';", False),
    "pg_class": ("SELECT EXTRACT(epoch from NOW())*1000000 as time, * FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = 'public';", False),
    "pg_index": ("SELECT EXTRACT(epoch from NOW())*1000000 as time, * FROM pg_index;", False),
    "pg_attribute": ("SELECT EXTRACT(epoch from NOW())*1000000 as time, * FROM pg_attribute;", False),
}


def pg_collector(output_rows, output_columns, slow_time, fast_time, shutdown):
    @unique
    class SettingType(Enum):
        BOOLEAN = auto()
        INTEGER = auto()
        BYTES = auto()
        INTEGER_TIME = auto()
        FLOAT_TIME = auto()
        FLOAT = auto()
        ENUM = auto()

    def _time_unit_to_ms(str):
        if str == "d":
            return 1000 * 60 * 60 * 24
        elif str == "h":
            return 1000 * 60 * 60
        elif str == "min":
            return 1000 * 60
        elif str == "s":
            return 1000
        elif str == "ms":
            return 1
        elif str == "us":
            return 1.0 / 1000
        else:
            return None

    def _parse_field(type, value):
        if type == SettingType.BOOLEAN:
            return util.strtobool(value)
        elif type == SettingType.INTEGER:
            return int(value)
        elif type == SettingType.BYTES:
            if value in ["-1", "0"]:
                # Hardcoded default/disabled values for this field.
                return int(value)
            bytes_regex = re.compile(r"(\d+)\s*([kmgtp]?b)", re.IGNORECASE)
            order = ("b", "kb", "mb", "gb", "tb", "pb")
            field_bytes = None
            for number, unit in bytes_regex.findall(value):
                field_bytes = int(number) * (1024 ** order.index(unit.lower()))
            assert field_bytes is not None, f"Failed to parse bytes from value string {value}"
            return field_bytes
        elif type == SettingType.INTEGER_TIME:
            if value == "-1":
                # Hardcoded default/disabled values for this field.
                return int(value)
            bytes_regex = re.compile(r"(\d+)\s*((?:d|h|min|s|ms|us)?)", re.IGNORECASE)
            field_ms = None
            for number, unit in bytes_regex.findall(value):
                field_ms = int(number) * _time_unit_to_ms(unit)
            assert field_ms is not None, f"Failed to parse time from value string {value}"
            return field_ms
        elif type == SettingType.FLOAT_TIME:
            if value == "0":
                # Hardcoded default/disabled values for this field.
                return int(value)
            bytes_regex = re.compile(r"(\d+(?:\.\d+)?)\s*((?:d|h|min|s|ms|us)?)", re.IGNORECASE)
            field_ms = None
            for number, unit in bytes_regex.findall(value):
                field_ms = float(number) * _time_unit_to_ms(unit)
            assert field_ms is not None, f"Failed to parse time from value string {value}"
            return field_ms
        elif type == SettingType.FLOAT:
            return float(value)
        else:
            return None

    knobs = {
        # https://www.postgresql.org/docs/current/runtime-config-autovacuum.html
        "autovacuum": SettingType.BOOLEAN,
        "autovacuum_max_workers": SettingType.INTEGER,
        "autovacuum_naptime": SettingType.INTEGER_TIME,
        "autovacuum_vacuum_threshold": SettingType.INTEGER,
        "autovacuum_vacuum_insert_threshold": SettingType.INTEGER,
        "autovacuum_analyze_threshold": SettingType.INTEGER,
        "autovacuum_vacuum_scale_factor": SettingType.FLOAT,
        "autovacuum_vacuum_insert_scale_factor": SettingType.FLOAT,
        "autovacuum_analyze_scale_factor": SettingType.FLOAT,
        "autovacuum_freeze_max_age": SettingType.INTEGER,
        "autovacuum_multixact_freeze_max_age": SettingType.INTEGER,
        "autovacuum_vacuum_cost_delay": SettingType.FLOAT_TIME,
        "autovacuum_vacuum_cost_limit": SettingType.INTEGER,
        # https://www.postgresql.org/docs/12/runtime-config-resource.html
        "maintenance_work_mem": SettingType.BYTES,
        "autovacuum_work_mem": SettingType.BYTES,
        "vacuum_cost_delay": SettingType.FLOAT_TIME,
        "vacuum_cost_page_hit": SettingType.INTEGER,
        "vacuum_cost_page_miss": SettingType.INTEGER,
        "vacuum_cost_page_dirty": SettingType.INTEGER,
        "vacuum_cost_limit": SettingType.INTEGER,
        "effective_io_concurrency": SettingType.INTEGER,
        "maintenance_io_concurrency": SettingType.INTEGER,
        "max_worker_processes": SettingType.INTEGER,
        "max_parallel_workers_per_gather": SettingType.INTEGER,
        "max_parallel_maintenance_workers": SettingType.INTEGER,
        "max_parallel_workers": SettingType.INTEGER,

        "jit": SettingType.BOOLEAN,
        "hash_mem_multiplier": SettingType.FLOAT,
        "effective_cache_size": SettingType.BYTES,
        "shared_buffers": SettingType.BYTES,
    }

    def scrape_settings(connection, rows):
        result = []
        with connection.cursor(row_factory=dict_row) as cursor:
            tns = time.time_ns() / 1000
            cursor.execute("SHOW ALL;")
            for record in cursor:
                setting_name = record["name"]
                if setting_name in rows:
                    setting_type = rows[setting_name]
                    setting_str = record["setting"]
                    result.append((setting_name, _parse_field(setting_type, setting_str)))

        connection.commit()
        result.append(("time", tns))
        result.sort(key=lambda t: t[0])
        return result

    def scrape_table(connection, query):
        # Open a cursor to perform database operations
        tuples = []
        columns = []
        with connection.cursor() as cursor:
            # Query the database and obtain data as Python objects.
            cursor.execute(query, prepare=False)
            binary = []
            for i, column in enumerate(cursor.description):
                if column.type_code == 17:
                    binary.append(i)
                columns.append(column.name)

            for record in cursor:
                rec = list(record)
                for binary_col in binary:
                    rec[binary_col] = binascii.hexlify(record[binary_col])
                tuples.append(rec)

        connection.commit()
        return columns, tuples

    setproctitle.setproctitle("Userspace Collector Process")
    with psycopg.connect("host=localhost port=5432 dbname=benchbase user=wz2", autocommit=True) as connection:
        # Poll on the Collector's output buffer until Collector is shut down.
        it = 0
        increments = slow_time / fast_time
        while not shutdown.is_set():
            try:
                knob_values = scrape_settings(connection, knobs)
                knob_columns = [k[0] for k in knob_values]
                knob_values = [k[1] for k in knob_values]
                output_columns["pg_settings"] = knob_columns
                output_rows["pg_settings"].append(knob_values)

                for target, query in PG_COLLECTOR_TARGETS.items():
                    if not query[1] and (it % increments) != 0:
                        continue

                    columns, tuples = scrape_table(connection, query[0])
                    output_columns[target] = columns
                    output_rows[target].extend(tuples)

                time.sleep(fast_time)
                it = it + 1
            except KeyboardInterrupt:
                logger.info("Userspace Collector caught KeyboardInterrupt.")
            except Exception as e:  # pylint: disable=broad-except
                # TODO(Matt): If postgres shuts down the connection closes and we get an exception for that.
                logger.warning("Userspace Collector caught %s.", e)

    logger.info("Userspace Collector shut down.")


def main():
    parser = argparse.ArgumentParser(description="collector")
    parser.add_argument("--outdir", required=False, default=".", help="Training data output directory")
    parser.add_argument("--collector_slow_interval", required=False, default=60, type=int, help="Time between pg collector invocations for infrequent information.")
    parser.add_argument("--collector_fast_interval", required=False, default=1, type=int, help="Time between pg collector invocations for frequent information.")
    args = parser.parse_args()
    outdir = args.outdir
    keep_running = True

    with mp.Manager() as manager:
        # Create coordination data structures for Collectors and Processors
        collector_flags = manager.dict()
        collector_processes = {}

        shutdown = manager.Event()

        pg_scrape_columns = manager.dict()
        pg_scrape_tuples = manager.dict()
        pg_scrape_tuples["pg_settings"] = manager.list()
        for target, _ in PG_COLLECTOR_TARGETS.items():
            pg_scrape_tuples[target] = manager.list()

        pg_collector_process = mp.Process(
            target=pg_collector,
            args=(
                pg_scrape_tuples,
                pg_scrape_columns,
                args.collector_slow_interval,
                args.collector_fast_interval,
                shutdown,
            ),
        )
        pg_collector_process.start()

        while keep_running:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                keep_running = False
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("Collector caught %s.", e)

        print("Collector shutting down.")

        # Shut down the Collectors so that
        # no more data is generated for the Processors.
        shutdown.set()

        pg_collector_process.join()

        PG_COLLECTOR_TARGETS["pg_settings"] = None
        for target in PG_COLLECTOR_TARGETS.keys():
            file_path = f"{outdir}/{target}.csv"
            write_header = not Path(file_path).exists()
            with open(file_path, "a", encoding="utf-8") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow(pg_scrape_columns[target])
                writer.writerows(pg_scrape_tuples[target])
        print("Collector wrote out pg collector data.")

        # We're done.
        sys.exit()


if __name__ == "__main__":
    main()
