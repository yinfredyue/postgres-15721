import os

import doit

from dodos import VERBOSITY_DEFAULT


def task_qss_install():
    """
    QSS: Compile and install the QSS extension.
    """
    return {
        "actions": [
            lambda: os.chdir("cmudb/qss/"),
            # Generate the necessary features.
            "python3 clang_gen.py",
            "PG_CONFIG=%(pg_config)s make clean -j",
            "PG_CONFIG=%(pg_config)s make -j",
            "PG_CONFIG=%(pg_config)s make install -j",
            # Reset working directory.
            lambda: os.chdir(doit.get_initial_workdir()),
        ],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
        "params": [
            {
                "name": "pg_config",
                "long": "pg_config",
                "help": "The location of the pg_config binary.",
                "default": "../../build/bin/pg_config",
            },
        ],
    }
