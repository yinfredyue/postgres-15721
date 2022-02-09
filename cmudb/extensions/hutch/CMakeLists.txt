# Set up the TScout extension.
add_custom_target(extensions_hutch_install
        # Generate the necessary features.
        COMMAND sudo python3 ${CMAKE_CURRENT_SOURCE_DIR}/tscout_feature_gen.py
        # Install the extension into the default build directory's PostgreSQL.
        # Note that the PG_CONFIG env var can be specified to override which
        # PostgreSQL the extension gets installed into.
        COMMAND make clean -j
        COMMAND make -j
        COMMAND make install -j
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        USES_TERMINAL
        )
