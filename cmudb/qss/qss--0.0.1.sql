CREATE FUNCTION qss_install_stats(IN reloid regclass,
    IN relpages INT,                -- number of pages to fake the pg_class entry
    IN reltuples FLOAT4,            -- number of tuples to fake the pg_class entry
    IN tree_height INT DEFAULT 0    -- estimated tree height for b+tree indexes
)
RETURNS void
LANGUAGE C VOLATILE
AS '$libdir/qss', 'qss_install_stats';

CREATE FUNCTION qss_remove_stats(IN reloid regclass)
RETURNS bool
LANGUAGE C VOLATILE
AS '$libdir/qss', 'qss_remove_stats';

CREATE FUNCTION qss_clear_stats()
RETURNS void
LANGUAGE C VOLATILE
AS '$libdir/qss', 'qss_clear_stats';
