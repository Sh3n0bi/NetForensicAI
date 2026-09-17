"""The optional DuckDB memory_limit / threads bounds applied per connection.

Default is unset (DuckDB sizes itself). An env var or saved config value
bounds it; a bad value is ignored rather than breaking the store.
"""

from netforensicai.core.store import CaseStore


def _store(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir(parents=True, exist_ok=True)
    return CaseStore(case_dir)


def _current(store, name):
    return store.conn.execute(f"SELECT current_setting('{name}')").fetchone()[0]


def test_defaults_leave_duckdb_to_size_itself(tmp_path):
    # No env, no config: threads is a positive integer DuckDB chose itself.
    with _store(tmp_path) as store:
        assert int(_current(store, "threads")) >= 1


def test_env_var_bounds_threads_and_memory(tmp_path, monkeypatch):
    monkeypatch.setenv("NETFORENSIC_DUCKDB_THREADS", "2")
    monkeypatch.setenv("NETFORENSIC_DUCKDB_MEMORY_LIMIT", "512MB")
    with _store(tmp_path) as store:
        assert int(_current(store, "threads")) == 2
        # DuckDB reports the limit in its own units; just confirm it is no
        # longer the (much larger) default by checking it parses small.
        mem = _current(store, "memory_limit")
        assert "MiB" in mem or "MB" in mem


def test_invalid_values_are_ignored_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("NETFORENSIC_DUCKDB_THREADS", "not-a-number")
    monkeypatch.setenv("NETFORENSIC_DUCKDB_MEMORY_LIMIT", "banana")
    # Must still open cleanly, falling back to DuckDB's defaults.
    with _store(tmp_path) as store:
        assert int(_current(store, "threads")) >= 1


def test_saved_config_is_used_when_no_env(tmp_path, monkeypatch):
    monkeypatch.delenv("NETFORENSIC_DUCKDB_THREADS", raising=False)
    monkeypatch.setenv("NETFORENSIC_CONFIG_DIR", str(tmp_path / "cfg"))
    from netforensicai.core import config

    config.save_settings({"duckdb_threads": "1"})
    with _store(tmp_path) as store:
        assert int(_current(store, "threads")) == 1
