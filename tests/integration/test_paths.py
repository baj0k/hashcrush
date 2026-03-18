from pathlib import Path

from hashcrush import paths


def test_get_default_config_path_prefers_explicit_env(monkeypatch):
    custom_path = "/tmp/hashcrush-custom.conf"
    monkeypatch.setenv("HASHCRUSH_CONFIG_PATH", custom_path)

    assert paths.get_default_config_path() == Path(custom_path)


def test_get_default_config_path_defaults_to_system_path_when_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("HASHCRUSH_CONFIG_PATH", raising=False)
    monkeypatch.setattr(paths, "get_system_config_path", lambda: tmp_path / "system.conf")
    monkeypatch.setattr(paths, "get_legacy_config_path", lambda: tmp_path / "legacy.conf")

    assert paths.get_default_config_path() == tmp_path / "system.conf"


def test_get_default_config_path_prefers_system_config_when_present(
    monkeypatch, tmp_path
):
    system_path = tmp_path / "system.conf"
    system_path.write_text("[app]\n", encoding="utf-8")
    monkeypatch.delenv("HASHCRUSH_CONFIG_PATH", raising=False)
    monkeypatch.setattr(paths, "get_system_config_path", lambda: system_path)
    monkeypatch.setattr(paths, "get_legacy_config_path", lambda: tmp_path / "legacy.conf")

    assert paths.get_default_config_path() == system_path


def test_iter_test_env_paths_prefers_tests_directory():
    env_paths = paths.iter_test_env_paths()

    assert env_paths[0] == paths.get_default_test_env_path()
    assert env_paths[1] == paths.get_legacy_test_env_path()
