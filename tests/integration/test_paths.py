from pathlib import Path

from hashcrush import paths


def test_get_default_config_path_prefers_explicit_env(monkeypatch):
    custom_path = "/tmp/hashcrush-custom.conf"
    monkeypatch.setenv("HASHCRUSH_CONFIG_PATH", custom_path)

    assert paths.get_default_config_path() == Path(custom_path)


def test_get_default_config_path_uses_repo_runtime_when_no_legacy_config(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("HASHCRUSH_CONFIG_PATH", raising=False)
    monkeypatch.setattr(paths, "get_legacy_config_path", lambda: tmp_path / "legacy.conf")
    monkeypatch.setattr(paths, "get_repo_runtime_root", lambda: tmp_path / ".runtime")

    assert paths.get_default_config_path() == tmp_path / ".runtime" / "config.conf"


def test_iter_test_env_paths_prefers_tests_directory():
    env_paths = paths.iter_test_env_paths()

    assert env_paths[0] == paths.get_default_test_env_path()
    assert env_paths[1] == paths.get_legacy_test_env_path()
