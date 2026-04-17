from hashcrush.utils import paths


def test_normalize_path_resolves_tilde(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = paths.normalize_path("~/some/dir")
    assert result == str(tmp_path / "some" / "dir")


def test_normalize_path_empty_returns_cwd():
    result = paths.normalize_path("")
    assert result  # non-empty absolute path


def test_is_path_within_root_true():
    assert paths.is_path_within_root("/var/lib/hashcrush/wordlists", "/var/lib/hashcrush")


def test_is_path_within_root_false():
    assert not paths.is_path_within_root("/etc/passwd", "/var/lib/hashcrush")


def test_is_path_within_root_empty():
    assert not paths.is_path_within_root("", "/var/lib/hashcrush")
    assert not paths.is_path_within_root("/var/lib/hashcrush", "")
