from app.services.version_utils import compare_versions, normalize_version, parse_version


def test_version_helpers():
    assert normalize_version("v1.2.3") == "1.2.3"
    assert parse_version("1.2.3") == [1, 2, 3]
    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("2.0", "1.9") == 1
