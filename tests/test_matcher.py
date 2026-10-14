from types import SimpleNamespace

import pytest

from app.services.matcher import assess_cpe_match


DEVICE_MODEL = "Sunny Boy TL-21"
CPE_CRITERION = (
    "cpe:2.3:a:sma:sunny_boy_tl_21:*:*:*:*:*:*:*:*"
)


def make_device(
    firmware="unknown",
    firmware_version=None,
    vendor="SMA Solar Technology",
    model=DEVICE_MODEL,
):
    return SimpleNamespace(
        vendor=vendor,
        model=model,
        firmware=firmware,
        firmware_version=firmware_version,
    )


def make_cve(*criteria):
    return {
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": list(criteria),
            }]
        }]
    }


def make_criterion(**version_range):
    return {
        "vulnerable": True,
        "criteria": CPE_CRITERION,
        **version_range,
    }


def test_unknown_firmware_is_potential_not_confirmed():
    result = assess_cpe_match(
        make_device("unknown"),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")),
    )

    assert result is not None
    assert result[0] == "potential"
    assert "firmware is unknown" in result[1]


@pytest.mark.parametrize("firmware", [None, ""])
def test_missing_firmware_is_not_treated_as_zero(firmware):
    result = assess_cpe_match(
        make_device(firmware),
        make_cve(make_criterion(versionStartIncluding="0", versionEndIncluding="2")),
    )

    assert result is not None
    assert result[0] == "potential"
    assert "firmware is unknown" in result[1]


def test_firmware_in_numeric_range_matches_nvd_criterion():
    result = assess_cpe_match(
        make_device("1.5.0"),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")),
    )

    assert result is not None
    assert result[0] == "affected"
    assert "not independently verified" in result[1]


def test_firmware_outside_numeric_range_is_not_affected_by_that_criterion():
    result = assess_cpe_match(
        make_device("2.1"),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndExcluding="2.0")),
    )

    assert result is not None
    assert result[0] == "not_affected"


@pytest.mark.parametrize(
    ("vendor", "model"),
    [
        ("Different Manufacturer", DEVICE_MODEL),
        ("SMA Solar Technology", "Different Product"),
    ],
)
def test_cpe_product_match_requires_correct_manufacturer_and_model(vendor, model):
    result = assess_cpe_match(
        make_device(
            firmware="1.5",
            vendor=vendor,
            model=model,
        ),
        make_cve(
            make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")
        ),
    )

    assert result is None


def test_firmware_version_is_preferred_to_legacy_firmware():
    result = assess_cpe_match(
        make_device(
            firmware="1.5.0",
            firmware_version="2.1.0",
        ),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")),
    )

    assert result is not None
    assert result[0] == "not_affected"
    assert "Firmware 2.1.0 is outside" in result[1]


def test_legacy_firmware_is_used_when_firmware_version_is_missing():
    result = assess_cpe_match(
        make_device(firmware="1.5.0"),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")),
    )

    assert result is not None
    assert result[0] == "affected"
    assert "Firmware 1.5.0 matches" in result[1]


@pytest.mark.parametrize(
    ("firmware", "firmware_version"),
    [
        ("Unknown", None),
        ("1.5.0", " Unknown "),
        (" ", ""),
    ],
)
def test_unknown_firmware_values_remain_potential(firmware, firmware_version):
    result = assess_cpe_match(
        make_device(firmware=firmware, firmware_version=firmware_version),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")),
    )

    assert result is not None
    assert result[0] == "potential"
    assert "firmware is unknown" in result[1]


def test_unsupported_firmware_suffix_remains_potential():
    result = assess_cpe_match(
        make_device(
            firmware="1.5.0",
            firmware_version="2.60.03.R",
        ),
        make_cve(make_criterion(versionStartIncluding="2.0", versionEndIncluding="3.0")),
    )

    assert result is not None
    assert result[0] == "potential"
    assert "firmware 2.60.03.R" in result[1]
    assert "unsupported" in result[1]


def test_unrecognized_firmware_format_is_not_compared():
    result = assess_cpe_match(
        make_device("1.5-beta"),
        make_cve(make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0")),
    )

    assert result is not None
    assert result[0] == "potential"


def test_or_configuration_matches_when_a_vulnerable_branch_is_true():
    result = assess_cpe_match(
        make_device("1.5"),
        make_cve(
            make_criterion(versionStartIncluding="1.0", versionEndIncluding="2.0"),
            {"vulnerable": False, "criteria": "cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*"},
        ),
    )

    assert result is not None
    assert result[0] == "affected"


def test_and_configuration_requires_every_criterion_to_match():
    result = assess_cpe_match(
        make_device("1.5"),
        {
            "configurations": [{
                "nodes": [{
                    "operator": "AND",
                    "cpeMatch": [
                        make_criterion(
                            versionStartIncluding="1.0",
                            versionEndIncluding="2.0",
                        ),
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:other_vendor:other_os:*:*:*:*:*:*:*:*",
                        },
                    ],
                }]
            }]
        },
    )

    assert result is not None
    assert result[0] == "potential"
    assert "complete NVD Boolean configuration did not evaluate true" in result[1]


def test_negated_matching_vulnerable_criterion_is_not_affected():
    result = assess_cpe_match(
        make_device("1.5"),
        {
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [
                        make_criterion(
                            versionStartIncluding="1.0",
                            versionEndIncluding="2.0",
                        )
                    ],
                }]
            }]
        },
    )

    assert result is not None
    assert result[0] == "not_affected"
    assert "negated" in result[1]


def test_missing_operator_for_multiple_criteria_is_indeterminate():
    result = assess_cpe_match(
        make_device("1.5"),
        {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        make_criterion(
                            versionStartIncluding="1.0",
                            versionEndIncluding="2.0",
                        ),
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:other_vendor:other_os:*:*:*:*:*:*:*:*",
                        },
                    ]
                }]
            }]
        },
    )

    assert result is not None
    assert result[0] == "indeterminate"
    assert "operator" in result[1]


def test_inconsistent_version_bounds_are_indeterminate():
    result = assess_cpe_match(
        make_device("1.5"),
        make_cve(make_criterion(
            versionStartIncluding="2.0",
            versionEndIncluding="1.0",
        )),
    )

    assert result is not None
    assert result[0] == "indeterminate"
