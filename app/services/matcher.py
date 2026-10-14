from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.cpe_resolver import resolve_vendor_token
from app.services.version_utils import compare_versions


@dataclass(frozen=True)
class _CPEEvaluation:
    value: bool | None
    has_product_match: bool = False
    has_vulnerable_candidate: bool = False
    has_vulnerable_match: bool = False
    has_out_of_range_match: bool = False
    uncertain: bool = False
    ambiguous_logic: bool = False
    has_negated_candidate: bool = False
    evidence: tuple[str, ...] = ()


def text_tokens(value: str | None) -> set[str]:
    if not value:
        return set()
    return set(re.findall(r"[a-z0-9]+", value.lower()))


def generate_vendor_model_tokens(device) -> set[str]:
    tokens = set()

    for value in [device.vendor, device.model, device.firmware, device.name]:
        tokens |= text_tokens(value)

    return tokens


def compute_match_score(device, cve_summary: str | None) -> int:
    if not cve_summary:
        return 0

    description = cve_summary.lower()
    vendor = (device.vendor or "").strip().lower()
    model = (device.model or "").strip().lower()

    score = 0

    if vendor and len(vendor) >= 4 and vendor in description:
        score += 5

    if model and len(model) >= 4 and model in description:
        score += 10

    return score


def assess_cpe_match(device, cve_data: dict) -> tuple[str, str] | None:
    """Evaluate NVD Boolean CPE configurations conservatively."""
    configurations = cve_data.get("configurations")
    if configurations is None or configurations == []:
        return None
    if not isinstance(configurations, list):
        return None

    evaluations = []
    for configuration in configurations:
        if not isinstance(configuration, dict):
            evaluations.append(_unknown("Malformed NVD configuration entry."))
            continue

        roots = configuration.get("nodes")
        if not isinstance(roots, list) or not roots:
            evaluations.append(_unknown("NVD configuration has no valid root nodes."))
        elif len(roots) == 1:
            evaluations.append(_evaluate_node(roots[0], device))
        else:
            combined = _combine(
                [_evaluate_node(root, device) for root in roots],
                "AND",
            )
            evaluations.append(_CPEEvaluation(
                value=None,
                has_product_match=combined.has_product_match,
                has_vulnerable_candidate=combined.has_vulnerable_candidate,
                has_vulnerable_match=combined.has_vulnerable_match,
                has_out_of_range_match=combined.has_out_of_range_match,
                uncertain=True,
                ambiguous_logic=True,
                has_negated_candidate=combined.has_negated_candidate,
                evidence=combined.evidence
                + ("Multiple configuration root nodes have no explicit operator.",),
            ))

    overall = _combine(evaluations, "OR")
    if not overall.has_product_match:
        return None

    evidence = "; ".join(overall.evidence[:8])
    if overall.value is True and overall.has_vulnerable_match:
        return (
            "affected",
            "NVD CPE configuration evaluated true and includes a vulnerable "
            f"criterion matching the device product and firmware. {evidence} "
            "Device identity and firmware were not independently verified.",
        )

    if overall.ambiguous_logic:
        return (
            "indeterminate",
            "A device-product CPE criterion matched, but NVD configuration logic "
            f"or firmware comparison could not be resolved safely. {evidence}",
        )

    if overall.uncertain or overall.value is None:
        return (
            "potential",
            "A device-product CPE criterion matched, but firmware or version "
            f"comparison is unknown. {evidence}",
        )

    if overall.has_vulnerable_match:
        return (
            "potential",
            "A vulnerable device-product CPE criterion matched, but the complete "
            f"NVD Boolean configuration did not evaluate true. {evidence}",
        )

    if (
        overall.value is False
        and overall.has_vulnerable_candidate
        and (overall.has_out_of_range_match or overall.has_negated_candidate)
    ):
        reason = (
            "The NVD Boolean configuration excluded the matching device criterion."
            if overall.has_negated_candidate
            else "Its known firmware falls outside the evaluated vulnerable ranges."
        )
        return (
            "not_affected",
            f"The device product matched NVD vulnerable criteria, but {reason} "
            f"{evidence}",
        )

    return (
        "potential",
        "The device product appears in NVD CPE data, but no fully evaluated "
        f"vulnerable criterion confirms applicability. {evidence}",
    )


def _evaluate_node(value, device) -> _CPEEvaluation:
    if not isinstance(value, dict):
        return _unknown("Malformed NVD CPE node.")

    terms = []
    cpe_matches = value.get("cpeMatch", [])
    if not isinstance(cpe_matches, list):
        terms.append(_unknown("NVD CPE match list is malformed."))
    else:
        for criterion in cpe_matches:
            terms.append(
                _evaluate_criterion(criterion, device)
                if isinstance(criterion, dict)
                else _unknown("Malformed NVD CPE criterion.")
            )

    for child_key in ("nodes", "children"):
        children = value.get(child_key, [])
        if not isinstance(children, list):
            terms.append(_unknown(f"NVD {child_key} list is malformed."))
            continue
        terms.extend(_evaluate_node(child, device) for child in children)

    if not terms:
        return _unknown("NVD CPE node contains no evaluable criteria.")

    operator = value.get("operator")
    if operator is None and len(terms) == 1:
        result = terms[0]
    elif isinstance(operator, str) and operator.upper() in {"AND", "OR"}:
        result = _combine(terms, operator.upper())
    else:
        result = _unknown(
            f"Unsupported or missing NVD Boolean operator: {operator!r}.",
            terms,
        )

    negate = value.get("negate", False)
    if not isinstance(negate, bool):
        return _unknown("NVD negate flag is not a Boolean value.", [result])
    if negate:
        return _CPEEvaluation(
            value=None if result.value is None else not result.value,
            has_product_match=result.has_product_match,
            has_vulnerable_candidate=result.has_vulnerable_candidate,
            has_vulnerable_match=False,
            has_out_of_range_match=result.has_out_of_range_match,
            uncertain=result.uncertain,
            ambiguous_logic=result.ambiguous_logic,
            has_negated_candidate=(
                result.has_negated_candidate or result.has_vulnerable_candidate
            ),
            evidence=result.evidence + ("NVD node is negated.",),
        )
    return result


def _evaluate_criterion(criterion: dict, device) -> _CPEEvaluation:
    criteria = criterion.get("criteria")
    product_match = _cpe_product_matches_device(criteria, device)
    if product_match is False:
        return _CPEEvaluation(value=False)
    if product_match is None:
        return _unknown("NVD CPE product identity is malformed or ambiguous.")

    vulnerable = criterion.get("vulnerable")
    if not isinstance(vulnerable, bool):
        return _CPEEvaluation(
            value=None,
            has_product_match=True,
            uncertain=True,
            ambiguous_logic=True,
            evidence=("Matching NVD CPE criterion has no valid vulnerable flag.",),
        )

    firmware = _device_firmware_version(device)
    firmware_match = _version_matches(firmware, criterion)
    if firmware_match is None:
        firmware_evidence = (
            f"firmware is unknown ({firmware or 'not provided'})"
            if firmware is None
            else f"firmware {firmware} or its NVD version range is unsupported"
        )
        return _CPEEvaluation(
            value=None,
            has_product_match=True,
            has_vulnerable_candidate=vulnerable,
            uncertain=True,
            ambiguous_logic=_numeric_version(firmware) is not None,
            evidence=(
                f"NVD CPE product matched ({criteria}), but {firmware_evidence}.",
            ),
        )

    if firmware_match:
        kind = "vulnerable" if vulnerable else "non-vulnerable context"
        return _CPEEvaluation(
            value=True,
            has_product_match=True,
            has_vulnerable_candidate=vulnerable,
            has_vulnerable_match=vulnerable,
            evidence=(
                f"Firmware {firmware} matches {kind} CPE criterion "
                f"{criteria}.",
            ),
        )

    return _CPEEvaluation(
        value=False,
        has_product_match=True,
        has_vulnerable_candidate=vulnerable,
        has_out_of_range_match=vulnerable,
        evidence=(
            f"Firmware {firmware} is outside CPE criterion {criteria}.",
        ),
    )


def _combine(
    evaluations: list[_CPEEvaluation],
    operator: str,
) -> _CPEEvaluation:
    values = [evaluation.value for evaluation in evaluations]
    if operator == "AND":
        value = (
            False if False in values
            else True if all(item is True for item in values)
            else None
        )
    else:
        value = (
            True if True in values
            else False if all(item is False for item in values)
            else None
        )
    vulnerable_match = any(
        item.has_vulnerable_match
        and (operator != "OR" or value is not True or item.value is True)
        for item in evaluations
    )
    return _CPEEvaluation(
        value=value,
        has_product_match=any(item.has_product_match for item in evaluations),
        has_vulnerable_candidate=any(
            item.has_vulnerable_candidate for item in evaluations
        ),
        has_vulnerable_match=vulnerable_match,
        has_out_of_range_match=any(
            item.has_out_of_range_match for item in evaluations
        ),
        uncertain=any(item.uncertain for item in evaluations),
        ambiguous_logic=any(item.ambiguous_logic for item in evaluations),
        has_negated_candidate=any(
            item.has_negated_candidate for item in evaluations
        ),
        evidence=tuple(
            evidence
            for evaluation in evaluations
            for evidence in evaluation.evidence
        ),
    )


def _unknown(
    reason: str,
    evaluations: list[_CPEEvaluation] | None = None,
) -> _CPEEvaluation:
    nested = evaluations or []
    return _CPEEvaluation(
        value=None,
        has_product_match=any(item.has_product_match for item in nested),
        has_vulnerable_candidate=any(
            item.has_vulnerable_candidate for item in nested
        ),
        has_vulnerable_match=any(item.has_vulnerable_match for item in nested),
        has_out_of_range_match=any(
            item.has_out_of_range_match for item in nested
        ),
        uncertain=True,
        ambiguous_logic=True,
        has_negated_candidate=any(
            item.has_negated_candidate for item in nested
        ),
        evidence=tuple(
            evidence for item in nested for evidence in item.evidence
        ) + (reason,),
    )


def _cpe_product_matches_device(criteria: str | None, device) -> bool | None:
    if not isinstance(criteria, str):
        return None
    fields = criteria.split(":")
    if len(fields) < 6 or fields[:2] != ["cpe", "2.3"]:
        return None

    vendor, product = fields[3], fields[4]
    if not vendor or not product or vendor in {"*", "-"} or product in {"*", "-"}:
        return None
    if not device.vendor or not device.model:
        return None

    normalized_vendor = re.sub(r"[^a-z0-9]", "", vendor.lower())
    normalized_product = re.sub(r"[^a-z0-9]", "", product.lower())
    device_vendor = re.sub(
        r"[^a-z0-9]", "", resolve_vendor_token(device.vendor).lower()
    )
    device_product = re.sub(r"[^a-z0-9]", "", device.model.lower())
    if not normalized_vendor or not normalized_product:
        return None
    return (
        normalized_vendor == device_vendor
        and normalized_product == device_product
    )


def _version_matches(firmware: str | None, criterion: dict) -> bool | None:
    firmware_version = _numeric_version(firmware)
    if firmware_version is None:
        return None

    start_including = criterion.get("versionStartIncluding")
    start_excluding = criterion.get("versionStartExcluding")
    end_including = criterion.get("versionEndIncluding")
    end_excluding = criterion.get("versionEndExcluding")
    bounds = [start_including, start_excluding, end_including, end_excluding]

    if (
        start_including is not None
        and start_excluding is not None
        or end_including is not None
        and end_excluding is not None
    ):
        return None
    if any(bound is not None and _numeric_version(bound) is None for bound in bounds):
        return None
    if (
        start_including is not None
        and end_including is not None
        and compare_versions(start_including, end_including) > 0
        or start_including is not None
        and end_excluding is not None
        and compare_versions(start_including, end_excluding) >= 0
        or start_excluding is not None
        and end_including is not None
        and compare_versions(start_excluding, end_including) >= 0
        or start_excluding is not None
        and end_excluding is not None
        and compare_versions(start_excluding, end_excluding) >= 0
    ):
        return None

    has_bounds = any(bound is not None for bound in bounds)
    if has_bounds:
        if start_including is not None and compare_versions(firmware, start_including) < 0:
            return False
        if start_excluding is not None and compare_versions(firmware, start_excluding) <= 0:
            return False
        if end_including is not None and compare_versions(firmware, end_including) > 0:
            return False
        if end_excluding is not None and compare_versions(firmware, end_excluding) >= 0:
            return False
        return True

    cpe_version = criterion.get("criteria", "").split(":")[5]
    if cpe_version == "*":
        return True
    if cpe_version == "-" or _numeric_version(cpe_version) is None:
        return None
    return compare_versions(firmware, cpe_version) == 0


def _device_firmware_version(device) -> str | None:
    preferred = getattr(device, "firmware_version", None)
    value = (
        preferred
        if preferred is not None
        else getattr(device, "firmware", None)
    )
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return None if value.casefold() == "unknown" else value


def _numeric_version(value: str | None) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[vV]?\d+(?:\.\d+)*", value.strip()
    ):
        return None
    return value.strip().lstrip("vV")
