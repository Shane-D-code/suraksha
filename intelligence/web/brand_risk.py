def brand_risk_score(match: dict) -> float:
    """
    Returns normalized brand risk score in range [0, 1]
    """
    if not match:
        return 0.0

    match_type = match.get("type")
    confidence = float(match.get("confidence", 0.0))

    if match_type == "exact":
        return 1.0

    if match_type == "punycode":
        return 0.9

    if match_type == "fuzzy":
        return min(confidence, 1.0)

    return 0.0