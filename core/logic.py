from typing import Tuple, Optional

# CVSS installation check
try:
    from cvss import CVSS4

    CVSS_INSTALLED = True
except ImportError:
    CVSS_INSTALLED = False


def calculate_cvss_score(vector: str) -> Tuple[float, Optional[str]]:
    """Calculates the CVSS v4 score from the vector string."""
    if not CVSS_INSTALLED:
        return 0.0, "CVSS library not installed. Install with 'pip install cvss'."

    if not vector.strip():
        return 0.0, "Vector is empty."

    if not vector.startswith("CVSS:4.0/"):
        vector = "CVSS:4.0/" + vector.lstrip("/")

    try:
        cvss_obj = CVSS4(vector)
        score = cvss_obj.base_score
        return round(score, 1), None
    except Exception as e:
        return 0.0, f"Invalid CVSS vector syntax: {e}"


def map_cvss_to_severity(score: float) -> str:
    """
    Maps the CVSS score to a qualitative severity rating (CVSS v4 standards).
    """
    if score == 0.0:
        return "NONE"
    elif 0.1 <= score <= 3.9:
        return "LOW"
    elif 4.0 <= score <= 6.9:
        return "MEDIUM"
    elif 7.0 <= score <= 8.9:
        return "HIGH"
    elif 9.0 <= score <= 10.0:
        return "CRITICAL"
    else:
        return "UNKNOWN"
