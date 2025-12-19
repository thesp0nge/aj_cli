import os
from jinja2 import Environment, FileSystemLoader
from typing import Dict, List
from datetime import datetime

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
REPORT_TEMPLATE = "audit_report.md.j2"
BUGZILLA_BASE_URL = "https://bugzilla.suse.com/show_bug.cgi?id="


def extract_bugzilla_number(bugzilla_id_string: str) -> str:
    """
    Extracts the numerical part of the Bugzilla ID string
    (e.g., 'bsc#123456' -> '123456').
    """
    if bugzilla_id_string and "#" in bugzilla_id_string:
        return bugzilla_id_string.split("#")[-1]
    return bugzilla_id_string


def generate_markdown_report(
    audit_details: Dict, findings: List[Dict], avg_score: float, triage_level: str
) -> str:
    """Generates the Markdown report using Jinja2."""

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(REPORT_TEMPLATE)

    audit_bz_id_string = audit_details.get("bugzilla_id", "N/A")
    audit_bz_number = extract_bugzilla_number(audit_bz_id_string)

    processed_findings = []
    for f in findings:
        f_copy = f.copy()
        f_bz_id_string = f.get("finding_bugzilla_id", "N/A")
        f_copy["finding_bugzilla_number"] = extract_bugzilla_number(f_bz_id_string)
        cwe_id = f.get("cwe_id")
        if cwe_id:
            kb_entry = get_kb_entry(cwe_id)
            if kb_entry:
                f_copy["cwe_id_display"] = f"CWE-{cwe_id}"
                f_copy["description_template"] = kb_entry.get(
                    "description_template", "N/A: KB template missing."
                )
                f_copy["impact_template"] = kb_entry.get(
                    "impact_template", "N/A: KB template missing."
                )
                f_copy["recommendation_template"] = kb_entry.get(
                    "recommendation_template", "N/A: KB template missing."
                )
            else:
                f_copy["cwe_id_display"] = f"CWE-{cwe_id} (Template mancante)"
                f_copy["description_template"] = (
                    "No standard template found. See notes for details."
                )
                f_copy["impact_template"] = "N/A"
                f_copy["recommendation_template"] = "N/A"
        else:
            # Gestione dei Custom/Nessun CWE ID
            f_copy["cwe_id_display"] = "Custom/N/A"
            f_copy["description_template"] = (
                "Custom finding: See notes below for detailed description."
            )
            f_copy["impact_template"] = "Custom finding: Review notes for impact."
            f_copy["recommendation_template"] = (
                "Custom finding: Review notes for recommendations."
            )

        processed_findings.append(f_copy)

    context = {
        "project_name": audit_details.get("project_name", "N/A"),
        "bugzilla_id_display": audit_bz_id_string,
        "bugzilla_id_number": audit_bz_number,
        "bugzilla_base_url": BUGZILLA_BASE_URL,
        "start_date": audit_details.get("start_date", "N/A"),
        "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "finding_count": len(processed_findings),
        "findings": processed_findings,
        "avg_score_display": f"{avg_score:.1f}" if avg_score > 0 else "N/A",
        "triage_level": triage_level,
    }

    return template.render(context)
