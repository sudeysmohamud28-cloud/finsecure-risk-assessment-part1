import os
import stat
import subprocess
import shutil
from typing import Dict, List, Optional


def check_file_permissions(path: str = "/secure_data") -> Dict:
    """
    Check whether a sensitive directory is restricted to owner-only permissions.

    Required return format:
    {
        "control": "file_permissions",
        "compliant": True/False,
        "evidence": "...",
        "risk_note": "..."
    }
    """
    try:
        st = os.stat(path)
        mode = st.st_mode
        perms_oct = oct(stat.S_IMODE(mode))

        # Hubi inaanay jirin group (S_IRWXG) ama other (S_IRWXO) permissions
        group_or_other_perms = mode & (stat.S_IRWXG | stat.S_IRWXO)

        if group_or_other_perms == 0:
            return {
                "control": "file_permissions",
                "compliant": True,
                "evidence": f"Directory '{path}' has owner-only permissions ({perms_oct}).",
                "risk_note": "No group or other permissions detected; access is restricted to owner.",
            }
        else:
            return {
                "control": "file_permissions",
                "compliant": False,
                "evidence": f"Directory '{path}' has permissions {perms_oct} (group or other bits set).",
                "risk_note": "Group or other permissions present on sensitive directory; potential unauthorized access.",
            }
    except FileNotFoundError:
        return {
            "control": "file_permissions",
            "compliant": False,
            "evidence": f"Directory '{path}' does not exist (FileNotFoundError).",
            "risk_note": "Target sensitive directory is missing; verify path and audit scope.",
        }
    except Exception as e:
        return {
            "control": "file_permissions",
            "compliant": False,
            "evidence": f"Error inspecting '{path}': {e}",
            "risk_note": "Unable to verify file system permissions due to an error.",
        }


def check_active_sessions(threshold: int = 5) -> Dict:
    """
    Check active user sessions using `who` and flag non-compliant if sessions > threshold.

    Required return format:
    {
        "control": "active_sessions",
        "compliant": True/False,
        "evidence": "...",
        "risk_note": "..."
    }
    """
    try:
        result = subprocess.run(
            ["who"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        session_count = len(lines)
        compliant = session_count <= threshold

        if compliant:
            return {
                "control": "active_sessions",
                "compliant": True,
                "evidence": f"Active sessions count: {session_count} (threshold: {threshold}).",
                "risk_note": "Active sessions are within acceptable threshold.",
            }
        else:
            return {
                "control": "active_sessions",
                "compliant": False,
                "evidence": f"Active sessions count: {session_count} exceeds threshold {threshold}.",
                "risk_note": "Elevated number of active sessions; investigate for unauthorized access.",
            }
    except Exception as e:
        return {
            "control": "active_sessions",
            "compliant": False,
            "evidence": f"Failed to run `who`: {e}",
            "risk_note": "Unable to verify active sessions; audit visibility gap.",
        }


def check_disk_space(path: str = "/", threshold: int = 80) -> Dict:
    """
    Check disk usage and flag non-compliant if usage percentage > threshold.

    Required return format:
    {
        "control": "disk_space",
        "compliant": True/False,
        "evidence": "...",
        "risk_note": "..."
    }
    """
    try:
        total, used, free = shutil.disk_usage(path)
        if total <= 0:
            return {
                "control": "disk_space",
                "compliant": False,
                "evidence": f"Invalid disk total size for '{path}': {total}.",
                "risk_note": "Unable to compute disk utilization percentage.",
            }

        usage_pct = (used / total) * 100
        compliant = usage_pct <= threshold

        if compliant:
            return {
                "control": "disk_space",
                "compliant": True,
                "evidence": f"Disk usage on '{path}': {usage_pct:.2f}% (threshold: {threshold}%).",
                "risk_note": "Disk utilization is within safe limits.",
            }
        else:
            return {
                "control": "disk_space",
                "compliant": False,
                "evidence": f"Disk usage on '{path}': {usage_pct:.2f}% exceeds threshold {threshold}%.",
                "risk_note": "High disk usage; risk of service disruption or log loss.",
            }
    except Exception as e:
        return {
            "control": "disk_space",
            "compliant": False,
            "evidence": f"Error checking disk space for '{path}': {e}",
            "risk_note": "Unable to check disk space utilization.",
        }


def _score_to_severity(score: int) -> str:
    if score <= 0:
        return "NONE"
    elif 1 <= score <= 5:
        return "LOW"
    elif 6 <= score <= 12:
        return "MEDIUM"
    else:
        return "HIGH"


def assess_risk(
    findings: List[Dict],
    impact_map: Optional[Dict[str, int]] = None,
    likelihood_map: Optional[Dict[str, int]] = None,
) -> List[Dict]:
    """
    Add risk scoring to each finding using score = impact * likelihood.

    Rules:
    - If compliant is True: score = 0 and severity = "NONE"
    - If compliant is False: score = impact * likelihood
    - If a control is not found in the impact/likelihood maps, use a reasonable default (example: 3)
    - Add keys "score" and "severity" to each finding.

    Required severity mapping:
    score == 0   -> NONE
    score 1-5    -> LOW
    score 6-12   -> MEDIUM
    score 13-25  -> HIGH
    """
    default_impact = {
        "file_permissions": 4,
        "active_sessions": 3,
        "disk_space": 4,
    }
    default_likelihood = {
        "file_permissions": 4,
        "active_sessions": 3,
        "disk_space": 3,
    }

    impacts = impact_map if impact_map is not None else default_impact
    likelihoods = likelihood_map if likelihood_map is not None else default_likelihood

    assessed: List[Dict] = []
    for finding in findings:
        updated = dict(finding)
        control = updated.get("control", "")
        is_compliant = bool(updated.get("compliant", False))

        if is_compliant:
            score = 0
            severity = "NONE"
        else:
            impact = impacts.get(control, 3)
            likelihood = likelihoods.get(control, 3)
            score = impact * likelihood
            severity = _score_to_severity(score)

        updated["score"] = score
        updated["severity"] = severity
        assessed.append(updated)

    return assessed


def prioritize(findings: List[Dict]) -> List[Dict]:
    """
    Return findings sorted from highest risk to lowest risk by score (descending).
    """
    return sorted(findings, key=lambda item: item.get("score", 0), reverse=True)


def main() -> None:
    """
    Run the full audit pipeline:
    1) Run all three compliance checks
    2) Score findings (impact x likelihood)
    3) Prioritize findings highest -> lowest
    4) Print a short prioritized summary
    """
    print("Starting System Audit Compliance Checker...\n")

    findings = [
        check_file_permissions("/secure_data"),
        check_active_sessions(threshold=5),
        check_disk_space(path="/", threshold=80),
    ]

    scored = assess_risk(findings)
    prioritized = prioritize(scored)

    print("Prioritized Risk Summary:")
    for item in prioritized:
        print(
            f"- control={item.get('control')} | severity={item.get('severity')} | "
            f"score={item.get('score')} | compliant={item.get('compliant')}"
        )

    print("\nCompliance check completed.")


if __name__ == "__main__":
    main()