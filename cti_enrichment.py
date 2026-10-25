
"""Live CVE enrichment using the official NIST NVD API."""

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(cve_id):
    """Return basic NVD details for a CVE, or a readable error."""
    cve_id = str(cve_id).strip().upper()

    if not cve_id.startswith("CVE-"):
        return {"cve": cve_id, "error": "Invalid CVE identifier."}

    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            timeout=12,
        )

        if response.status_code == 404:
            return {"cve": cve_id, "error": "CVE not found."}

        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return {
                "cve": cve_id,
                "error": "No matching record returned by NVD.",
            }

        item = vulnerabilities[0].get("cve", {})
        descriptions = item.get("descriptions", [])
        description = next(
            (
                entry.get("value", "")
                for entry in descriptions
                if entry.get("lang") == "en"
            ),
            "No English description available.",
        )

        metrics = item.get("metrics", {})
        score = None
        severity = None

        for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = (
                    cvss.get("baseSeverity")
                    or entries[0].get("baseSeverity")
                )
                break

        return {
            "cve": item.get("id", cve_id),
            "description": description,
            "cvss_score": score,
            "severity": severity,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    except requests.RequestException as exc:
        return {
            "cve": cve_id,
            "error": f"NVD request failed: {type(exc).__name__}",
        }
    except (ValueError, KeyError, IndexError, TypeError):
        return {
            "cve": cve_id,
            "error": "NVD returned an unexpected response.",
        }
