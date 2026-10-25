from cti_enrichment import lookup_cve
import streamlit as st
from cti_engine import analyze_threat

st.set_page_config(
    page_title="CyberScope | Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberScope")
st.subheader("AI-Assisted Cyber Threat Intelligence Explorer")

st.write(
    "Extract potential threat indicators from security reports, "
    "incident notes, and suspicious text."
)

st.info(
    "This version uses rule-based extraction. "
    "Detected indicators are not proof that an IP, URL, or entity is malicious."
)

text_input = st.text_area(
    "Paste threat intelligence text",
    height=220,
    placeholder=(
        "Example: A report mentions CVE-2024-12345, "
        "the malware Emotet, and https://example.com"
    )
)

if st.button("🔍 Analyze Text", type="primary"):
    if not text_input.strip():
        st.warning("Please paste some text before analyzing.")
    else:
        try:
            results = analyze_threat(text_input)

            # Live NVD vulnerability enrichment
            with st.expander(
                " Live NVD Vulnerability Enrichment",
                expanded=True
            ):
                cve_ids = results.get("cves", [])

                if not cve_ids:
                    st.info("No CVE identifiers were extracted.")
                else:
                    for cve_id in cve_ids[:5]:
                        st.markdown(f"### {cve_id}")

                        details = lookup_cve(cve_id)

                        if details.get("error"):
                            st.warning(details["error"])
                        else:
                            st.write(details["description"])

                            col1, col2 = st.columns(2)

                            col1.metric(
                                "CVSS Score",
                                details["cvss_score"]
                                if details["cvss_score"] is not None
                                else "N/A"
                            )

                            col2.metric(
                                "Severity",
                                details["severity"] or "N/A"
                            )

                            st.markdown(
                                f"[View NVD record]({details['nvd_url']})"
                            )

            st.success("Analysis completed.")

            st.caption(
                f"Analysis type: {results['analysis_type']}"
            )

            st.subheader("Indicator Summary")

            categories = [
                ("IP addresses", "ips"),
                ("URLs", "urls"),
                ("Domains", "domains"),
                ("CVE IDs", "cves"),
                ("Malware mentions", "malware"),
                ("Threat actors", "threat_actors"),
                ("Technique indicators", "attack_techniques"),
            ]

            columns = st.columns(4)

            for index, (label, key) in enumerate(categories):
                with columns[index % 4]:
                    st.metric(label, len(results[key]))

            st.subheader("Extracted Findings")

            for label, key in categories:
                with st.expander(
                    f"{label} ({len(results[key])})",
                    expanded=bool(results[key])
                ):
                    if results[key]:
                        for item in results[key]:
                            st.write(f"• {item}")
                    else:
                        st.write("No indicators found.")

            st.warning(results["classification_caveat"])

            report_lines = [
                "CYBERSCOPE - THREAT INTELLIGENCE REPORT",
                "=" * 45,
                "",
                "Analysis type: " + results["analysis_type"],
                "",
            ]

            for label, key in categories:
                report_lines.append(
                    f"{label}: {len(results[key])} found"
                )
                if results[key]:
                    report_lines.extend(
                        f"  - {item}" for item in results[key]
                    )
                else:
                    report_lines.append("  - None found")
                report_lines.append("")

            report_lines.extend([
                "IMPORTANT LIMITATION:",
                results["classification_caveat"],
            ])

            report = "\n".join(report_lines)

            st.download_button(
                label="📥 Download Analysis Report",
                data=report,
                file_name="cyberscope_report.txt",
                mime="text/plain"
            )

        except ValueError as error:
            st.error(str(error))

st.divider()
st.caption(
    "CyberScope prototype | Research and educational use only"
)
