
import streamlit as st
from pathlib import Path

from cti_engine import analyze_threat
from cti_enrichment import lookup_cve

# Make the app usable even if joblib is temporarily unavailable.
try:
    import joblib
except ImportError:
    joblib = None


MODEL_PATH = (
    Path(__file__).parent / "threatlens_cti_relevance_model.joblib"
)


st.set_page_config(
    page_title="CyberScope | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def load_cti_model():
    if joblib is None or not MODEL_PATH.exists():
        return None

    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


st.title("🛡️ CyberScope")
st.subheader("AI-Assisted Cyber Threat Intelligence Explorer")

st.write(
    "Extract potential threat indicators from security reports, "
    "incident notes, and suspicious text."
)

st.info(
    "CyberScope combines indicator extraction, live CVE enrichment, "
    "and an optional machine-learning CTI relevance model. "
    "Detected indicators are not proof that something is malicious."
)

text_input = st.text_area(
    "Paste threat intelligence text",
    height=220,
    placeholder=(
        "Example: A report mentions CVE-2024-12345, "
        "the malware Emotet, and https://example.com"
    ),
)

if st.button("🔍 Analyze Text", type="primary"):

    if not text_input.strip():
        st.warning("Please paste some text before analyzing.")

    else:
        try:
            results = analyze_threat(text_input)

            # Live NVD vulnerability enrichment
            with st.expander(
                "Live NVD Vulnerability Enrichment",
                expanded=True,
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
                            continue

                        st.write(
                            details.get("description")
                            or "No description available."
                        )

                        col1, col2 = st.columns(2)

                        score = details.get("cvss_score")
                        severity = details.get("severity")

                        col1.metric(
                            "CVSS Score",
                            score if score is not None else "N/A",
                        )

                        col2.metric(
                            "Severity",
                            severity or "N/A",
                        )

                        nvd_url = details.get("nvd_url")
                        if nvd_url:
                            st.markdown(
                                f"[View NVD record]({nvd_url})"
                            )

            st.success("Analysis completed.")

            st.caption(
                f"Analysis type: {results['analysis_type']}"
            )

            # Indicator summary
            categories = [
                ("IP addresses", "ips"),
                ("URLs", "urls"),
                ("Domains", "domains"),
                ("CVE IDs", "cves"),
                ("Malware mentions", "malware"),
                ("Threat actors", "threat_actors"),
                ("Technique indicators", "attack_techniques"),
            ]

            st.subheader("Indicator Summary")

            columns = st.columns(4)

            for index, (label, key) in enumerate(categories):
                with columns[index % 4]:
                    st.metric(
                        label,
                        len(results.get(key, [])),
                    )

            st.subheader("Extracted Findings")

            for label, key in categories:
                items = results.get(key, [])

                with st.expander(
                    f"{label} ({len(items)})",
                    expanded=bool(items),
                ):
                    if items:
                        for item in items:
                            st.write(f"• {item}")
                    else:
                        st.write("No indicators found.")

            st.warning(
                results.get(
                    "classification_caveat",
                    "Extracted indicators require further investigation.",
                )
            )

            # ML-based CTI relevance analysis
            st.subheader("🧠 ML-Based CTI Relevance")

            cti_model = load_cti_model()

            if cti_model is None:
                st.warning(
                    "The ML model is currently unavailable. "
                    "Check that joblib and scikit-learn are installed "
                    "and the model file is present in the repository root."
                )

            else:
                try:
                    prediction = cti_model.predict([text_input])[0]
                    prediction_text = str(prediction).strip().lower()

                    if prediction_text in ("yes", "1", "true"):
                        st.success(
                            "The model classifies this text as "
                            "relevant to cyber threat intelligence."
                        )
                    elif prediction_text in ("no", "0", "false"):
                        st.info(
                            "The model classifies this text as "
                            "not relevant to cyber threat intelligence."
                        )
                    else:
                        st.write(
                            f"Model prediction: {prediction}"
                        )

                    st.caption(
                        "This model predicts CTI relevance, not whether "
                        "the text or its indicators are malicious."
                    )

                except Exception as model_error:
                    st.warning(
                        "The ML model could not analyze this input. "
                        f"Details: {model_error}"
                    )

            # Downloadable report
            report_lines = [
                "CYBERSCOPE - THREAT INTELLIGENCE REPORT",
                "=" * 45,
                "",
                f"Analysis type: {results['analysis_type']}",
                "",
            ]

            for label, key in categories:
                items = results.get(key, [])

                report_lines.append(
                    f"{label}: {len(items)} found"
                )

                if items:
                    report_lines.extend(
                        f"  - {item}" for item in items
                    )
                else:
                    report_lines.append("  - None found")

                report_lines.append("")

            report_lines.extend([
                "IMPORTANT LIMITATION:",
                results.get(
                    "classification_caveat",
                    "Indicators are not proof of malicious activity.",
                ),
            ])

            report = "\n".join(report_lines)

            st.download_button(
                label="📥 Download Analysis Report",
                data=report,
                file_name="cyberscope_report.txt",
                mime="text/plain",
            )

        except ValueError as error:
            st.error(str(error))

        except Exception as error:
            st.error(
                "An unexpected error occurred during analysis. "
                f"Details: {error}"
            )


st.divider()
st.caption(
    "CyberScope prototype | Research and educational use only"
)
