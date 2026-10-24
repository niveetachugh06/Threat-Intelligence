
import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st


# -----------------------------
# CyberScope: IOC Extraction
# -----------------------------

st.set_page_config(
    page_title="CyberScope | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }
    .main-title {
        font-size: 2.6rem;
        font-weight: 800;
        color: #60a5fa;
        margin-bottom: 0;
    }
    .subtitle {
        color: #9ca3af;
        font-size: 1.05rem;
        margin-top: 5px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<p class="main-title">🛡️ CyberScope</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="subtitle">Cyber Threat Intelligence Analysis Prototype</p>',
    unsafe_allow_html=True,
)

st.divider()

st.write(
    "Paste a security alert, threat report, or suspicious message below. "
    "CyberScope will extract potential indicators that you can investigate."
)

# -----------------------------
# Indicator extraction engine
# -----------------------------

def analyze_text(text):
    """Extract candidate IOCs from text. Extraction does not prove maliciousness."""

    # Extract CVE identifiers
    cves = sorted(
        set(
            match.upper()
            for match in re.findall(
                r"\bCVE-\d{4}-\d{4,}\b",
                text,
                flags=re.IGNORECASE,
            )
        )
    )

    # Extract URLs
    url_pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    raw_urls = re.findall(url_pattern, text)

    urls = set()
    for url in raw_urls:
        # Remove common punctuation attached to a URL in prose
        url = url.rstrip(".,;:!?)]}")
        if url:
            urls.add(url)

    urls = sorted(urls)

    # Extract and validate IPv4 addresses
    ip_candidates = re.findall(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
        text,
    )

    ips = set()
    for candidate in ip_candidates:
        try:
            parsed_ip = ipaddress.ip_address(candidate)
            if parsed_ip.version == 4:
                ips.add(str(parsed_ip))
        except ValueError:
            pass

    ips = sorted(ips)

    # Extract domains from URLs and standalone domain-like strings
    domains = set()

    for url in urls:
        normalized_url = url if "://" in url else "http://" + url
        try:
            hostname = urlparse(normalized_url).hostname
            if hostname and "." in hostname:
                domains.add(hostname.lower())
        except ValueError:
            pass

    domain_pattern = (
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}\b"
    )

    for match in re.findall(domain_pattern, text):
        domains.add(match.lower())

    # Avoid treating an IP address as a domain
    domains = {
        domain for domain in domains
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain)
    }

    # URLs already contain their hostnames, so keep domains as a separate list
    domains = sorted(domains)

    return {
        "IP addresses": ips,
        "URLs": urls,
        "Domains": domains,
        "CVE IDs": cves,
    }


# -----------------------------
# User input
# -----------------------------

example_text = """Example security alert:
A suspicious connection was reported to http://malicious-example.com/login
The source IP was 185.199.108.153.
The report also mentions CVE-2024-12345.
Please investigate these indicators before taking action."""

with st.expander("Load sample text"):
    st.code(example_text, language="text")

text_input = st.text_area(
    "Threat report or suspicious text",
    height=220,
    placeholder=(
        "Paste a threat report, security log, email, or alert here..."
    ),
)

analyze_button = st.button(
    "🔍 Analyze Text",
    type="primary",
    use_container_width=True,
)

if analyze_button:
    if not text_input.strip():
        st.warning("Please paste some text before running the analysis.")
    else:
        results = analyze_text(text_input)

        st.subheader("Analysis Results")
        st.caption(
            "These are extracted candidates, not confirmed malicious indicators."
        )

        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("IP Addresses", len(results["IP addresses"]))
        col2.metric("URLs", len(results["URLs"]))
        col3.metric("Domains", len(results["Domains"]))
        col4.metric("CVE IDs", len(results["CVE IDs"]))

        st.divider()

        # Detailed results
        for category, indicators in results.items():
            with st.expander(
                f"{category} ({len(indicators)})",
                expanded=True,
            ):
                if indicators:
                    for indicator in indicators:
                        st.code(indicator, language=None)
                else:
                    st.write("No indicators found in this category.")

        # Download a text report directly from the website
        report_lines = [
            "CyberScope - Indicator Extraction Report",
            "=" * 42,
            "",
            "Important: Extracted indicators are not confirmed malicious.",
            "",
        ]

        for category, indicators in results.items():
            report_lines.append(f"{category}:")
            if indicators:
                report_lines.extend(f"- {item}" for item in indicators)
            else:
                report_lines.append("- None found")
            report_lines.append("")

        report = "\n".join(report_lines)

        st.download_button(
            label="⬇️ Download Analysis Report",
            data=report,
            file_name="cyberscope_analysis.txt",
            mime="text/plain",
            use_container_width=True,
        )

st.divider()

st.caption(
    "CyberScope is an experimental prototype. "
    "It does not verify reputation, exploitability, or whether an indicator "
    "is actively malicious. Validate findings using trusted security sources."
)
