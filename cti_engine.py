
import re
import ipaddress
from urllib.parse import urlparse


# Curated names from the original notebook.
MALWARE_NAMES = [
    "emotet", "trickbot", "wannacry", "wanna cry",
    "ryuk", "lockbit", "mirai", "agent tesla",
    "njrat", "remcos", "darkcomet",
]

THREAT_ACTORS = [
    "apt28", "apt29", "lazarus", "fin7",
    "fin8", "carbanak", "turla", "sandworm",
]

ATTACK_TECHNIQUES = {
    "phishing": [
        "phishing", "spearphishing", "credential harvesting",
        "fake login", "malicious email",
    ],
    "command_execution": [
        "command execution", "remote code execution",
        "execute command", "shell command",
    ],
    "credential_access": [
        "credential theft", "steal credentials",
        "password theft", "credential harvesting",
    ],
    "malware_delivery": [
        "malware", "payload", "trojan", "malicious attachment",
    ],
    "exploitation": [
        "exploit", "exploited", "exploitation",
        "vulnerability", "CVE-",
    ],
}


def extract_cves(text):
    if not isinstance(text, str):
        return []

    matches = re.findall(
        r"\bCVE-\d{4}-\d{4,}\b",
        text,
        flags=re.IGNORECASE,
    )
    return sorted({value.upper() for value in matches})


def extract_valid_ips(text):
    if not isinstance(text, str):
        return []

    candidates = re.findall(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)",
        text,
    )

    valid = set()
    for candidate in candidates:
        try:
            parsed = ipaddress.ip_address(candidate)
            if parsed.version == 4:
                valid.add(str(parsed))
        except ValueError:
            continue

    return sorted(valid)


def normalize_url(url):
    if not isinstance(url, str):
        return None

    value = url.strip()

    markdown_match = re.fullmatch(
        r"\[([^\]]*)\]\((https?://[^)\s]+)\)",
        value,
        flags=re.IGNORECASE,
    )
    if markdown_match:
        value = markdown_match.group(2)

    value = value.rstrip(".,!?;:'\")]}")
    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        return None

    try:
        parsed = urlparse(value)
        if not parsed.hostname:
            return None
        _ = parsed.port
    except ValueError:
        return None

    return value


def extract_urls(text):
    if not isinstance(text, str):
        return []

    markdown_pattern = r"\[[^\]]+\]\((https?://[^)\s]+)\)"
    prepared = re.sub(
        markdown_pattern, r"\1", text, flags=re.IGNORECASE
    )

    candidates = re.findall(
        r"https?://[^\s<>\]\)]+",
        prepared,
        flags=re.IGNORECASE,
    )

    normalized = [normalize_url(url) for url in candidates]
    return sorted({url for url in normalized if url})


def extract_domains(text):
    domains = set()

    for url in extract_urls(text):
        try:
            hostname = urlparse(url).hostname
            if hostname:
                domains.add(hostname.lower())
        except ValueError:
            continue

    return sorted(domains)


def extract_named_threats(text):
    if not isinstance(text, str):
        return {"malware": [], "threat_actors": []}

    def mentioned(name):
        pattern = r"(?<!\w)" + re.escape(name) + r"(?!\w)"
        return re.search(
            pattern, text, flags=re.IGNORECASE
        ) is not None

    malware = sorted({
        name for name in MALWARE_NAMES if mentioned(name)
    })
    actors = sorted({
        name for name in THREAT_ACTORS if mentioned(name)
    })

    return {
        "malware": malware,
        "threat_actors": actors,
    }


def extract_attack_techniques(text):
    if not isinstance(text, str):
        return []

    text_lower = text.lower()
    detected = []

    for category, indicators in ATTACK_TECHNIQUES.items():
        if any(term.lower() in text_lower for term in indicators):
            detected.append(category)

    return detected


def extract_all_threat_intelligence(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text.")

    named = extract_named_threats(text)

    return {
        "cves": extract_cves(text),
        "ips": extract_valid_ips(text),
        "urls": extract_urls(text),
        "domains": extract_domains(text),
        "malware": named["malware"],
        "threat_actors": named["threat_actors"],
        "attack_techniques": extract_attack_techniques(text),
    }


def analyze_threat(text):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Please provide non-empty text.")

    return {
        "analysis_type": "CTI indicator extraction",
        "classification": "not_run",
        "classification_caveat": (
            "This extraction module uses rules and curated name lists. "
            "Extracted indicators and names are not proof of maliciousness "
            "or attribution."
        ),
        **extract_all_threat_intelligence(text),
    }
