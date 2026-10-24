
# 🛡️ CyberScope — Cyber Threat Intelligence Analysis

CyberScope is a beginner-friendly cybersecurity prototype that extracts potential Indicators of Compromise (IOCs) from security reports, suspicious messages, and threat-related text.

## 🎯 Project Objective

The goal of CyberScope is to make it easier to identify potentially useful security indicators in unstructured text so that they can be investigated further.

## ✨ Features

- **IP address extraction:** Identifies valid IPv4 addresses.
- **URL extraction:** Finds URLs and web addresses.
- **Domain extraction:** Identifies domain-like strings.
- **CVE extraction:** Finds Common Vulnerabilities and Exposures (CVE) identifiers.
- **Results summary:** Displays the number of indicators found in each category.
- **Report download:** Allows users to download the analysis results as a text file.
- **Interactive interface:** Built with Streamlit.

## 🧰 Technology Stack

- Python
- Streamlit
- Regular expressions
- Python `ipaddress` and `urllib.parse` standard-library modules

## 🚀 Run Locally

1. Clone this repository:

   ```bash
   git clone https://github.com/YOUR-USERNAME/cyberscope-threat-intelligence.git
   ```

2. Open the project folder:

   ```bash
   cd cyberscope-threat-intelligence
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   streamlit run app.py
   ```

5. Open the local URL displayed in your terminal.

Replace `YOUR-USERNAME` with your GitHub username.

## 🔍 How It Works

1. The user pastes a threat report, security alert, or suspicious text.
2. CyberScope scans the text using pattern matching and regular expressions.
3. Candidate IP addresses, URLs, domains, and CVE identifiers are extracted.
4. The results are displayed by category.
5. The user can download a text report for further investigation.

## ⚠️ Limitations

CyberScope is an experimental prototype. It extracts indicators but does not independently confirm whether they are malicious, check their reputation, validate vulnerability exploitability, or detect every cyberattack.

Always investigate extracted indicators using trusted security tools and sources before taking action.

## 🗺️ Future Improvements

- Integrate trusted threat-intelligence feeds.
- Add reputation checks for extracted indicators.
- Incorporate machine-learning-based text classification.
- Add interactive threat relationship graphs.
- Improve evaluation using labelled cybersecurity datasets.
- Add testing, logging, and error handling.

These are proposed future enhancements, not features currently implemented.

## 🔐 Responsible Use

Use CyberScope for educational purposes and authorized defensive security research. Avoid submitting confidential logs, credentials, personal data, or sensitive organizational information to an online deployment.

## 📌 Project Status

**Status:** Initial prototype

CyberScope is under development, with future improvements planned for threat-intelligence enrichment and analysis.
