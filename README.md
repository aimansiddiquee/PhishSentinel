# 🛡️ Phishing URL & Domain Analyzer

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.0+-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

A powerful, modern web-based threat intelligence application designed to analyze suspicious links, domains, and URLs for phishing indicators, typo-squatting tactics, domain age anomalies, SSL certificate issues, and real-time threat intelligence data.

---

## 🚀 Key Features

- 🔍 **Heuristic & Pattern Detection**: Detects typo-squatting, URL shortener abuses, homograph attacks, raw IP hosts, high Shannon entropy, and suspicious keywords (e.g., `paypa1-login.com`).
- 🌐 **Domain & WHOIS Insights**: Evaluates domain age, registration duration, creation/expiration dates, and registrar details to spot freshly registered malicious domains.
- 🔒 **SSL Certificate Inspection**: Verifies certificate presence, issuer authority, expiration timeline, and domain matching.
- 📡 **Threat Intelligence API Integration**: Aggregates reputation scores and flag counts from external providers such as **VirusTotal** and **IPQualityScore**.
- 📊 **Dynamic Risk Scoring**: Calculates an automated Risk Score (0–100) categorized into **Safe**, **Low Risk**, **Medium Risk**, or **Critical Risk**.
- 📋 **Export & Scan History**: Automatically saves recent scans locally and allows exporting raw JSON threat reports for further incident response analysis.

---

## 🏗️ Tech Stack

- **Backend Framework**: Python ([FastAPI](https://fastapi.tiangolo.com/) or [Flask](https://flask.palletsprojects.com/))
- **Frontend Framework**: HTML5, JavaScript (ES6+), [Tailwind CSS](https://tailwindcss.com/), [Lucide Icons](https://lucide.dev/)
- **Data Visualizations**: [Chart.js](https://www.chartjs.org/)
- **Threat Intelligence Integrations**:
  - [VirusTotal v3 API](https://developers.virustotal.com/)
  - [IPQualityScore Malicious URL Scanner API](https://www.ipqualityscore.com/)
  - Python `python-whois` & `ssl` libraries

---

## 📂 Project Structure

```text
phishing-analyzer/
│
├── app/
│   ├── main.py              # Application entrypoint (FastAPI / Flask)
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── domain_whois.py  # WHOIS and domain creation age verification
│   │   ├── ssl_checker.py   # SSL certificate validity & issuer parser
│   │   ├── heuristics.py    # Entropy calculation & typo-squatting detection
│   │   └── threat_intel.py  # External API clients (VirusTotal, IPQS)
│   └── templates/
│       └── index.html       # Single-page dynamic frontend dashboard
│
├── .env.example             # Template for API credentials
├── requirements.txt         # Python dependency list
├── README.md                # Repository documentation
└── LICENSE                  # Open source license
