# 🛡️ ThreatLens — Phishing URL Detector

> Real-time phishing URL detection using heuristic analysis, SSL validation & WHOIS lookup  
> Built with Python + Flask · IBM CSRBOX Cybersecurity Internship 2025

[![Live Demo](https://img.shields.io/badge/Live%20Demo-threatlens--i74k.onrender.com-red?style=for-the-badge&logo=render)](https://threatlens-i74k.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)

---

## 🌐 Live Demo

**👉 [https://threat-lens-swart.vercel.app/](https://threat-lens-swart.vercel.app/)**

---

## 📸 Preview

| Home | Scan Result |
|------|-------------|
| Paste any URL and hit Scan | Get a risk score with full breakdown |

---

## ✨ Features

- 🔍 **15+ Heuristic Signals** — URL length, subdomain depth, IP detection, hex encoding, brand impersonation, suspicious TLDs, and more
- 🔒 **SSL Certificate Check** — Validates certificate issuer, validity, and expiration in real time
- 📅 **Domain Age via WHOIS** — Flags newly registered domains (under 30 days) as high risk
- 🎯 **Brand Impersonation Detection** — Detects spoofed PayPal, Amazon, Google, Apple domains
- 📊 **Risk Score 0–100** — Weighted scoring with a clear Safe / Suspicious / Phishing verdict
- 📄 **PDF Report Export** — Download a full professional threat analysis report
- 🌙 **Dark / Light Mode** — Theme toggle with localStorage persistence
- 📱 **Fully Responsive** — Mobile-friendly with hamburger navigation

---

## 🔍 How Detection Works

Signals are grouped into categories, each with a weighted risk score:

### URL Structure
| Signal | Risk Weight |
|--------|-------------|
| IP address in URL | +25 |
| Brand impersonation | +30 |
| Suspicious TLD (.tk, .xyz, .ml…) | +20 |
| Excessive subdomain depth | +15 |
| URL length > 100 chars | +10 |
| Hex encoding in URL | +10 |
| @ symbol in URL | +15 |
| URL shortener detected | +15 |

### Security
| Signal | Risk Weight |
|--------|-------------|
| No HTTPS | +20 |
| Domain age < 30 days | +25 |
| Domain age < 180 days | +10 |
| SSL invalid / expired | +10 |

### Content
| Signal | Risk Weight |
|--------|-------------|
| 3+ phishing keywords | +20 |
| 1–2 phishing keywords | +8 |
| Hyphen in domain | +5 |
| Digits in domain | +5 |

**Score Ranges:**
- 🚨 **70–100** → Likely Phishing
- ⚠️ **40–69** → Suspicious
- ✅ **0–39** → Likely Safe

---

## 📁 Project Structure

```
ThreatLens-v2/
│
├── app.py                  ← Flask routes & API endpoints
├── requirements.txt        ← Python dependencies
├── Procfile                ← Render deployment config
├── reports/                ← Generated PDF reports (auto-created)
│
├── utils/
│   ├── analyzer.py         ← Core detection logic (15+ signals)
│   └── report.py           ← PDF report generator (ReportLab)
│
├── templates/
│   ├── index.html          ← Home / Scanner page
│   ├── demo.html           ← Demo page
│   ├── how_it_works.html   ← How It Works page
│   ├── about.html          ← About page
│   └── contact.html        ← Contact page
│
└── static/
    ├── css/style.css       ← Full UI styles + responsive
    └── js/main.js          ← Frontend logic & API calls
```

---

## 🚀 Local Setup

```bash
# 1. Clone the repo
git clone https://github.com/RohanBurad/ThreatLens.git
cd ThreatLens

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## 📊 Sample Test URLs

**Phishing samples (should score HIGH):**
- `http://paypa1-secure-login.tk/verify/account`
- `http://192.168.1.1/login`
- `http://amaz0n-account-verify.xyz/signin`

**Legitimate (should score LOW):**
- `https://github.com`
- `https://wikipedia.org`
- `https://python.org`

---

## 🛠️ Built With

- **Python 3** + **Flask** — Backend & routing
- **TLDExtract** — Domain parsing
- **Python-WHOIS** — Domain registration lookup
- **ReportLab** — PDF report generation
- **Vanilla JS** — Frontend interactions

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. It does not guarantee 100% detection accuracy. Always exercise caution when clicking unknown URLs.

---

*ThreatLens · Built by Rohan Burad · IBM CSRBOX Cybersecurity Internship 2025*
