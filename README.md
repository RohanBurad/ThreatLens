# 🛡️ PhishGuard — Phishing URL Detection Tool

> Cybersecurity Internship Project | Built with Python + Flask

PhishGuard analyzes URLs in real time using 15+ heuristic signals — SSL validation, WHOIS domain age, keyword detection, brand impersonation checks, and more — then generates a PDF threat report.

---

## 🚀 Quick Setup

```bash
# 1. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## 📁 Project Structure

```
phishing-detector/
│
├── app.py                  ← Flask routes
├── requirements.txt        ← Python dependencies
├── reports/                ← Generated PDF reports (auto-created)
│
├── utils/
│   ├── analyzer.py         ← Core detection logic (15+ signals)
│   └── report.py           ← PDF report generator (ReportLab)
│
├── templates/
│   └── index.html          ← Main UI
│
└── static/
    ├── css/style.css        ← Dark themed UI
    └── js/main.js           ← Frontend logic
```

---

## 🔍 How Detection Works

PhishGuard checks 15+ signals grouped into categories:

### URL Structure
| Signal | Risk Weight |
|--------|-------------|
| IP address in URL | +25 |
| Brand impersonation | +30 |
| Suspicious TLD (.tk, .xyz, .ml...) | +20 |
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
| SSL invalid/expired | +10 |

### Content
| Signal | Risk Weight |
|--------|-------------|
| 3+ phishing keywords | +20 |
| 1-2 phishing keywords | +8 |
| Hyphen in domain | +5 |
| Digits in domain | +5 |

**Score Ranges:**
- 🚨 **70–100** → Likely Phishing
- ⚠️ **40–69**  → Suspicious
- ✅ **0–39**   → Likely Safe

---

## 🔑 Optional: VirusTotal API

To add VirusTotal cross-checking:

1. Get a free API key at https://www.virustotal.com/gui/my-apikey
2. Pass it to `analyze_url(url, vt_api_key="YOUR_KEY")` in `app.py`

---

## 📅 4-Day Internship Plan

| Day | Tasks |
|-----|-------|
| **Day 1** | Setup environment, understand `analyzer.py`, test URLs manually, add more keywords |
| **Day 2** | Test with 20 URLs (10 phishing, 10 legit), document false positives/negatives |
| **Day 3** | Integrate VirusTotal API (free tier), improve scoring weights based on testing |
| **Day 4** | Generate sample reports, prepare demo PPT, document findings |

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

## 🎓 Learning Outcomes

After completing this project, the intern will understand:
- URL anatomy and how phishing URLs are constructed
- Heuristic vs ML-based detection
- SSL certificate validation
- WHOIS domain registration data
- Risk scoring algorithms
- Flask web application structure
- PDF report generation with ReportLab

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. It does not guarantee 100% accuracy. Always exercise caution when clicking unknown URLs.

---

*PhishGuard · UBM CSRBOX Cybersecurity Internship 2025*
