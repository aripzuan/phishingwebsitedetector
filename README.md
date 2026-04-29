# Phishing Website Detector

A machine learning web app that detects phishing URLs in real time using a hybrid approach — rule-based checks combined with a trained XGBoost model.

**Live Demo:** https://arridz-phishing-detector.hf.space

---

## How It Works

Each submitted URL goes through two stages:

1. **Rule-based checks** — instant detection for high-confidence phishing patterns:
   - Hosted on a free DDNS service (e.g. `no-ip.com`, `servebbs.org`)
   - Suspicious TLD (`.tk`, `.xyz`, `.top`, etc.) with no HTTPS
   - Raw IP address used as domain with no HTTPS

2. **ML model** — if no rule fires, 22 URL features are extracted and passed to a trained XGBoost classifier. The model returns a phishing probability, which is bucketed into:
   - 🔴 High Risk (>90%)
   - 🟠 Suspicious (>75%)
   - 🟢 Legitimate

## Features Extracted

URL length, domain entropy, number of dots/hyphens, subdomain count, presence of HTTPS, use of IP address, phishing keywords, brand names, free DDNS match, suspicious TLD, URL shortener detection, and more.

## Tech Stack

| Layer | Technology |
|---|---|
| Web framework | Flask + Gunicorn |
| ML model | XGBoost + Random Forest (ensemble) |
| Preprocessing | scikit-learn StandardScaler |
| Container | Docker |
| Hosting | Hugging Face Spaces |

## Run Locally

```bash
git clone https://github.com/aripzuan/phishingwebsitedetector.git
cd phishingwebsitedetector
pip install -r requirements.txt
python app.py
```

The model (`phishing_model.pkl`) will be downloaded automatically on first run.

## Dataset

Trained on a combined dataset of phishing and legitimate URLs. Features were engineered manually based on known phishing indicators from literature and real-world patterns.
