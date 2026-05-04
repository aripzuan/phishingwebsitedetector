import os
import pickle
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, render_template
from feature_extract import extract_features, FREE_DDNS, SKETCHY_TLDS

if not os.path.exists("phishing_model.pkl"):
    from huggingface_hub import hf_hub_download
    hf_hub_download(
        repo_id="arridz/phishing-detector",
        repo_type="space",
        filename="phishing_model.pkl",
        local_dir=".",
    )

app = Flask(__name__)

with open("phishing_model.pkl", "rb") as f:
    saved = pickle.load(f)

model     = saved["model"]
scaler    = saved["scaler"]
threshold = saved.get("threshold", 0.5)

# ── Known legitimate domains ──────────────────────────────────────
# The training dataset (phishing_site_urls.csv) has poor quality
# legitimate URL examples, causing the model to score well-known
# sites as phishing. This list provides a safety net for domains
# that are unambiguously legitimate.
KNOWN_LEGITIMATE = {
    "google.com", "youtube.com", "gmail.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "bbc.com", "bbc.co.uk",
    "amazon.com", "apple.com", "microsoft.com",
    "netflix.com", "spotify.com", "reddit.com",
    "python.org", "timberland.com", "workiva.com",
    "huggingface.co", "kaggle.com", "openai.com",
}


def is_known_legitimate(domain: str) -> bool:
    d = domain.lower().lstrip("www.")
    return any(d == ld or d.endswith("." + ld) for ld in KNOWN_LEGITIMATE)


def rule_based_check(url: str, domain: str):
    # 1. Known legitimate domains — bypass model
    if is_known_legitimate(domain):
        return "🟢 Looks legitimate (known domain)", "legit"

    # 2. Free DDNS — legitimate businesses never host here
    if any(ddns in domain for ddns in FREE_DDNS):
        return "🔴 High Risk — hosted on free DDNS service (strong phishing indicator)", "phishing"

    # 3. Sketchy TLD with no HTTPS
    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in SKETCHY_TLDS and not url.startswith("https"):
        return "🔴 High Risk — suspicious TLD with no HTTPS", "phishing"

    # 4. IP address as domain with no HTTPS
    try:
        ipaddress.ip_address(domain.split(":")[0])
        if not url.startswith("https"):
            return "🔴 High Risk — IP address used as domain", "phishing"
    except ValueError:
        pass

    return None


def classify(prob: float):
    if prob > threshold + 0.2:
        return f"🔴 High Risk — likely phishing ({prob*100:.1f}%)", "phishing"
    elif prob > threshold:
        return f"🟠 Suspicious — proceed with caution ({prob*100:.1f}%)", "suspicious"
    else:
        return f"🟢 Looks legitimate ({(1-prob)*100:.1f}% confidence)", "legit"


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "GET":
        return render_template("index.html")

    url = request.form["url"].strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    domain = urlparse(url).netloc.lower()

    rule_result = rule_based_check(url, domain)
    if rule_result:
        result, css_class = rule_result
        return render_template("index.html", prediction_text=result, css_class=css_class)

    feats    = extract_features(url)
    features = scaler.transform([feats])
    prob     = model.predict_proba(features)[0][1]
    result, css_class = classify(prob)

    return render_template("index.html", prediction_text=result, css_class=css_class)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)