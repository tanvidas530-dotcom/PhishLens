from flask import Flask, jsonify, render_template, request
from urllib.parse import urlsplit
import ipaddress
import re

app = Flask(__name__)

SUSPICIOUS_WORDS = {
    "login", "verify", "account", "secure",
    "update", "password", "wallet", "confirm"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "cutt.ly", "is.gd", "rb.gy"
}


def analyze_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url or len(raw_url) > 2048:
        return {"error": "Enter a URL up to 2048 characters."}

    # Reject unsupported schemes before normalizing the URL.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_url):
        if not re.match(r"^https?://", raw_url, re.I):
            return {"error": "Only HTTP and HTTPS URLs are supported."}
        candidate = raw_url
    else:
        candidate = "https://" + raw_url

    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname

        if (
            parsed.scheme.lower() not in ("http", "https")
            or not host
            or any(c.isspace() for c in host)
            or any(ord(c) < 32 for c in candidate)
        ):
            raise ValueError("Invalid URL")

        # Accessing port also checks whether its syntax is valid.
        _ = parsed.port

        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            is_ip = False

    except ValueError:
        return {"error": "Invalid URL. Check its format."}

    hostname = host.lower().rstrip(".")
    full_url = candidate.lower()
    labels = hostname.split(".")

    indicators = []
    score = 0

    def flag(name, points, explanation):
        nonlocal score
        score += points
        indicators.append({
            "name": name,
            "points": points,
            "explanation": explanation
        })

    if parsed.scheme.lower() == "http":
        flag(
            "No HTTPS", 10,
            "HTTP does not provide HTTPS transport encryption."
        )

    if is_ip:
        flag(
            "IP address host", 25,
            "The hostname is an IP address instead of a conventional domain."
        )

    if "@" in parsed.netloc:
        flag(
            "Misleading @ symbol", 25,
            "Text before @ can disguise the actual destination hostname."
        )

    if "xn--" in hostname:
        flag(
            "Punycode domain", 20,
            "Inspect this internationalized domain for lookalike characters."
        )

    if len(hostname) > 40:
        flag(
            "Long hostname", 10,
            "The hostname is unusually long and may be harder to inspect."
        )

    if len(labels) >= 5:
        flag(
            "Many subdomains", 10,
            "Inspect which domain actually owns this hostname."
        )

    if hostname in SHORTENERS:
        flag(
            "URL shortener", 10,
            "The shortened URL hides its final destination."
        )

    if sum(c.isdigit() for c in hostname) >= 5:
        flag(
            "Many digits", 10,
            "The hostname contains many digits. Verify its identity."
        )

    if len(parsed.query) > 120:
        flag(
            "Long query string", 10,
            "Long URL parameters can be difficult to inspect."
        )

    if hostname.count("-") >= 3:
        flag(
            "Hyphen-heavy hostname", 10,
            "Several hyphens can make a hostname harder to distinguish."
        )

    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(rf"(?<![a-z]){word}(?![a-z])", full_url)
    )

    if matched_words:
        flag(
            "Sensitive wording", 10,
            "Account-related terms found: "
            + ", ".join(matched_words)
            + ". These words alone do not prove phishing."
        )

    score = min(score, 100)

    if score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return {
        "hostname": hostname,
        "score": score,
        "level": level,
        "indicators": indicators,
        "message": (
            "This score measures configured warning signs, "
            "not the verified safety of the website."
        )
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/test")
def test_api():
    return jsonify({
        "project": "PhishLens",
        "status": "working"
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")

    if not isinstance(raw_url, str):
        return jsonify({"error": "URL must be text."}), 400

    result = analyze_url(raw_url)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)