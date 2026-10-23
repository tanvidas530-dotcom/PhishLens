from app import app, analyze_url


def test_legitimate_sample():
    result = analyze_url("https://example.com")
    assert result["score"] == 0
    assert result["level"] == "Low"


def test_http_warning():
    result = analyze_url("http://example.com")
    names = [item["name"] for item in result["indicators"]]
    assert "No HTTPS" in names


def test_ip_address_warning():
    result = analyze_url("http://192.0.2.10/login")
    names = [item["name"] for item in result["indicators"]]
    assert "IP address host" in names


def test_empty_url():
    result = analyze_url("")
    assert "error" in result


def test_unsupported_scheme():
    result = analyze_url("javascript:alert(1)")
    assert "error" in result


def test_random_text():
    result = analyze_url("not a url")
    assert "error" in result


def test_api_rejects_non_string():
    client = app.test_client()
    response = client.post(
        "/api/analyze",
        json={"url": 123}
    )
    assert response.status_code == 400