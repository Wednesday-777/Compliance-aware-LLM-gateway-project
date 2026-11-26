from app.pii import redact


def test_pan_redacted():
    text, findings = redact("My PAN is ABCDE1234F")
    assert "ABCDE1234F" not in text
    assert "[PAN]" in text


def test_aadhaar_redacted():
    text, _ = redact("Aadhaar: 2345 6789 0123")
    assert "[AADHAAR]" in text


def test_email_and_phone():
    text, findings = redact("Mail me at a.b@gmail.com or call 9876543210")
    assert "[EMAIL]" in text
    assert "[PHONE_IN]" in text
    assert len(findings) == 2


def test_valid_card_detected_as_card():
    text, _ = redact("Card 4111 1111 1111 1111")
    assert "[CREDIT_CARD]" in text


def test_clean_text_unchanged():
    text, findings = redact("What is the capital of France?")
    assert text == "What is the capital of France?"
    assert findings == []