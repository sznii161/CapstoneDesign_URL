"""Offline subject/body and URL inference with the saved v1 models."""
from pathlib import Path
import sys

from email_intake_v1 import HTMLText, clean
from capstone_models.email_links import MailHTML, destinations

ROOT = Path(__file__).resolve().parents[1]
# Preserve module paths used by the existing callers and joblib artifacts.
sys.path.append(str(ROOT / "chrome-url-check"))
from email_prediction import extract_links, load_email_model, predict_email_text
from handoff.url_detector_v1.inference import load_detector

WEB_PREFIXES = ("http://", "https://", "//", "www.")


def _analyze(subject, body, *, html_body, extracted_links, unavailable_reason, legacy):
    """Pass selected MIME text plus optional original HTML or MIME-extracted URLs."""
    if not isinstance(subject, str) or not isinstance(body, str):
        raise TypeError("subject and body must be strings")
    links = None
    try:
        parser = HTMLText() if legacy else MailHTML()
        if html_body is not None:
            parser.feed(html_body)
            parser.close()
            visible = clean("".join(parser.text))
            body = body if body.strip() else visible
        else:
            visible = ""
        hrefs = [href.strip() for href in parser.hrefs if href.strip().lower().startswith(WEB_PREFIXES)]
        if legacy:
            links = dict.fromkeys(extract_links(subject, body) + extract_links("", visible) + hrefs + list(extracted_links))
        else:
            links = destinations(subject, body, visible=visible, hrefs=hrefs, extracted_links=extracted_links)
    except (TypeError, ValueError, AssertionError) as exc:
        extraction_error = type(exc).__name__

    if not (subject.strip() or body.strip()):
        raise ValueError("Email subject or body is required")
    text = predict_email_text(load_email_model(), subject, body)
    checks = []
    if links is None:
        status = "extraction_failed"
        reason = extraction_error
    elif links:
        for url in links:
            try:
                checks.append({"url": url, **load_detector().predict(url)})
            except Exception as exc:
                checks.append({"url": url, "error": type(exc).__name__})
        status = "scored" if all("predicted_label" in row for row in checks) else "check_failed"
        reason = unavailable_reason
    else:
        status = "unavailable" if unavailable_reason else "no_links"
        reason = unavailable_reason

    url_labels = [row["predicted_label"] for row in checks if "predicted_label" in row]
    url_label = 0 if 0 in url_labels else 1 if status == "scored" and not reason else None
    combined = 0 if text["predicted_label"] == 0 or url_label == 0 else 1
    return {"text": text, "links": checks, "url_status": status, "url_reason": reason,
            "url_label": url_label, "combined_label": combined}


def analyze_email_v1(subject="", body="", *, html_body=None, extracted_links=(), unavailable_reason=None):
    """Reproduce the original development experiment."""
    return _analyze(subject, body, html_body=html_body, extracted_links=extracted_links,
                    unavailable_reason=unavailable_reason, legacy=True)


def analyze_email(subject="", body="", *, html_body=None, extracted_links=(), unavailable_reason=None):
    """Use title/body for the final warning and expose link scores as evidence."""
    result = _analyze(subject, body, html_body=html_body, extracted_links=extracted_links,
                      unavailable_reason=unavailable_reason, legacy=False)
    result["policy_version"] = "email_text_only_v1"
    result["link_extraction_version"] = "explicit_web_v2"
    result["model_versions"] = {"text": "email_baseline_v1", "url": "url_detector_v1"}
    result["final_label"] = result["text"]["predicted_label"]
    result["final_warning"] = result["final_label"] == 0
    return result
