"""Check the internal integration bundle from its extracted root."""
from contextlib import contextmanager
import hashlib
import json
import platform
from pathlib import Path
import sys

from capstone_models.email import analyze_email, load_email_model
from capstone_models.login import analyze_login_screen, load_login_analyzer
from handoff.url_detector_v1.inference import load_detector, predict_url

ROOT = Path(__file__).resolve().parent
EMAIL = ROOT / "models/email_baseline_v1/model.joblib"
URL = ROOT / "handoff/url_detector_v1/url_char_tfidf_logreg_phreshphish_v1.joblib"
VISION = ROOT / "models/login_visual_v1/mobilenetv2.onnx"
REF = VISION.with_name("naver.png")
OFFICIAL = "https://nid.naver.com/nidlogin.login"


@contextmanager
def missing(path, reader):
    temp = path.with_suffix(path.suffix + ".verify-missing")
    if temp.exists():
        raise FileExistsError(temp)
    reader.cache_clear()
    path.rename(temp)
    try:
        yield
    finally:
        temp.rename(path)
        reader.cache_clear()


def expected_exception(expected, function, *args):
    try:
        function(*args)
    except expected as error:
        return type(error).__name__
    raise AssertionError(f"Expected {expected.__name__}")


def main():
    hashes = json.loads((ROOT / "SHA256SUMS.json").read_text(encoding="utf-8"))
    for name, expected in hashes.items():
        actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        assert actual == expected, name

    scored = analyze_email("Synthetic notice", "Read https://example.com/")
    assert scored["url_status"] == "scored" and scored["links"][0]["predicted_label"] == 0
    assert scored["combined_label"] == 0 and scored["final_warning"] is False
    assert scored["model_versions"] == {"text":"email_baseline_v1","url":"url_detector_v1"}
    assert scored["policy_version"] == "email_text_only_v1" and scored["link_extraction_version"] == "explicit_web_v2"
    no_links = analyze_email("Synthetic meeting", "Tomorrow morning")
    assert no_links["url_status"] == "no_links" and no_links["url_label"] is None
    failed = analyze_email("Synthetic meeting", "Tomorrow", extracted_links=["https://[bad"])
    assert failed["url_status"] == "check_failed" and failed["links"][0]["error"] == "ValueError"
    assert failed["url_label"] is None
    direct = predict_url("https://example.org/")
    assert direct["model_version"] == "url_detector_v1"
    screen = analyze_login_screen(REF, OFFICIAL)
    assert screen["status"] == "similarity_only" and screen["brand"] == "naver" and screen["domain_match"]
    bad_screen = analyze_login_screen(REF, "not-a-url")
    assert bad_screen["status"] == "invalid_input"
    no_screen = analyze_login_screen(REF.with_name("file-not-provided.png"), OFFICIAL)
    assert no_screen["status"] == "invalid_input"

    with missing(EMAIL, load_email_model):
        missing_email = expected_exception(FileNotFoundError, analyze_email, "Synthetic", "Text")
    with missing(URL, load_detector):
        missing_url = expected_exception(FileNotFoundError, predict_url, "https://example.org/")
        missing_url_mail = analyze_email("Synthetic notice", "Read https://example.com/")
        assert missing_url_mail["url_status"] == "check_failed"
        assert missing_url_mail["links"][0]["error"] == "FileNotFoundError"
    with missing(VISION, load_login_analyzer):
        missing_vision = analyze_login_screen(REF, OFFICIAL)
        assert missing_vision["status"] == "asset_error"

    output = {"python":sys.version, "os":platform.platform(), "machine":platform.machine(),
              "manifest_file_count":len(hashes), "email_link_disagreement":scored,"email_no_links":no_links,
              "email_url_check_failed":failed,"url":direct,"screen":screen,"bad_screen_url":bad_screen,
              "missing_screen":no_screen,"missing_email_model":missing_email,"missing_url_model":missing_url,
              "missing_url_model_email":missing_url_mail,"missing_vision_model":missing_vision,
              "invalid_email_type":expected_exception(TypeError,analyze_email,42,"Text"),
              "empty_email":expected_exception(ValueError,analyze_email,"",""),
              "invalid_url":expected_exception(ValueError,predict_url,"https://[bad")}
    print(json.dumps(output,indent=2))


if __name__ == "__main__":
    main()
