from functools import lru_cache
from html import unescape
from pathlib import Path
import re
import sys

import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))
from train_email_baseline_v1 import EMAIL, URL, mask

LINK_OR_EMAIL = re.compile(
    rf"(?P<email>{EMAIL.pattern.removeprefix('(?i)')})|(?P<link>{URL.pattern.removeprefix('(?ix)')})",
    URL.flags,
)


def extract_links(subject, body):
    raw_text = subject + "\n\n" + body
    links = {}
    for match in LINK_OR_EMAIL.finditer(raw_text):
        if match.lastgroup != "link":
            continue
        url = unescape(match.group()).rstrip(".,;:!?。！？、")
        for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
            while url.endswith(closing) and url.count(closing) > url.count(opening):
                url = url[:-1]
        # The existing URL detector accepts both bare and protocol-relative URLs.
        if "://" not in url or url.lower().startswith(("http://", "https://")):
            links[url] = None
    return list(links)


@lru_cache(maxsize=1)
def load_email_model():
    model = joblib.load(ROOT / "models" / "email_baseline_v1" / "model.joblib")
    return model, list(model.classes_).index(0)


def predict_email_text(detector, subject, body):
    model, phishing_column = detector
    model_text = mask(subject) + "\n\n" + mask(body)
    score = float(model.predict_proba([model_text])[0, phishing_column])
    return {"phishing_score": score, "predicted_label": 0 if score >= 0.5 else 1}
