"""Offline inference; initialize once with load_detector(), then reuse predict_url()."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
from urllib.parse import urlsplit
import joblib
import numpy as np

BASE_DIR = Path(__file__).resolve().parent

def validate_url(url):
    if not isinstance(url,str) or not url or not url.strip():
        raise ValueError('URL must be a nonempty string')
    if url[0].isspace() or any(ord(c)<32 or ord(c)==127 for c in url) or '\\' in url:
        raise ValueError('Ambiguous whitespace/control/backslash input')
    # Temporary authority parsing only. The Pipeline still receives the original URL.
    p=urlsplit(url if '://' in url or url.startswith('//') else '//'+url)
    if not p.hostname or any(c.isspace() for c in p.netloc) or '%' in p.hostname:
        raise ValueError('Cannot identify URL host')
    _=p.port
    if '://' in url and p.scheme.lower() not in ('http','https'):
        raise ValueError('Unsupported URL scheme')

class URLDetector:
    def __init__(self):
        metadata = json.loads((BASE_DIR/'metadata.json').read_text(encoding='utf-8'))
        path = BASE_DIR/metadata['model_file']
        if sha256(path.read_bytes()).hexdigest() != metadata['model_sha256']:
            raise ValueError('Model SHA-256 mismatch')
        if metadata['threshold'] != 0.5 or metadata['label_mapping'] != {'benign':1,'phish':0}:
            raise ValueError('Unexpected model decision metadata')
        self._model = joblib.load(path)
        classes = np.asarray(self._model.classes_)
        column = np.flatnonzero(classes == 0)
        if set(classes) != {0,1} or len(column) != 1:
            raise ValueError('Unexpected classes_')
        self._phishing_column = int(column[0])
        self._version = metadata['model_version']

    def predict(self,url):
        validate_url(url)
        score = float(self._model.predict_proba([url])[0,self._phishing_column])
        if not np.isfinite(score) or not 0 <= score <= 1:
            raise ValueError('Invalid model score')
        return {'phishing_score':score,'predicted_label':0 if score >= 0.5 else 1,
                'model_version':self._version}

@lru_cache(maxsize=1)
def load_detector():
    """Call once at startup. The same detector object is reused in this process."""
    return URLDetector()

def predict_url(url):
    """Return model score, label and version; invalid inputs raise ValueError."""
    return load_detector().predict(url)
