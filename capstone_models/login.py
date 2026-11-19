"""Offline CPU comparison of login-panel screenshots against official references."""
from functools import lru_cache
import json
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit

import cv2
import numpy as np

ASSETS = Path(__file__).resolve().parents[1] / "models/login_visual_v1"
CONFIG = Path(__file__).with_name("login_brands.json")
POOL_LAYER = "onnx_node!GlobalAveragePool_97"
MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)


def official_host(url):
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 or c == "\\" for c in url):
        raise ValueError("Ambiguous URL")
    address = urlsplit(url)
    if address.scheme not in ("https", "http") or not address.hostname or "%" in address.hostname:
        raise ValueError("Expected an absolute HTTP(S) URL")
    if address.username is not None or address.password is not None:
        raise ValueError("Userinfo is unsupported")
    _ = address.port
    return address.hostname.rstrip(".").encode("idna").decode("ascii").lower()


class LoginAnalyzer:
    def __init__(self, assets=ASSETS, config=CONFIG):
        assets = Path(assets)
        self.brands = json.loads(Path(config).read_text(encoding="utf-8-sig"))
        if not self.brands:
            raise ValueError("At least one reference is required")
        self.net = cv2.dnn.readNetFromONNX(str(assets / "mobilenetv2.onnx"))
        self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_OPENCV)
        self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CPU)
        self.lock = Lock()
        self.references = {brand: self._embed(assets / row["reference"], None)
                           for brand, row in self.brands.items()}

    def _embed(self, path, region):
        image = cv2.imdecode(np.frombuffer(Path(path).read_bytes(), dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Cannot decode screenshot")
        height, width = image.shape[:2]
        if region is not None:
            x, y, w, h = region
            if not (0 <= x < x + w <= width and 0 <= y < y + h <= height):
                raise ValueError("Crop lies outside screenshot")
            image = image[y:y+h, x:x+w]
            height, width = image.shape[:2]
        scale = 224 / max(height, width)
        shape = (max(1, round(width * scale)), max(1, round(height * scale)))
        resized = cv2.resize(image, shape, interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR)
        canvas = np.full((224, 224, 3), 255, dtype=np.uint8)
        x, y = (224 - shape[0]) // 2, (224 - shape[1]) // 2
        canvas[y:y+shape[1], x:x+shape[0]] = resized[:, :, ::-1]
        pixels = (canvas.astype(np.float32) / 255 - MEAN) / STD
        with self.lock:
            self.net.setInput(np.ascontiguousarray(pixels.transpose(2, 0, 1)[None]))
            vector = self.net.forward(POOL_LAYER).ravel().copy()
        norm = np.linalg.norm(vector)
        if not np.isfinite(norm) or norm == 0:
            raise ValueError("Invalid embedding")
        return vector / norm

    def analyze(self, screenshot_path, page_url, *, region=None):
        try:
            host = official_host(page_url)
            vector = self._embed(screenshot_path, region)
        except (OSError, ValueError, TypeError, UnicodeError, cv2.error) as exc:
            return {"status": "invalid_input", "brand": None, "similarity": None,
                    "domain_match": None, "reason": type(exc).__name__}
        scores = {brand: float(np.clip(vector @ ref, -1, 1)) for brand, ref in self.references.items()}
        brand = max(scores, key=scores.get)
        domain_match = host in self.brands[brand]["hosts"]
        return {"status": "similarity_only", "brand": brand, "similarity": scores[brand],
                "domain_match": domain_match, "similarities": scores,
                "reason": "allowed_exact_host" if domain_match else "host_not_allowed_for_top_candidate"}


@lru_cache(maxsize=1)
def load_login_analyzer():
    return LoginAnalyzer()


def analyze_login_screen(screenshot_path, page_url, *, region=None):
    """Use a login-panel image or pass its (x, y, width, height) pixel rectangle."""
    try:
        analyzer = load_login_analyzer()
    except (OSError, ValueError, KeyError, cv2.error) as exc:
        return {"status": "asset_error", "brand": None, "similarity": None,
                "domain_match": None, "reason": type(exc).__name__}
    return analyzer.analyze(screenshot_path, page_url, region=region)

