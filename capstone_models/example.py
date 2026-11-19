"""Synthetic integration example. Both functions run locally."""
import json

from capstone_models.email import ROOT, analyze_email
from capstone_models.login import analyze_login_screen


def main():
    email = analyze_email("Synthetic notice", "Read https://example.com/")
    login = analyze_login_screen(ROOT / "models/login_visual_v1/naver.png",
                                 "https://nid.naver.com/nidlogin.login")
    assert email["text"]["predicted_label"] == 1
    assert email["url_label"] == email["combined_label"] == 0
    assert email["final_label"] == 1 and not email["final_warning"]
    assert login["brand"] == "naver" and login["domain_match"]
    print(json.dumps({"email": email, "login": login}, indent=2))


if __name__ == "__main__":
    main()
