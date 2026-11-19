# 캡스톤 모델 통합 패키지 v1

팀원은 이 문서부터 읽는다. 기존 `handoff/capstone_model_v1/CURRENT_CONTRACT_KO.md`와 `EMAIL_POLICY_V2_KO.md`는 정책의 배경이고, 기존 `README_KO.md`는 v1 실험도 포함한다. 이 패키지의 설치·오류 처리·표시 기준은 아래 내용이 최신이다.

## 설치 및 시작

Windows x64, Python 3.14.6 기준. ZIP을 새 폴더에 풀고, 풀린 폴더의 루트에서 실행한다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r capstone_models/requirements.txt
.\.venv\Scripts\python.exe -m capstone_models.example
.\.venv\Scripts\python.exe verify_package.py
```

설치에 패키지 다운로드가 필요할 수 있다. 모델 로딩과 예제 추론은 오프라인이다. `SHA256SUMS.json`의 해시를 확인한 프로젝트 가중치만 로딩한다. 모델·설정·이미지 상대 경로를 유지한다. 검증 중에는 모델 파일을 테스트 폴더에서 잠깐 이름 변경한 뒤 복구하므로 실행 중인 서비스 폴더에서는 검증기를 실행하지 않는다.

## 연결 함수

```python
from capstone_models.email import analyze_email
from handoff.url_detector_v1.inference import predict_url
from capstone_models.login import analyze_login_screen

mail = analyze_email("Synthetic notice", "Read https://example.com/")
url = predict_url("https://example.org/")
screen = analyze_login_screen(
    "models/login_visual_v1/naver.png", "https://nid.naver.com/nidlogin.login"
)
```

| 값 | 팀원 화면 표시 |
|---|---|
| `final_warning=true` | 제목·본문 모델 피싱 경고 |
| `final_warning=false` | 제목·본문 모델이 피싱 징후를 탐지하지 못함. 메일·링크·첨부의 안전 보장 없음 |
| 링크 `predicted_label=0` | 해당 링크의 모델 경고. 이메일 최종 경고는 `final_warning`에서 읽음 |
| `url_status=no_links` | 검사할 링크 없음 |
| `url_status=check_failed` | 일부 또는 전체 링크 검사 실패. 각 링크의 `error`와 성공 결과를 별도 표시 |
| `url_status=extraction_failed` / `unavailable` | 링크 추출 실패 / 원본 링크 확인 불가 |
| `url_status=scored` + `url_label=1` | 검사한 링크에서 URL 경고 없음 |
| `combined_label` | 개발 비교용 OR. 이메일 최종 경고에 연결하지 않음 |
| `similarity_only` | 기준 화면 유사도, 1위 브랜드 후보, 해당 후보의 허용 호스트 일치 여부. 1위나 불일치에 사칭 확정 의미를 부여하지 않음 |
| `invalid_input` / `asset_error` | 화면 입력 오류 / 화면 모델·기준 자산 로드 실패 |

실제 예제에서 본문 점수는 0.189336, 링크 점수는 0.676298이다. `final_warning=false`와 링크 경고가 함께 반환된다. `combined_label=0`은 실험용이다. URL 단독은 잘못된 입력이면 `ValueError`, 모델이 없으면 `FileNotFoundError`가 발생한다. 이메일 제목·본문 타입 오류는 `TypeError`, 둘 다 비어 있으면 `ValueError`, 본문 모델 누락은 `FileNotFoundError`다. URL 모델 누락은 이메일의 링크 검사 실패로 나타난다. 오류를 미탐지로 표시하지 않는다.

언어 성능 표시는 앱의 설명 문구로 관리한다. 이메일은 **한국어 독립 평가 성능 미검증**으로 표시한다. 기존 한국어 공개 사례의 소규모 개발 점검은 한국어 성능을 검증하기에 부족하다. URL 공식 시험의 한국어 표본 수치는 이메일 본문과 별개다.

## 버전 및 구성

- 본문 `email_baseline_v1`, URL `url_detector_v1`, 링크 추출 `explicit_web_v2`, 최종 정책 `email_text_only_v1`, 두 분류 기준값 0.5
- 화면 `login_visual_v1`의 MobileNetV2 ONNX, 기준 PNG 3장, `login_brands.json`, 상태 `similarity_only`
- `chrome-url-check/email_prediction.py`는 기존 본문 추론 의존 파일이다. Chrome 확장 파일과 FastAPI 서버는 패키지에 포함되지 않는다.
- 파일별 경로와 해시는 `SHA256SUMS.json`을 참고한다. 원문·평가 데이터·비밀키·가상환경·문자 모델은 ZIP 밖에 있다. 이 ZIP은 팀 내부 검증용이며 공개 GitHub 후보와 분리한다.
