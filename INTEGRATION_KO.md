# 이메일·로그인 화면 분석 연결 안내

이 브랜치는 모델 추론 소스와 팀원 연결 문서를 공개용으로 정리한 것입니다. 기존 루트 URL 패키지는 유지합니다.

## 실행 전 준비

이 저장소만 clone하면 새 이메일·화면 예제는 실행되지 않습니다. 새 가중치와 기준 이미지는 공개 검토가 끝나지 않아 포함하지 않았습니다. 팀 내부로 전달한 `capstone_runtime_v1_INTERNAL.zip`을 별도 폴더에 풀어 실행하세요. ZIP, 메일 원문, 가중치와 캡처는 GitHub에 추가하지 마세요.

- [내부 패키지 시작 문서](handoff/capstone_integration_v1/START_HERE_KO.md)
- [구현·평가 현황](handoff/capstone_integration_v1/PROFESSOR_BRIEF_KO.md)

시작 문서의 명령과 SHA256SUMS.json은 내부 ZIP 루트 기준입니다. 검증기 소스는 저장소의 `handoff/capstone_integration_v1/verify_package.py`에 보관되며, 실행할 때는 내부 ZIP 루트의 검증기를 사용합니다. 문서에 등장하는 상세 평가 자료와 과거 전달 문서 일부는 로컬 연구 자료이며 이 공개 소스에 포함되지 않습니다.

## 필요한 비공개 자산

- `models/email_baseline_v1/model.joblib`
- `models/login_visual_v1/mobilenetv2.onnx`, `naver.png`, `kakao.png`, `woori.png`
- `handoff/url_detector_v1/metadata.json` 및 해당 모델 가중치
- 내부 ZIP의 `SHA256SUMS.json`

기존 루트 URL 가중치는 기존 커밋 그대로입니다. 새 가중치를 추가하거나 기존 파일을 재배치하지 않았습니다.

## 연결 계약

`capstone_models.email.analyze_email()`의 `final_warning`은 제목·본문 모델 경고입니다. 링크별 `links` 결과는 별도 표시합니다. `combined_label`은 실험용 OR이므로 최종 경고로 사용하지 않습니다. 미탐지는 안전 보장이 아니며 오류·링크 없음과 구분합니다. 한국어 이메일 독립 성능은 미검증입니다.

`capstone_models.login.analyze_login_screen()`은 `similarity_only`입니다. 1위 브랜드나 호스트 불일치만으로 사칭을 확정하지 않습니다.

Chrome 확장과 FastAPI 서버 구현은 팀원 통합 범위입니다. `chrome-url-check/email_prediction.py`만 기존 본문 추론 의존성으로 포함했습니다.

## 검증 범위

이 업로드는 기존 소스 보존과 Python 문법·공개 대상 점검을 수행합니다. 내부 패키지 실행 검증은 전달 문서에 기록된 기존 실험이며, GitHub 소스만으로 전체 추론을 새로 검증한 것은 아닙니다. 데이터 수집·학습 스크립트는 필요한 원본 자료가 별도로 있어야 실행됩니다.
