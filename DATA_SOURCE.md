# 데이터 출처와 이용 조건

학습 출처: [PhreshPhish 공식 저장소](https://huggingface.co/datasets/phreshphish/phreshphish)

고정 revision: `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`

[해당 revision 데이터 카드](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md)의 로컬 사본은 `DATASET_CARD.md`다. 카드는 CC BY 4.0 및 피싱 방지 연구용 사용 조건을 명시한다. 원본 데이터·HTML은 이 패키지에 포함하지 않는다.

공식 train을 도메인 그룹 기준으로 나눈 splits_v1의 train 392,506행만 학습했다. validation 105,743행은 개발 평가에 사용했고 train+validation 재학습은 하지 않았다. 공식 test 168,060행은 모델·입력 정책·임계값을 고정한 후 평가했다. UCI 자료·예약 정상 후보를 학습에 병합하지 않았다.

논문: Thomas Dalton 외, *PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark* (2025), https://arxiv.org/abs/2507.10854

데이터 라이선스가 학습 모델이나 새 추론 코드에 자동으로 동일하게 적용된다고 단정하지 않는다. 코드·모델의 배포 라이선스는 아직 지정하지 않았다. GitHub 공유 시 소유자가 배포 권한·조건을 검토하고 별도 라이선스를 결정해야 한다. 이 문서는 새로운 라이선스 허가를 부여하지 않는다.
