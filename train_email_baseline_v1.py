"""One development-only subject/body baseline; no network or URL detector use."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics
import time

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent
DATA = BASE / 'data/email/experiments/baseline_v1'
REPORT = BASE / 'reports/email_baseline_v1'
MODEL = BASE / 'models/email_baseline_v1'
INPUT = BASE / 'data/email/processed/messages.jsonl'
EMAIL = re.compile(r'(?i)[\w.+%-]+@[\w.-]+\.[a-z]{2,}')
# Include explicit schemes, protocol-relative addresses, www and bare domains.
URL = re.compile(r'''(?ix)(?:\b[a-z][a-z0-9+.-]*://|(?<!\w)//|\bwww\.)[^\s<>"']+|\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}(?::\d+)?(?:[/\?#][^\s<>"']*)?''')


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()


def mask(text):
    return URL.sub('[URL]', EMAIL.sub('[EMAIL]', text))


def template(text):
    text = re.sub(r'\d+', ' NUM ', text.casefold())
    return ' '.join(re.findall(r'\w+', text))


def group_texts(texts):
    """Connected components of exact templates and near/template shingles."""
    parent = list(range(len(texts)))
    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def union(i, j):
        a, b = root(i), root(j)
        if a != b:
            parent[max(a,b)] = min(a,b)
    exact, inverted, sets, edges = {}, defaultdict(list), [], []
    for i, text in enumerate(texts):
        norm = template(text)
        words = norm.split()
        shingles = set(zip(words, words[1:], words[2:]))
        sets.append(shingles)
        if norm in exact:
            j = exact[norm]
            union(i, j)
            edges.append([i,j,'exact_template'])
        else:
            exact[norm] = i
        candidates = Counter(j for s in shingles for j in inverted[s])
        for j, shared in candidates.items():
            other = sets[j]
            small, large = sorted((len(shingles), len(other)))
            if small < 10:
                continue
            jaccard = shared / (len(shingles)+len(other)-shared)
            containment = shared / small
            if jaccard >= .80 or (containment >= .90 and small/large >= .60):
                union(i, j)
                edges.append([i,j,'near_template'])
        for s in shingles:
            inverted[s].append(i)
    return [f'g{root(i):05d}' for i in range(len(texts))], edges


def metrics(y, pred, rows):
    p,r,f,_ = precision_recall_fscore_support(y,pred,labels=[0],zero_division=0)
    cm = confusion_matrix(y,pred,labels=[0,1]).tolist()
    groups = {}
    for source in ['nazario_2021','easy_ham','hard_ham']:
        ids = [i for i,row in enumerate(rows) if row['group']==source]
        phish = sum(int(pred[i])==0 for i in ids)
        groups[source] = {'n':len(ids),'predicted_phishing':phish,
            'rate':phish/len(ids) if ids else None,
            'meaning':'phishing_candidates_detected' if source=='nazario_2021' else 'benign_candidates_false_alarm'}
    return {'accuracy':float(accuracy_score(y,pred)), 'phishing_precision':float(p[0]),
        'phishing_recall':float(r[0]),'phishing_f1':float(f[0]),
        'confusion_matrix_rows_true_columns_pred_labels_0_1':cm,'by_source':groups}


def main():
    for p in [DATA, REPORT, MODEL]:
        p.mkdir(parents=True,exist_ok=True)
    if (MODEL/'model.joblib').exists():
        raise SystemExit('Model already exists; refusing to refit or overwrite this one-run experiment.')
    # Hash every pre-existing research artifact; exclude only new email experiment outputs.
    protected = {}
    for folder in ['data','models','reports','handoff']:
        for p in (BASE/folder).rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts and not any(p.is_relative_to(q) for q in [DATA,REPORT,MODEL]):
                protected[p.relative_to(BASE).as_posix()] = sha(p)
    for p in BASE.glob('*.py'):
        if p.name != Path(__file__).name:
            protected[p.name] = sha(p)
    dump(REPORT/'preservation_before.json',protected)
    original = [json.loads(line) for line in INPUT.read_text(encoding='utf-8').splitlines()]
    rows, held = [], []
    for idx,row in enumerate(original):
        subject,body = row.get('subject',''),row.get('body_text','')
        if row['status'] != 'success' or not (subject.strip() or body.strip()):
            held.append({'row_index':idx,'original_location':row['original_location'],
                'reason':'parse_failure' if row['status']!='success' else 'empty_subject_and_body'})
            continue
        label = {'phishing_candidate':0,'benign_candidate':1}[row['project_category']]
        text = mask(subject) + '\n\n' + mask(body)
        assert not URL.search(text.replace('[URL]',''))
        rows.append({**row,'input_row_index':idx,'project_label':label,'model_text':text})
    groups, edges = group_texts([r['model_text'] for r in rows])
    for row,g in zip(rows,groups):row['split_group']=g
    y = np.array([r['project_label'] for r in rows])
    # Exactly one split; no retries, stratification search or score selection.
    train,valid = next(GroupShuffleSplit(n_splits=1,test_size=.20,random_state=42).split(rows,y,groups))
    assert not set(groups[i] for i in train)&set(groups[i] for i in valid)
    assert set(y[train])=={0,1} and set(y[valid])=={0,1}
    valid_set=set(valid.tolist())
    with (DATA/'assignments.jsonl').open('w',encoding='utf-8') as f:
        for i,row in enumerate(rows):
            f.write(json.dumps({**row,'split':'validation' if i in valid_set else 'train'},ensure_ascii=False)+'\n')
    dump(DATA/'held.json',held)
    dump(DATA/'group_edges.json',edges)
    pipeline=Pipeline([('tfidf',TfidfVectorizer(lowercase=True,ngram_range=(1,2),min_df=2,
        max_df=1.0,max_features=30000,sublinear_tf=True)),
        ('classifier',LogisticRegression(C=1.0,class_weight='balanced',solver='liblinear',
            max_iter=2000,random_state=42))])
    start=time.perf_counter()
    pipeline.fit([rows[i]['model_text'] for i in train],y[train])
    elapsed=time.perf_counter()-start
    classes=pipeline.classes_
    col=int(np.flatnonzero(classes==0)[0])
    scores=pipeline.predict_proba([rows[i]['model_text'] for i in valid])[:,col]
    predicted=np.where(scores>=.5,0,1)
    validation_rows=[rows[i] for i in valid]
    model_metrics=metrics(y[valid],predicted,validation_rows)
    baseline_metrics=metrics(y[valid],np.ones(len(valid),dtype=int),validation_rows)
    with (DATA/'validation_predictions.jsonl').open('w',encoding='utf-8') as f:
        for row,score,pred in zip(validation_rows,scores,predicted):
            f.write(json.dumps({'input_row_index':row['input_row_index'],'original_location':row['original_location'],
                'source_group':row['group'],'split_group':row['split_group'],
                'original_classification':row['original_classification'],'project_label':row['project_label'],
                'phishing_score':float(score),'predicted_label':int(pred),'threshold':.5},ensure_ascii=False)+'\n')
    joblib.dump(pipeline,MODEL/'model.joblib')
    reloaded=joblib.load(MODEL/'model.joblib')
    assert np.array_equal(scores,reloaded.predict_proba([r['model_text'] for r in validation_rows])[:,col])
    split={}
    for name,ids in [('train',train),('validation',valid)]:
        split[name]={'messages':len(ids),'groups':len({groups[i] for i in ids}),
            'by_source':dict(Counter(rows[i]['group'] for i in ids)),
            'by_label':dict(Counter(int(y[i]) for i in ids)),
            'no_url_messages':sum(not rows[i]['has_url'] for i in ids)}
    preservation={n:sha(BASE/n)==h for n,h in protected.items()}
    assert all(preservation.values())
    result={'experiment':'email_baseline_v1_development_only','input_sha256':sha(INPUT),
        'label_mapping':{'phishing_candidate':0,'benign_candidate':1},'threshold':.5,
        'split':split,'split_group_overlap':0,'held_count':len(held),'retained_messages':len(rows),
        'grouping':{'normalization':'URL/email masked, casefold, digits to NUM, word tokens',
            'rule':'connected components: exact normalized title+body OR word-trigram Jaccard >=0.80 OR containment >=0.90 with size ratio >=0.60; near comparisons require >=10 shingles',
            'groups':len(set(groups)),'largest_group':max(Counter(groups).values()),
            'edges':len(edges),'short_text_policy':'exact normalized match only',
            'limitation':'heuristic grouping cannot guarantee all semantic templates are caught'},
        'split_config':{'method':'GroupShuffleSplit','n_splits':1,'test_size_groups':.2,'random_state':42},
        'tfidf_config':{'ngram_range':[1,2],'min_df':2,'max_df':1.0,'max_features':30000,'sublinear_tf':True,'lowercase':True,'norm':'l2','use_idf':True,'smooth_idf':True,'token_pattern':pipeline['tfidf'].token_pattern},
        'classifier_config':{'C':1.0,'class_weight':'balanced','solver':'liblinear','max_iter':2000,'random_state':42},
        'classes':classes.tolist(),'phishing_probability_column':col,
        'vocabulary_size':len(pipeline['tfidf'].vocabulary_),'fit_seconds':elapsed,
        'sklearn_version':sklearn.__version__,'model_sha256':sha(MODEL/'model.joblib'),
        'model':model_metrics,'always_benign':baseline_metrics,
        'verification':{'protected_files':len(protected),'all_protected_hashes_unchanged':True,
            'reload_scores_exactly_equal':True,'train_only_pipeline_fit_calls':1,
            'url_detector_loaded':False,'group_features_fit':False},
        'privacy':'message-level text, locations and predictions under ignored data/email; fitted vocabulary/model ignored under models/email_baseline_v1'}
    dump(REPORT/'results.json',result)
    dump(MODEL/'metadata.json',result)
    write_report(result)
    print(json.dumps(result,ensure_ascii=True,indent=2))


def write_report(r):
    lines=['# 제목·본문 이메일 기준 모델 v1 — 개발 검증','',
        '질문: URL 주소 자체를 가린 제목·읽을 수 있는 본문만으로 피싱 후보를 얼마나 잡는가? 기존 email_intake_v1의 2,850개 메일만 사용했다. 독립적인 최종 성능이나 새 출처 일반화 성능이 아니다. 피싱 후보는 전부 Nazario, 정상 후보는 전부 SpamAssassin이므로 출처와 라벨이 완전히 얽혀 있다.','',
        '## 입력·라벨·보존','',
        '기존 원본 라벨·출처·원본 위치는 보존하고 프로젝트 라벨은 피싱 후보=0, 정상 후보=1로 따로 만들었다. 모델 입력은 제목과 읽을 수 있는 본문뿐이며 출처·파일명·헤더·HTML 플래그·추출 href 배열은 넣지 않았다. 본문의 서명·반복 문구 등 간접 출처 단서는 남아 있을 수 있다.','',
        'URL의 명시적 scheme·프로토콜 상대 주소·www·맨 도메인은 [URL]로 치환했다. 이메일 주소도 출처·개인정보 단서를 줄이기 위해 [EMAIL]로 치환했다. HTML에서 추출한 읽을 수 있는 텍스트의 URL도 같은 처리를 한다. 난독화 주소·IP 단독 표기 등 모든 주소 표현을 완전히 제거한다고 보장하지 않는다. 치환 전 원문은 기존 추출 자료에 그대로 보존했다.','',
        f"URL 없는 메일도 포함했다. 둘 다 빈 제목·본문 또는 파싱 실패는 보류하며 이번 보류는 {r['held_count']}개다. 제목이나 본문 하나만 비어 있으면 나머지를 사용했다. 원문·메일별 위치·분리·예측은 Git 제외된 data/email/experiments/baseline_v1/에만 저장했다. 모델은 학습 어휘를 포함하므로 models/email_baseline_v1/ 전체도 Git 제외했다.",'',
        '## 그룹과 한 번의 분리','',
        'URL/이메일 마스킹 후 제목+본문을 소문자화(casefold), 숫자→NUM, 단어 토큰으로 정규화했다. 같은 정규화 문자열 또는 단어 3-gram 집합 Jaccard ≥0.80 또는 포함률 ≥0.90이면서 집합 크기 비율 ≥0.60이면 연결했다. 근접 비교는 최소 10개 shingle이 있는 문서에만 적용하고 짧은 문서는 정확한 정규화 일치만 사용했다. 연결요소를 한 그룹으로 묶어 반복 템플릿의 연결 사슬도 같은 집합에 둔다. 이 규칙은 의미가 같은 모든 템플릿의 검출을 보장하지 않는다.','',
        f"총 그룹 {r['grouping']['groups']}개, 최대 그룹 {r['grouping']['largest_group']}메일. GroupShuffleSplit(random_state=42, n_splits=1, test_size=0.20)로 한 번만 나눴다. 20%는 그룹 비율 목표라 실제 메일 비율은 다를 수 있다. 결과를 보고 다시 나누지 않았다. train/validation 그룹 교집합은 0개다. 그룹 계산은 텍스트 비교 규칙만 사용하며 TF-IDF를 전체 자료에 fit하지 않았다.",'',
        '| 집합 | 전체 | Nazario | easy_ham | hard_ham | URL 없는 메일 | 그룹 |','|---|---:|---:|---:|---:|---:|---:|']
    for name,s in r['split'].items():
        b=s['by_source'];lines.append(f"| {name} | {s['messages']} | {b.get('nazario_2021',0)} | {b.get('easy_ham',0)} | {b.get('hard_ham',0)} | {s['no_url_messages']} | {s['groups']} |")
    lines+=['','## 모델과 평가','',
        '단어 TF-IDF(1~2gram, min_df=2, max_df=1.0, max_features=30000, sublinear_tf=True, lowercase=True, L2 정규화, smooth IDF) + 로지스틱 회귀(C=1.0, class_weight=balanced, liblinear, max_iter=2000, random_state=42)를 한 번 학습했다. 어휘·IDF·분류기는 train에만 fit했다. classes_에서 0의 열을 찾아 피싱 후보 점수로 사용하고 0.5 이상이면 0, 그 외는 1이다. 임계값 탐색·튜닝·URL v1 점수 결합은 하지 않았다.','',
        f"scikit-learn {r['sklearn_version']}, 실제 어휘 {r['vocabulary_size']}개. 전체 설정·입력/모델 SHA-256은 results.json에 있다.",'',
        '| 같은 validation 평가 | 정확도 | 피싱 Precision | 피싱 Recall | 피싱 F1 |','|---|---:|---:|---:|---:|']
    for name,key in [('TF-IDF + 로지스틱','model'),('항상 정상','always_benign')]:
        m=r[key];lines.append(f"| {name} | {m['accuracy']:.2%} | {m['phishing_precision']:.2%} | {m['phishing_recall']:.2%} | {m['phishing_f1']:.2%} |")
    lines+=['','양성 예측이 없는 항상 정상 기준의 Precision/F1은 zero_division=0으로 0을 기록했다.','',
        '| 그룹 / 해석 | 모델 경고 / 전체 | 비율 | 항상 정상 경고 / 전체 |','|---|---:|---:|---:|']
    for source in ['nazario_2021','easy_ham','hard_ham']:
        s=r['model']['by_source'][source];n=s['n'];label='피싱 후보 탐지' if source=='nazario_2021' else '정상 후보 오경고'
        lines.append(f"| {source} / {label} | {s['predicted_phishing']} / {n} | {s['rate']:.2%} | 0 / {n} |")
    lines+=['','혼동행렬은 행=실제, 열=예측이며 순서는 [피싱 후보(0), 정상 후보(1)]이다.','',
        '| 모델 | 실제 피싱→피싱 | 실제 피싱→정상 | 실제 정상→피싱 | 실제 정상→정상 |','|---|---:|---:|---:|---:|']
    for name,key in [('TF-IDF + 로지스틱','model'),('항상 정상','always_benign')]:
        c=r[key]['confusion_matrix_rows_true_columns_pred_labels_0_1'];lines.append(f'| {name} | {c[0][0]} | {c[0][1]} | {c[1][0]} | {c[1][1]} |')
    n=r['model']['by_source']['nazario_2021']['n']
    lines+=['',f'검증 피싱 후보는 {n}개뿐이다. 한 메일의 탐지 여부만 달라져도 Recall이 {100/n:.2f}%p 변한다. 높은 점수도 새 출처 피싱 탐지의 증거가 아니다. 그룹 자체도 서로 독립 표본이라고 보장할 수 없다.','',
        '## 검증과 다음 비교 기준','',
        f"보호 파일 {r['verification']['protected_files']}개 해시 불변, train/validation 그룹 겹침 0, 저장 후 재로딩 점수 정확히 일치를 확인했다. 기존 URL v1은 로딩·추론·수정하지 않았다. 새 다운로드·패키지 변경·Git 업로드는 하지 않았다.",'',
        '다음 URL 점수 결합 실험은 이번 assignments.jsonl의 같은 메일·같은 train/validation·같은 라벨을 그대로 사용해야 공정하게 비교할 수 있다. 이번에는 결합을 수행하지 않았다. split 기록과 행별 예측은 개인정보 때문에 Git 제외 경로에 있고 입력 SHA-256으로 재현 기준을 남겼다.','',
        '학습 전용 코드: train_email_baseline_v1.py. 실수로 두 번째 학습을 하지 않도록 모델이 이미 있으면 중단한다. 재실행해 기존 실험을 덮어쓰지 않는다.','',
        '향후 필요한 자료는 같은 시기·같은 수집 환경의 정상/피싱, 한국어 정상/피싱, 독립 출처의 평가 메일, 수작업 피싱 재검토와 URL 단위 정답이다. 출처 마커·서명·시대 차이·근접 중복 누출 점검도 더 필요하다.','']
    (REPORT/'report_ko.md').write_text('\n'.join(lines),encoding='utf-8')


if __name__=='__main__':main()
