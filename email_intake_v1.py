"""Offline email inspection; only --download fetches the three allowlisted archives."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import hashlib
from html.parser import HTMLParser
import json
import mailbox
from pathlib import Path
import re
import statistics
import subprocess
import tarfile
from urllib.request import urlopen
from zoneinfo import ZoneInfo

BASE = Path(__file__).resolve().parent
RAW = BASE / 'data/email/raw'
OUT = BASE / 'data/email/processed'
REPORT = BASE / 'reports/email_intake_v1'
SOURCES = [
    ('nazario_2021', 'https://monkey.org/~jose/phishing/phishing-2021', 'phishing', 'phishing_candidate'),
    ('easy_ham', 'https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2', 'ham', 'benign_candidate'),
    ('hard_ham', 'https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2', 'ham', 'benign_candidate'),
]
TERMS = {
    'nazario_2021': {'url': 'https://monkey.org/~jose/phishing/README.txt',
        'license_url': 'https://monkey.org/~jose/phishing/LICENSE.txt',
        'publisher_terms': 'CC BY 4.0; attribution required; derivatives and commercial use permitted. Hand classified, errors possible. Earlier mailboxes anonymized; later ones not.',
        'verified_date_kst': '2026-11-03'},
    'spamassassin': {'url': 'https://spamassassin.apache.org/old/publiccorpus/readme.html',
        'publisher_terms': 'Copyright in message text remains with original senders. Do not send corpus messages into live email systems. Some addresses and hostnames obfuscated. Explicit corpus-wide reuse/commercial/redistribution license unconfirmed; software license not applied to corpus.',
        'verified_date_kst': '2026-11-03'},
}
URL_RE = re.compile(r'''(?i)\b(?:https?://|ftp://|www\.)[^\s<>"'\x00-\x1f]+''')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def download(use_curl=False):
    RAW.mkdir(parents=True, exist_ok=True)
    manifest_path = REPORT / 'source_manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8')) if manifest_path.exists() else []
    for group, url, label, candidate in SOURCES:
        path = RAW / url.rsplit('/', 1)[1]
        if path.exists():
            recorded = next((r for r in manifest if r['filename'] == path.name), None)
            if not recorded or recorded['sha256'] != sha(path):
                raise RuntimeError('Existing original has no matching provenance: ' + path.name)
            continue
        temp = path.with_suffix(path.suffix + '.partial')
        if use_curl:
            head = subprocess.run(['curl.exe', '--fail', '--silent', '--show-error',
                '--head', '--connect-timeout', '15', '--max-time', '30', url],
                capture_output=True, text=True, check=True).stdout
            match = re.search(r'(?im)^Content-Length:\s*(\d+)', head)
            if not match:
                raise RuntimeError('Missing Content-Length: ' + path.name)
            total = int(match[1])
            headers = dict(re.findall(r'(?m)^([^:\r\n]+):\s*([^\r\n]*)', head))
            resolved_url = url
            # Small HTTP ranges avoid a repeatable stall on large responses.
            # A chunk is appended only after its length and 206 response pass.
            start = temp.stat().st_size if temp.exists() else 0
            chunk = path.with_suffix(path.suffix + '.chunk')
            while start < total:
                end = min(start + 65535, total - 1)
                result = subprocess.run(['curl.exe', '--fail', '--silent', '--show-error',
                    '--connect-timeout', '15', '--max-time', '45', '--range', f'{start}-{end}',
                    '--output', str(chunk), '--write-out', '%{json}', url],
                    capture_output=True, text=True, check=True)
                transfer = json.loads(result.stdout)
                if transfer['http_code'] != 206 or chunk.stat().st_size != end-start+1:
                    raise RuntimeError('Unexpected ranged response: ' + path.name)
                with temp.open('ab') as f:
                    f.write(chunk.read_bytes())
                chunk.unlink()
                start = end + 1
            if temp.stat().st_size != total:
                raise RuntimeError('Original size mismatch: ' + path.name)
        else:
            with urlopen(url, timeout=60) as response, temp.open('wb') as f:
                resolved_url = response.url
                headers = {k: response.headers.get(k) for k in ['Content-Type', 'Content-Length', 'Last-Modified', 'ETag']}
                for block in iter(lambda: response.read(1024 * 1024), b''):
                    f.write(block)
        temp.replace(path)
        now = datetime.now(timezone.utc)
        row = {'group': group, 'source_url': url, 'resolved_url': resolved_url,
               'filename': path.name, 'raw_path': path.relative_to(BASE).as_posix(),
               'downloaded_at_utc': now.isoformat(),
               'downloaded_at_kst': now.astimezone(ZoneInfo('Asia/Seoul')).isoformat(),
               'sha256': sha(path), 'bytes': path.stat().st_size, 'response_headers': headers,
               'original_classification': label, 'project_category': candidate,
               'terms': TERMS['nazario_2021' if group == 'nazario_2021' else 'spamassassin']}
        manifest.append(row)
        save(manifest_path, manifest)


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.hrefs = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'head'):
            self.hidden += 1
        if tag in ('a', 'area'):
            for key, value in attrs:
                if key.lower() == 'href' and value is not None:
                    self.hrefs.append(value)
        if tag in ('br', 'p', 'div', 'li', 'tr'):
            self.text.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'head'):
            self.hidden = max(0, self.hidden - 1)
        if tag in ('p', 'div', 'li', 'tr'):
            self.text.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def unique(items):
    return list(dict.fromkeys(items))


def clean(text):
    return '\n'.join(re.sub(r'[\t \r\f\v]+', ' ', line).strip() for line in text.splitlines()).strip()


def decode(part, warnings):
    payload = part.get_payload(decode=True)
    if payload is None:
        value = part.get_payload()
        return value if isinstance(value, str) else ''
    charset = part.get_content_charset() or 'ascii'
    try:
        return payload.decode(charset, errors='strict')
    except (LookupError, UnicodeError):
        warnings.append('decode_fallback:' + charset)
        try:
            return payload.decode('utf-8', errors='strict')
        except UnicodeError:
            return payload.decode('windows-1252', errors='replace')


def extract(part, warnings):
    """Return selected text, URLs across body alternatives, hrefs, HTML flag.

    Prefer nonempty text/plain within multipart/alternative; still inspect HTML
    alternative for hrefs without appending its equivalent body a second time.
    Skip attachments, named files and attached message/rfc822 entirely.
    """
    if part.get_content_disposition() == 'attachment' or part.get_filename() or part.get_content_type() == 'message/rfc822':
        return '', [], [], False
    if part.is_multipart():
        children = [extract(p, warnings) for p in part.iter_parts()]
        urls = unique([u for c in children for u in c[1]])
        hrefs = unique([u for c in children for u in c[2]])
        html = any(c[3] for c in children)
        if part.get_content_subtype() == 'alternative':
            pairs = list(zip(part.iter_parts(), children))
            preferred = next((c[0] for p, c in pairs if p.get_content_type() == 'text/plain' and c[0].strip()), None)
            text = preferred if preferred is not None else next((c[0] for c in reversed(children) if c[0].strip()), '')
        else:
            text = '\n'.join(unique([c[0] for c in children if c[0].strip()]))
        return text, urls, hrefs, html
    ctype = part.get_content_type()
    if ctype not in ('text/plain', 'text/html'):
        return '', [], [], False
    text = decode(part, warnings)
    if ctype == 'text/html':
        parser = HTMLText()
        parser.feed(text)
        parser.close()
        visible = clean(''.join(parser.text))
        return visible, unique(URL_RE.findall(visible)), unique(parser.hrefs), True
    return clean(text), unique(URL_RE.findall(text)), [], False


def messages(group, path, inventory):
    if group == 'nazario_2021':
        box = mailbox.mbox(str(path), create=False)
        try:
            for index, key in enumerate(box.iterkeys(), 1):
                yield f'{path.name}#message={index}', box.get_bytes(key, from_=False)
        finally:
            box.close()
    else:
        # Never extract archive paths onto disk; only read regular mail members.
        with tarfile.open(path, 'r:bz2') as archive:
            for member in archive:
                leaf = Path(member.name).name
                if not member.isfile() or not re.match(r'^\d+\.', leaf):
                    inventory.append({'archive': path.name, 'member': member.name, 'reason': 'non_message_member'})
                    continue
                stream = archive.extractfile(member)
                yield f'{path.name}::{member.name}', stream.read()


def inspect():
    OUT.mkdir(parents=True, exist_ok=True)
    rows, excluded = [], []
    manifest = json.loads((REPORT / 'source_manifest.json').read_text(encoding='utf-8'))
    for group, url, label, candidate in SOURCES:
        path = RAW / url.rsplit('/', 1)[1]
        provenance = next(r for r in manifest if r['group'] == group)
        assert sha(path) == provenance['sha256']
        for position, raw in messages(group, path, excluded):
            row = {'group': group, 'source_url': url, 'original_location': position,
                   'original_classification': label, 'project_category': candidate,
                   'message_sha256': hashlib.sha256(raw).hexdigest(),
                   'url_labels': None, 'url_label_policy': 'not_inherited_from_email',
                   'status': 'success', 'warnings': []}
            try:
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                subject = str(msg.get('Subject', ''))
                if 'X-IMAP' in msg and 'FOLDER INTERNAL DATA' in subject:
                    excluded.append({'archive': path.name, 'member': position,
                        'reason': 'imap_folder_internal_metadata_not_actual_email',
                        'message_sha256': row['message_sha256']})
                    continue
                body, urls, hrefs, has_html = extract(msg, row['warnings'])
                defects = [type(d).__name__ for part in msg.walk() for d in part.defects]
                defects += [type(d).__name__ for _, header in msg.items() for d in getattr(header, 'defects', ())]
                row['warnings'].extend('email_defect:' + d for d in defects)
                headers = {k.lower() for k in msg.keys()}
                row.update(subject=subject, body_text=body, body_urls=urls, html_hrefs=hrefs,
                           has_html_body=has_html, header_names=sorted(headers),
                           missing_subject=not subject.strip(), missing_body=not body.strip(),
                           body_length=len(body),
                           has_url=bool(urls or any(re.match(r'(?i)^(?:https?|ftp)://|^//|^www\.', h.strip()) for h in hrefs)),
                           missing_reasons=[])
                if row['missing_subject']:
                    row['missing_reasons'].append('missing_or_empty_subject_header')
                if row['missing_body']:
                    row['missing_reasons'].append('no_nonempty_supported_inline_text_body')
                row['source_markers'] = {m: m in raw.decode('latin-1').lower() for m in
                    ['spamassassin.taint.org', 'monkey.org', 'x-spam-', 'list-unsubscribe', 'list-id', 'mailman', 'unsubscribe']}
            except Exception as exc:
                row.update(status='failure', error_type=type(exc).__name__, error=str(exc),
                           subject='', body_text='', body_urls=[], html_hrefs=[],
                           missing_subject=True, missing_body=True, has_html_body=False,
                           body_length=0, has_url=False, header_names=[], source_markers={},
                           missing_reasons=['parse_failed_fields_unavailable'])
            rows.append(row)
    with (OUT / 'messages.jsonl').open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    save(OUT / 'issues.json', [r for r in rows if r['warnings'] or r['missing_reasons'] or r['status'] == 'failure'])
    save(OUT / 'archive_inventory.json', excluded)
    stats = []
    for group, *_ in SOURCES:
        group_rows = [r for r in rows if r['group'] == group]
        ok = [r for r in group_rows if r['status'] == 'success']
        counts = Counter((r['subject'], r['body_text']) for r in ok)
        normalized = Counter((re.sub(r'\s+', ' ', r['subject']).strip(), re.sub(r'\s+', ' ', r['body_text']).strip()) for r in ok)
        headers = Counter(h for r in ok for h in r['header_names'])
        markers = {m: sum(r['source_markers'].get(m, False) for r in ok) for m in ok[0]['source_markers']} if ok else {}
        lines = Counter(line for r in ok for line in set(r['body_text'].splitlines()) if len(line.strip()) >= 20)
        # Sensitive repeated lines are local only. Public report uses counts + hashes.
        save(OUT / f'{group}_repeated_lines.json', [{'line': line, 'message_count': n} for line, n in lines.most_common(20)])
        stats.append({'group': group, 'messages': len(group_rows), 'success': len(ok),
            'failure': len(group_rows)-len(ok), 'missing_subject': sum(r['missing_subject'] for r in ok),
            'missing_body': sum(r['missing_body'] for r in ok),
            'html_messages': sum(r['has_html_body'] for r in ok), 'url_messages': sum(r['has_url'] for r in ok),
            'median_body_length': statistics.median([r['body_length'] for r in ok]) if ok else None,
            'exact_duplicate_excess': sum(n-1 for n in counts.values()),
            'exact_duplicate_groups': sum(n>1 for n in counts.values()),
            'whitespace_normalized_duplicate_excess': sum(n-1 for n in normalized.values()),
            'messages_with_warnings': sum(bool(r['warnings']) for r in ok),
            'warning_counts': dict(Counter(w for r in ok for w in set(r['warnings']))),
            'header_message_counts': dict(headers.most_common()), 'marker_message_counts': markers,
            'repeated_line_counts_and_hashes': [{'message_count': n, 'sha256': hashlib.sha256(line.encode()).hexdigest()} for line, n in lines.most_common(10)]})
    save(REPORT / 'summary.json', stats)
    return stats


def write_report(stats):
    lines = [
        '# 이메일 데이터 첫 점검 v1', '',
        '확인일: 2026-11-03 (한국 시간). 지정한 공식 배포 파일 세 개만 사용했다. URL 탐지 v1 모델을 호출하지 않았으며 학습·데이터 분리·Enron 수집·외부 링크 접속을 수행하지 않았다.', '',
        '## 원본과 이용 조건', '',
        '원본은 `data/email/raw/`, 메일별 추출은 `data/email/processed/messages.jsonl`에 있다. 출처 URL·파일명·실제 다운로드 시각(UTC/KST)·파일 크기·SHA-256·HTTP 응답 메타데이터는 [source_manifest.json](source_manifest.json)에 기록했다.', '',
        '- Nazario: [공식 README](https://monkey.org/~jose/phishing/README.txt), [CC BY 4.0](https://monkey.org/~jose/phishing/LICENSE.txt). 출처 표시가 필요하고 수정·상업 이용을 허용한다고 명시한다. 개인 수신함의 수작업 분류로 오류가 있을 수 있고 초기와 후기 자료의 익명화 범위가 다르다.',
        '- SpamAssassin: [공식 README](https://spamassassin.apache.org/old/publiccorpus/readme.html). 메일 본문 저작권은 원 발신자에게 있다. 실메일 시스템에 재전송하지 말라는 요청이 있다. 데이터 전체의 명시적 재사용·상업 이용·재배포 라이선스는 미확인이다. 소프트웨어 라이선스를 데이터에 적용하지 않았다.', '',
        'Nazario의 원래 분류 `phishing`은 프로젝트 구분 `phishing_candidate`와 별도로 보존했다. easy_ham과 hard_ham은 원래 `ham`이고 프로젝트 구분은 `benign_candidate`다. hard_ham도 정상 대조 후보이다. 어떤 메일의 분류도 내부 URL에 복사하지 않았고 `url_labels=null`로 두었다.', '',
        '## 출처별 실제 구성', '',
        '| 그룹 | 실제 메일 수 | 파싱 성공 / 실패 | 제목 누락 | 본문 누락 | HTML 본문 수 / 비율 | URL 포함 수 / 비율 | 본문 길이 중앙값(문자) | 동일 제목·본문 반복 초과 건수 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
    ]
    for s in stats:
        n = s['success']
        lines.append(f"| {s['group']} | {s['messages']:,} | {n:,} / {s['failure']:,} | {s['missing_subject']:,} | {s['missing_body']:,} | {s['html_messages']:,} / {s['html_messages']/n:.2%} | {s['url_messages']:,} / {s['url_messages']/n:.2%} | {s['median_body_length']:,} | {s['exact_duplicate_excess']:,} |")
    lines += ['',
        '실제 메일 수는 mbox 메시지 항목 또는 tar 내부의 숫자+점으로 시작하는 일반 파일 수다. Nazario 원본의 mbox 항목은 101개지만 그중 1개는 X-IMAP 및 FOLDER INTERNAL DATA 표지가 있는 폴더 관리용 메타 메시지라 실제 메일 100개와 구분했다. 디렉터리·메타 파일은 메일 수에서 제외하고 `archive_inventory.json`에 원본 위치와 이유를 남긴다. 실패 행을 포함한 실제 메일은 모두 보존한다. 비율과 중앙값은 파싱 성공 메일 기준이며, 파싱 실패 시 제목·본문의 유무는 판정 불가이므로 누락 수에는 합산하지 않는다.', '',
        'HTML 비율은 첨부를 제외한 본문 대체 버전에 HTML이 하나라도 있는 비율이다. URL 포함은 본문 표시 텍스트의 http/https/ftp/www 주소 또는 HTML href의 http/https/ftp/프로토콜 상대/www 목적지가 하나 이상 있는 경우다. 상대 경로·mailto·javascript 등도 원래 href 배열에는 남지만 그 자체로 URL 포함 건수에 넣지는 않는다. 맨 도메인, CSS URL, 이미지 src, 첨부 내 주소는 이번 URL 통계 범위 밖이다.', '',
        '본문 길이는 추출된 유니코드 문자열 길이다. 반복 건수는 추출 후 제목과 본문이 정확히 같은 그룹에서 첫 메일을 뺀 추가 건수이며 제거하지 않았다. 공백 정규화 기준의 추가 중복 수와 중복 그룹 수는 `summary.json`에 별도 기록했다. 이 수치는 원본 바이트 중복 또는 유사 캠페인 수와 다르다.', '',
        '## 파싱 정책과 누락·경고', '',
        'Python 표준 라이브러리 email, mailbox, tarfile, HTMLParser를 사용했다. multipart/alternative에서는 비어 있지 않은 plain을 우선하고 없으면 HTML의 텍스트를 사용한다. HTML 대체 버전의 href는 별도로 수집하되 같은 본문을 두 번 이어 붙이지 않는다. multipart/mixed의 서로 다른 본문 조각은 유지한다. 첨부·파일명이 있는 파트·첨부 message/rfc822는 제외한다. HTML 스크립트·스타일·head는 본문에서 제외하고 HTML 실행이나 이미지 로딩을 하지 않는다.', '',
        '본문 표시 URL은 `body_urls`, HTML a/area href 목적지는 `html_hrefs`로 분리했다. href를 클릭하거나 URL을 정규화·리디렉션 조회하지 않는다. URL 없는 메일도 유지한다. 잘못된 인코딩은 원래 charset 실패와 fallback을 경고로 남기고 MIME·헤더 결함도 수집한다. 파서가 복구해서 읽은 메일은 성공+경고이며, 예외로 읽지 못한 메일만 실패다.', '',
        '`data/email/processed/issues.json`에 메시지 원본 위치·누락 이유·경고·실패 이유를 남겼다. 해당 파일도 메일 내용을 포함하므로 Git 제외 대상이다. 원본 파일은 덮어쓰지 않으며 재실행 시 manifest의 해시와 일치하는지 확인한다.', '',
    ]
    for s in stats:
        lines.append(f"- **{s['group']}**: 경고가 있는 메일 {s['messages_with_warnings']}개. 경고 종류와 메일별 발생 수: `{json.dumps(s['warning_counts'], ensure_ascii=False)}`.")
    lines += ['', '## 출처 노출 가능성', '',
        '아래는 헤더 이름이나 알려진 고정 마커가 포함된 메일 수이며, 값·이메일 주소·실제 링크는 공개하지 않는다. 마커 존재는 본문 의미와 무관하게 출처를 학습할 가능성을 뜻하며 실제 분류 영향은 아직 측정하지 않았다. 원본 헤더는 보존하지만 현재 모델 학습은 하지 않는다.', '']
    for s in stats:
        markers = ', '.join(f'{k}: {v}' for k, v in s['marker_message_counts'].items())
        notable = {k: v for k, v in s['header_message_counts'].items() if k.startswith(('x-spam', 'list-', 'x-mailer', 'x-beenthere'))}
        repeats = s['repeated_line_counts_and_hashes']
        top = repeats[0]['message_count'] if repeats else 0
        lines += [f"- **{s['group']}**: 고정 마커(헤더·본문 전체 바이트 검색) `{markers}`. 주요 헤더 이름별 메일 수 `{json.dumps(notable, ensure_ascii=False)}`. 길이 20자 이상 동일 본문 행의 최다 반복은 {top}개 메일에서 관찰했다."]
    lines += ['',
        '반복 문구의 원문은 개인정보 노출을 피하기 위해 보고서에 인용하지 않았다. 집계에는 문구의 SHA-256과 빈도만 남겼고, 실제 문구 검토용 자료는 Git 제외된 `*_repeated_lines.json`에만 있다. 보고서에는 실제 메일 발췌·개인정보·메일 내부 링크를 싣지 않았다. 위 공식 출처 링크는 수집 근거 문서다.', '',
        '## 보존·재현', '',
        '루트 `.gitignore`의 `/data/email/` 규칙으로 원본과 모든 행 단위 추출·오류 자료를 제외했다. 현재 루트는 Git 저장소가 아니며, 저장소 초기화·커밋은 하지 않았다. 별도 전달 저장소의 Git 디렉터리를 읽기 전용으로 사용해 루트 작업 트리에 대한 `check-ignore --no-index` 판정을 확인했다. 전달 저장소 자체에는 메일 자료를 복사하지 않았다.', '',
        '기존 URL 프로젝트의 데이터·모델·학습 스크립트·보고서·handoff 등 316개 보호 파일은 이전 보존 해시 기록과 일치한다. 상세는 [url_v1_preservation.json](url_v1_preservation.json)에 있다. 점수 계산을 위해 모델을 로드하지 않았다.', '',
        '```powershell',
        "Set-Location 'C:\\Users\\user\\Desktop\\phishing-detector'",
        '.\\.venv\\Scripts\\python.exe -X utf8 .\\email_intake_v1.py',
        '.\\.venv\\Scripts\\python.exe -X utf8 -m unittest test_email_intake_v1.py',
        '```', '',
        '첫 명령은 이미 받은 원본만 로컬에서 다시 점검하고 추출·보고서를 갱신한다. 다운로드가 필요할 때만 `--download`를 붙인다. 큰 응답의 전송 정지가 발생한 환경에서는 `--download --curl`로 지정된 같은 세 파일의 HTTP 범위를 나누어 받는다. 패키지 설치는 필요 없다.', '',
        '## 학습 전에 더 필요한 자료', '',
        '- 출처·연도 차이가 정답의 지름길이 되지 않도록 같은 시기·비슷한 수집 환경의 피싱과 정상 메일. 현재는 2021 피싱과 2003 배포 정상 메일의 차이가 크다.',
        '- 한국어를 대상으로 한다면 한국어 정상·피싱을 함께 포함한 독립 자료와 언어별 실제 분포 점검. 이번에는 언어를 자동 판정하지 않았다.',
        '- URL 없는 피싱, 정상 알림·인증·청구 메일, HTML 정상 메일 등 어려운 대조 집단과 별도 수작업 검토. ham은 현재 웹 링크 안전성의 보증이 아니다.',
        '- 메일 피싱 라벨의 재검토 기준과 별도의 URL 단위 정답. 일반 스팸은 피싱과 분리해야 한다.',
        '- 정확·유사 중복, 전달/회신 스레드, 캠페인·도메인 겹침, 출처 마커 누출을 확인한 뒤 평가 설계. 이번에는 train/test 분리하지 않았다.',
        '- SpamAssassin 이용·재배포 범위 추가 확인 및 개인정보 취급 기준. 원본과 행 단위 자료의 공개는 이번 작업 범위에 없다.', '',
    ]
    (REPORT / 'report_ko.md').write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--download', action='store_true', help='Fetch exactly the three allowlisted originals if absent')
    parser.add_argument('--curl', action='store_true', help='Use Windows curl transport if urllib stalls')
    args = parser.parse_args()
    REPORT.mkdir(parents=True, exist_ok=True)
    if args.download:
        download(args.curl)
    stats = inspect()
    write_report(stats)
    print(json.dumps([{k: v for k, v in s.items() if k not in ('header_message_counts', 'repeated_line_counts_and_hashes')} for s in stats], ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
