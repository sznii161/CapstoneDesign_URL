const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

export function analyzeUrl(rawInput) {
  const input = String(rawInput ?? "").trim();
  if (!input) throw new Error("검사할 URL을 입력해 주세요.");

  const withProtocol = /^[a-z][a-z\d+.-]*:\/\//i.test(input)
    ? input
    : `https://${input}`;

  let url;
  try {
    url = new URL(withProtocol);
  } catch {
    throw new Error("올바른 URL 형식으로 입력해 주세요.");
  }
  if (!HTTP_PROTOCOLS.has(url.protocol) || !url.hostname) {
    throw new Error("http 또는 https 웹 주소만 검사할 수 있습니다.");
  }

  const hostname = url.hostname.toLowerCase();
  const labels = hostname.split(".").filter(Boolean);
  const signals = [];

  if (url.username || url.password) {
    signals.push("주소에 @ 앞쪽 사용자 정보가 있어 실제 접속 도메인을 혼동할 수 있습니다.");
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":")) {
    signals.push("일반 도메인 이름 대신 IP 주소를 사용합니다.");
  }
  if (hostname.includes("xn--")) {
    signals.push("국제화 도메인의 변환 표기(xn--)가 포함되어 있습니다.");
  }
  if ((hostname.match(/-/g) ?? []).length >= 2) {
    signals.push("도메인에 하이픈(-)이 여러 개 포함되어 있습니다.");
  }
  if (labels.length >= 5) {
    signals.push("하위 도메인 단계가 많아 실제 등록 도메인을 확인할 필요가 있습니다.");
  }
  if (url.href.length >= 100) {
    signals.push("URL이 길어 주소 전체를 살펴볼 필요가 있습니다.");
  }

  const level = signals.length >= 2 ? "alert" : signals.length === 1 ? "watch" : "neutral";
  const headline = signals.length
    ? `URL 구조 주의 신호 ${signals.length}개`
    : "뚜렷한 URL 구조 신호 없음";

  return {
    url: url.origin,
    hostname,
    level,
    headline,
    signals,
    checkedAt: new Date().toISOString()
  };
}

export function analyzeEmail(titleInput, bodyInput) {
  const title = String(titleInput ?? "").trim();
  const body = String(bodyInput ?? "").trim();
  if (!title && !body) throw new Error("이메일 제목이나 본문을 입력해 주세요.");

  const combined = `${title}\n${body}`;
  const links = [...combined.matchAll(/https?:\/\/[^\s<>"']+/gi)]
    .map((match) => match[0].replace(/[),.;!?]+$/, ""));
  const signals = [];

  if (/(긴급|즉시|오늘\s*안에|계정\s*정지|사용\s*중지|24시간\s*이내)/i.test(combined)) {
    signals.push("서둘러 행동하도록 요구하는 문구가 있습니다.");
  }
  if (/(비밀번호|인증번호|계정\s*확인|본인\s*확인|로그인)/i.test(combined)) {
    signals.push("로그인 또는 계정 정보 입력을 요청하는 문구가 있습니다.");
  }
  if (links.length) {
    signals.push(`본문에 웹 링크 ${links.length}개가 있습니다. 클릭 전에 실제 도메인을 확인하세요.`);
  }

  let unusualLinkCount = 0;
  for (const link of links) {
    try {
      if (analyzeUrl(link).signals.length > 0) unusualLinkCount += 1;
    } catch {
      // URL 구문 오류만으로 피싱 여부를 단정하지 않습니다.
    }
  }
  if (unusualLinkCount) {
    signals.push(`포함된 링크 ${unusualLinkCount}개에서 URL 구조 주의 신호가 보입니다.`);
  }

  const level = signals.length >= 3 ? "alert" : signals.length ? "watch" : "neutral";
  return {
    level,
    headline: signals.length ? `이메일 문구·링크 신호 ${signals.length}개` : "뚜렷한 문구·링크 신호 없음",
    signals,
    linkCount: links.length
  };
}
