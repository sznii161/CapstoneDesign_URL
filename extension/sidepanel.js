const $ = (id) => document.getElementById(id);

function render(result) {
  if (!result) return;
  document.querySelector(".result-section").dataset.level = result.level;
  $("detail-headline").textContent = result.headline;
  const kind = result.level === "neutral" ? "sunflower" : "brown";
  const alertMark = result.level === "alert" ? " mascot-alert" : "";
  $("detail-mascot").className = `detail-mascot mascot-${kind}${alertMark}`;
  $("detail-url").textContent = result.url;
  $("detail-signals").replaceChildren();
  const signals = result.signals.length
    ? result.signals
    : ["뚜렷한 구조 신호는 없지만 정상 사이트로 확인된 것은 아닙니다."];
  for (const signal of signals) {
    const item = document.createElement("li");
    item.textContent = signal;
    $("detail-signals").append(item);
  }
}

chrome.storage.session.get("lastUrlAnalysis").then(({ lastUrlAnalysis }) => render(lastUrlAnalysis));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.lastUrlAnalysis) {
    render(changes.lastUrlAnalysis.newValue);
  }
});
