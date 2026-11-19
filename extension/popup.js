import { analyzeUrl, analyzeEmail } from "./analysis.mjs";

const $ = (id) => document.getElementById(id);
let activeTabId = null;
let currentPageUrl = null;

function selectTab(selected) {
  for (const [tabId, viewId] of [["url-tab", "url-view"], ["email-tab", "email-view"]]) {
    const active = tabId === selected;
    $(tabId).classList.toggle("active", active);
    $(tabId).setAttribute("aria-selected", String(active));
    $(viewId).hidden = !active;
  }
}

function showError(elementId, message) {
  const element = $(elementId);
  element.textContent = message;
  element.hidden = !message;
}

function renderSignals(list, signals, neutralMessage) {
  list.replaceChildren();
  if (!signals.length) {
    const item = document.createElement("li");
    item.textContent = neutralMessage;
    list.append(item);
    return;
  }
  for (const signal of signals) {
    const item = document.createElement("li");
    item.textContent = signal;
    list.append(item);
  }
}

function showMascot(elementId, level) {
  const kind = level === "neutral" ? "sunflower" : "brown";
  const alertMark = level === "alert" ? " mascot-alert" : "";
  $(elementId).className = `result-mascot mascot-${kind}${alertMark}`;
}

async function inspectUrl(input, source) {
  showError("url-error", "");
  let result;
  try {
    result = analyzeUrl(input);
  } catch (error) {
    $("url-result").hidden = true;
    showError("url-error", error.message);
    return;
  }

  const resultElement = $("url-result");
  if (source === "manual") {
    $("url-error").before(resultElement);
  } else {
    $("current-page-card").after(resultElement);
  }
  $("url-result-source").textContent = source === "manual" ? "직접 입력한 URL 검사 결과" : "현재 페이지 검사 결과";
  resultElement.hidden = false;
  resultElement.dataset.level = result.level;
  $("url-status-icon").textContent = result.level === "neutral" ? "i" : "!";
  $("url-headline").textContent = result.headline;
  $("url-result-host").textContent = result.hostname;
  showMascot("url-mascot", result.level);
  renderSignals($("url-signals"), result.signals, "URL 구조만으로는 정상 여부를 판단할 수 없습니다.");

  try {
    await chrome.storage.session.set({ lastUrlAnalysis: result });
  } catch {
    showError("url-error", "상세 화면에 결과를 전달하지 못했습니다. 확장을 새로고침해 주세요.");
  }
}

async function loadCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTabId = tab?.id ?? null;
    if (!tab?.url || !/^https?:\/\//i.test(tab.url)) {
      $("current-host").textContent = "이 탭의 웹 주소는 검사할 수 없습니다";
      $("current-url").textContent = "아래에 URL을 직접 입력해 주세요.";
      return;
    }
    currentPageUrl = tab.url;
    $("current-host").textContent = new URL(tab.url).hostname;
    $("current-url").textContent = tab.url;
    $("check-current").disabled = false;
    await inspectUrl(tab.url, "current");
  } catch {
    $("current-host").textContent = "현재 페이지 주소를 읽지 못했습니다";
    $("current-url").textContent = "URL을 직접 입력해 주세요.";
  }
}

$("url-tab").addEventListener("click", () => selectTab("url-tab"));
$("email-tab").addEventListener("click", () => selectTab("email-tab"));
$("check-current").addEventListener("click", () => {
  if (currentPageUrl) inspectUrl(currentPageUrl, "current");
});
$("url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  inspectUrl($("url-input").value, "manual");
});
$("fill-demo").addEventListener("click", () => {
  $("url-input").value = "https://secure.account.verify.nuri-bank-login.example/confirm";
  inspectUrl($("url-input").value, "manual");
});
$("fill-email-demo").addEventListener("click", () => {
  $("email-title").value = "긴급 계정 확인 안내";
  $("email-body").value = "24시간 이내에 계정을 확인해 주세요. 아래 주소에서 로그인해 주세요.\nhttps://secure.account.verify.nuri-bank-login.example/confirm";
  $("email-form").requestSubmit();
});
$("open-detail").addEventListener("click", () => {
  if (activeTabId === null) {
    showError("url-error", "상세 화면을 열려면 일반 웹페이지 탭을 먼저 열어 주세요.");
    return;
  }
  chrome.sidePanel.open({ tabId: activeTabId }).catch(() => {
    showError("url-error", "상세 화면을 열지 못했습니다. 확장을 새로고침해 주세요.");
  });
});
$("email-form").addEventListener("submit", (event) => {
  event.preventDefault();
  showError("email-error", "");
  try {
    const result = analyzeEmail($("email-title").value, $("email-body").value);
    $("email-result").hidden = false;
    $("email-result").dataset.level = result.level;
    $("email-status-icon").textContent = result.level === "neutral" ? "i" : "!";
    $("email-headline").textContent = result.headline;
    showMascot("email-mascot", result.level);
    renderSignals($("email-signals"), result.signals, "이메일 문구만으로는 정상 여부를 판단할 수 없습니다.");
  } catch (error) {
    $("email-result").hidden = true;
    showError("email-error", error.message);
  }
});

loadCurrentTab();
