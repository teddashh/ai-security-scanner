const languageButtons = document.querySelectorAll("[data-language]");
const description = document.querySelector('meta[name="description"]');

const pageCopy = {
  en: {
    title: "ai-security-scanner — Many security tools, one clear report",
    description: "Run applicable open-source security checks across repositories, websites, internal systems, cloud, containers, and Kubernetes, then read one prioritized report.",
  },
  "zh-TW": {
    title: "ai-security-scanner — 多種安全工具，一份清楚報告",
    description: "針對程式碼專案、網站、內部系統、雲端、容器與 Kubernetes 執行適用的開源安全檢查，再閱讀一份排好優先順序的報告。",
  },
};

const applyLanguage = (language, updateUrl = true) => {
  const selected = language === "zh-TW" ? "zh-TW" : "en";
  document.documentElement.dataset.lang = selected;
  document.documentElement.lang = selected === "zh-TW" ? "zh-Hant" : "en";
  document.title = pageCopy[selected].title;
  description?.setAttribute("content", pageCopy[selected].description);

  for (const button of languageButtons) {
    button.setAttribute("aria-pressed", String(button.dataset.language === selected));
  }

  if (updateUrl) {
    const url = new URL(window.location.href);
    if (selected === "zh-TW") url.searchParams.set("lang", "zh-TW");
    else url.searchParams.delete("lang");
    window.history.replaceState({}, "", url);
  }
};

for (const button of languageButtons) {
  button.addEventListener("click", () => applyLanguage(button.dataset.language));
}

applyLanguage(document.documentElement.dataset.lang, false);
