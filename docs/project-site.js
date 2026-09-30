const languageButtons = document.querySelectorAll("[data-language]");
const description = document.querySelector('meta[name="description"]');

const pageCopy = {
  en: {
    title: "ai-security-scanner · Many security tools, one clear report",
    description: "Use the desktop app or Claude Code and Codex Agent Skills for upstream security checks and one standardized report. Linux, macOS and Windows candidate installers; public release on HOLD.",
  },
  "zh-TW": {
    title: "ai-security-scanner · 多種安全工具，一份清楚報告",
    description: "透過桌面程式或 Claude Code／Codex Agent Skills 執行上游安全檢查，閱讀一份標準化報告。候選安裝檔涵蓋 Linux、macOS、Windows；公開發布維持 HOLD。",
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
