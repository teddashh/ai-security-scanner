const languageButtons = document.querySelectorAll("[data-language]");
const description = document.querySelector('meta[name="description"]');

const pageCopy = {
  en: {
    title: "ai-security-scanner · Many security tools, one clear report",
    description: "Use the desktop app or Claude Code and Codex Agent Skills for upstream security checks and one standardized report. Download the v0.4.0 stable release for Linux, macOS and Windows.",
  },
  "zh-TW": {
    title: "ai-security-scanner · 多種安全工具，一份清楚報告",
    description: "透過桌面程式或 Claude Code／Codex Agent Skills 執行上游安全檢查，閱讀一份標準化報告。下載 Linux、macOS、Windows 的 v0.4.0 正式版。",
  },
};

const applyLanguage = (language, updateUrl = true) => {
  const selected = language === "zh-TW" ? "zh-TW" : "en";
  document.documentElement.dataset.lang = selected;
  document.documentElement.lang = selected === "zh-TW" ? "zh-Hant" : "en";
  const titleElement = document.querySelector("title");
  const title = (selected === "zh-TW" ? titleElement?.dataset.zh : titleElement?.dataset.en) || pageCopy[selected].title;
  const summary = (selected === "zh-TW" ? description?.dataset.zh : description?.dataset.en) || pageCopy[selected].description;
  document.title = title;
  description?.setAttribute("content", summary);
  document.querySelector('meta[property="og:title"]')?.setAttribute("content", title);
  document.querySelector('meta[property="og:description"]')?.setAttribute("content", summary);
  document.querySelector('meta[property="og:locale"]')?.setAttribute("content", selected === "zh-TW" ? "zh_TW" : "en_US");
  for (const link of document.querySelectorAll("a[data-href-en][data-href-zh]")) {
    link.href = selected === "zh-TW" ? link.dataset.hrefZh : link.dataset.hrefEn;
  }

  for (const button of languageButtons) {
    button.setAttribute("aria-pressed", String(button.dataset.language === selected));
  }

  document.dispatchEvent(new Event("site-language-change"));

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
