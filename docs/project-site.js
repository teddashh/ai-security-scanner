const languageButtons = document.querySelectorAll("[data-language]");
const description = document.querySelector('meta[name="description"]');

const pageCopy = {
  en: {
    title: "ai-security-scanner · Find security problems. Know what to do next.",
    description: "Check your code, websites and company systems from one desktop app. Read a clear report with priorities and next steps. Available for Windows, macOS and Linux.",
  },
  "zh-TW": {
    title: "ai-security-scanner · 找出安全問題，知道下一步",
    description: "在一個桌面程式裡檢查程式碼、網站與公司系統。看一份報告，了解問題、處理順序與下一步。支援 Windows、macOS 與 Linux。",
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
