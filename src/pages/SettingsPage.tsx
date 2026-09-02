import { Icon } from "../components/Icon";
import { PageHeader } from "../components/Shared";
import { useI18n, type Locale } from "../i18n";

import "../settings-page.css";

interface SettingsPageProps {
  locale: Locale;
  mode: "native" | "demo";
  runtimeAvailable?: boolean;
  onLocaleChange: (locale: Locale) => void;
  onOpenNewScan: () => void;
  onOpenProjects: () => void;
}

export function SettingsPage({
  locale,
  mode,
  runtimeAvailable,
  onLocaleChange,
  onOpenNewScan,
  onOpenProjects,
}: SettingsPageProps) {
  const { text } = useI18n();
  const runtimeStatus = mode === "demo"
    ? text({
      en: "Sample mode is active. No real target is being tested.",
      zhTW: "目前是範例模式，不會檢查真實目標。",
    })
    : runtimeAvailable
      ? text({
        en: "Local scan tools were ready at the last check.",
        zhTW: "本機掃描工具在上次檢查時已就緒。",
      })
      : text({
        en: "One or more local scan tools still need automatic preparation. Saved projects and reports remain available.",
        zhTW: "一項或多項本機掃描工具仍需要自動準備；已保存的專案與報告仍可使用。",
      });

  return (
    <div className="page page--settings">
      <PageHeader
        eyebrow={text({ en: "Application settings", zhTW: "應用程式設定" })}
        title={text({ en: "Settings", zhTW: "設定" })}
        description={text({
          en: "Choose the application language and review the safety boundaries that stay in effect for every scan.",
          zhTW: "選擇應用程式語言，並查看每次掃描都會遵守的安全界線。",
        })}
      />

      <section className="section-block settings-section" aria-labelledby="settings-language-title">
        <div className="section-heading">
          <h2 id="settings-language-title">{text({ en: "Application language", zhTW: "應用程式語言" })}</h2>
          <p>{text({
            en: "This changes the interface immediately. Each exported readable report keeps its own explicitly selected language.",
            zhTW: "這會立即更新介面；每份匯出的好讀報告仍保留匯出時明確選擇的語言。",
          })}</p>
        </div>
        <div className="settings-language-options" role="group" aria-label={text({ en: "Application language", zhTW: "應用程式語言" })}>
          <button
            className={`settings-choice${locale === "en" ? " settings-choice--selected" : ""}`}
            type="button"
            aria-pressed={locale === "en"}
            onClick={() => onLocaleChange("en")}
          >
            <Icon name="check" size={18} />
            <span><strong>English</strong><small>English interface</small></span>
          </button>
          <button
            className={`settings-choice${locale === "zh-TW" ? " settings-choice--selected" : ""}`}
            type="button"
            aria-pressed={locale === "zh-TW"}
            onClick={() => onLocaleChange("zh-TW")}
          >
            <Icon name="check" size={18} />
            <span><strong>繁體中文</strong><small>繁體中文介面</small></span>
          </button>
        </div>
      </section>

      <section className="settings-grid" aria-label={text({ en: "Safety and status", zhTW: "安全與狀態" })}>
        <article className="section-block settings-section">
          <span className="settings-section__icon"><Icon name="lock" size={20} /></span>
          <div className="section-heading">
            <h2>{text({ en: "Data and scan boundaries", zhTW: "資料與掃描界線" })}</h2>
            <p>{text({
              en: "Projects and evidence stay on this device unless you choose an export destination. A scan never widens to another target without saved approval.",
              zhTW: "除非你選擇匯出位置，專案與證據會留在這台裝置；掃描不會在沒有保存核准的情況下擴大到其他目標。",
            })}</p>
          </div>
        </article>

        <article className="section-block settings-section">
          <span className="settings-section__icon"><Icon name={runtimeAvailable ? "check" : "settings"} size={20} /></span>
          <div className="section-heading">
            <h2>{text({ en: "Local scan tools", zhTW: "本機掃描工具" })}</h2>
            <p>{runtimeStatus}</p>
          </div>
        </article>
      </section>

      <section className="section-block settings-section settings-section--actions">
        <div className="section-heading">
          <h2>{text({ en: "Continue working", zhTW: "繼續工作" })}</h2>
          <p>{text({
            en: "Opening these pages does not start a scan. You still review and confirm the target before any contact.",
            zhTW: "開啟這些頁面不會開始掃描；在連線任何目標前，你仍需先檢視並確認。",
          })}</p>
        </div>
        <div className="button-group">
          <button className="button button--primary" type="button" onClick={onOpenNewScan}>
            <Icon name="spark" size={17} /> {text({ en: "New scan", zhTW: "開始新掃描" })}
          </button>
          <button className="button button--secondary" type="button" onClick={onOpenProjects}>
            <Icon name="cases" size={17} /> {text({ en: "My scans", zhTW: "我的掃描" })}
          </button>
        </div>
      </section>
    </div>
  );
}
