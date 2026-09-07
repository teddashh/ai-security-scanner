import { Icon } from "../components/Icon";
import { PageHeader } from "../components/Shared";
import { useI18n, type Locale } from "../i18n";
import { getSettingsRuntimePresentation } from "../settingsRuntimePresentation";

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
}: SettingsPageProps) {
  const { text } = useI18n();
  const runtimePresentation = getSettingsRuntimePresentation(mode, runtimeAvailable);

  return (
    <div className="page page--settings">
      <PageHeader
        title={text({ en: "Settings", zhTW: "設定" })}
        description={text({
          en: "Language, safety, and local scan tools.",
          zhTW: "語言、安全界線與本機掃描工具。",
        })}
      />

      <section className="section-block settings-section" aria-labelledby="settings-language-title">
        <div className="section-heading">
          <h2 id="settings-language-title">{text({ en: "Application language", zhTW: "應用程式語言" })}</h2>
        </div>
        <div className="settings-language-options" role="group" aria-label={text({ en: "Application language", zhTW: "應用程式語言" })}>
          <button
            className={`settings-choice${locale === "en" ? " settings-choice--selected" : ""}`}
            type="button"
            aria-pressed={locale === "en"}
            onClick={() => onLocaleChange("en")}
          >
            <Icon name="check" size={18} />
            <strong>English</strong>
          </button>
          <button
            className={`settings-choice${locale === "zh-TW" ? " settings-choice--selected" : ""}`}
            type="button"
            aria-pressed={locale === "zh-TW"}
            onClick={() => onLocaleChange("zh-TW")}
          >
            <Icon name="check" size={18} />
            <strong>繁體中文</strong>
          </button>
        </div>
      </section>

      <section className="settings-grid" aria-label={text({ en: "Safety and status", zhTW: "安全與狀態" })}>
        <article className="section-block settings-section">
          <span className="settings-section__icon"><Icon name="lock" size={20} /></span>
          <div className="section-heading">
            <h2>{text({ en: "Safety", zhTW: "安全界線" })}</h2>
            <p>{text({
              en: "Projects and evidence stay on this device unless you export them. Scans use only saved, approved targets.",
              zhTW: "專案與證據留在這台裝置，除非你主動匯出；掃描只使用已保存並核准的目標。",
            })}</p>
          </div>
        </article>

        <article className="section-block settings-section">
          <span className="settings-section__icon"><Icon name={runtimePresentation.icon} size={20} /></span>
          <div className="section-heading">
            <h2>{text({ en: "Local tools", zhTW: "本機工具" })}</h2>
            <p>{text(runtimePresentation.status)}</p>
          </div>
        </article>
      </section>

    </div>
  );
}
