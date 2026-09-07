import { useEffect, useState, type ReactNode } from "react";

import { Icon } from "../components/Icon";
import {
  DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  parseLocalhostQuickScanPort,
} from "../localhostQuickScan";
import {
  useCaseDefinitions,
  type StartPageCopy,
  type UseCaseDefinition,
  type UseCaseId,
} from "../useCases";

import "../start-page.css";

interface StartPageProps {
  locale: "en" | "zh-TW";
  copy: StartPageCopy;
  setup?: ReactNode;
  setupFocusKey?: number;
  nativeMode: boolean;
  localhostQuickScanBusy?: boolean;
  onStartLocalhostQuickScan: (port: number) => void;
  onChoose: (useCase: UseCaseDefinition) => void;
  onOpenExistingCase?: () => void;
}

interface MarketingCopy {
  title: string;
  description: string;
  previewDescription: string;
  localhostQuickScanAction: string;
  localhostQuickScanBusy: string;
  localhostQuickScanBoundary: string;
  localhostQuickScanOptions: string;
  localhostQuickScanPortLabel: string;
  localhostQuickScanPortHelp: string;
  localhostQuickScanPortError: string;
  choiceTitle: string;
  choiceDescription: string;
  cardDetails: string;
  moreWaysTitle: string;
  moreWaysDescription: string;
  controlSummary: string;
  cards: Record<UseCaseId, { outcome: string; action: string }>;
}

const marketingCopy: Record<"en" | "zh-TW", MarketingCopy> = {
  en: {
    title: "Start a security check",
    description: "Run a quick localhost check, or choose another target below.",
    previewDescription: "Choose a target below to preview the scan setup.",
    localhostQuickScanAction: "Check this computer · 127.0.0.1:9001",
    localhostQuickScanBusy: "Starting this check…",
    localhostQuickScanBoundary:
      "One TCP connection to 127.0.0.1:9001; no payload; up to 3 seconds. This is not a security guarantee.",
    localhostQuickScanOptions: "Use a different local port",
    localhostQuickScanPortLabel: "Local port",
    localhostQuickScanPortHelp: "Enter a port from 1 to 65535.",
    localhostQuickScanPortError: "Enter a whole-number port from 1 to 65535.",
    choiceTitle: "What do you want to protect first?",
    choiceDescription: "Choose the closest match. You can add more checks later.",
    cardDetails: "See what’s included",
    moreWaysTitle: "More ways to scan",
    moreWaysDescription: "Source code, cloud accounts, infrastructure code, containers, and Kubernetes",
    controlSummary: "How scanning stays under your control",
    cards: {
      deployed_website: {
        outcome: "Catch common website and API weaknesses before they turn into incidents.",
        action: "Check a website",
      },
      external_ip_or_domain: {
        outcome: "See the services your organization exposes to the public Internet.",
        action: "Check public exposure",
      },
      internal_it_environment: {
        outcome: "Spot weaknesses and risky settings across your approved internal systems.",
        action: "Check internal systems",
      },
      ai_application: {
        outcome: "Catch risky AI-generated code, exposed secrets, and vulnerable dependencies before they ship.",
        action: "Check an AI project",
      },
      source_code: {
        outcome: "Check source code locally for risky patterns and exposed secrets.",
        action: "Check my code",
      },
      infrastructure_as_code: {
        outcome: "Find risky cloud and deployment settings before they go live.",
        action: "Check infrastructure code",
      },
      cloud_account: {
        outcome: "Turn cloud assets, identity, and security settings into a prioritized fix list.",
        action: "Check a cloud account",
      },
      container_image: {
        outcome: "Know what is inside an image and which known vulnerabilities need attention.",
        action: "Check a container image",
      },
      kubernetes: {
        outcome: "Find workload and node settings that leave your Kubernetes environment exposed.",
        action: "Check Kubernetes",
      },
    },
  },
  "zh-TW": {
    title: "開始資安檢查",
    description: "先快速檢查 localhost，或在下方選擇其他目標。",
    previewDescription: "在下方選擇目標，預覽掃描設定流程。",
    localhostQuickScanAction: "檢查這台電腦 · 127.0.0.1:9001",
    localhostQuickScanBusy: "正在開始檢查…",
    localhostQuickScanBoundary:
      "只會嘗試一次到 127.0.0.1:9001 的 TCP 連線；不會傳送內容；最長等待 3 秒。這不代表這台電腦一定安全。",
    localhostQuickScanOptions: "改用其他本機連接埠",
    localhostQuickScanPortLabel: "本機連接埠",
    localhostQuickScanPortHelp: "請輸入 1 到 65535 的連接埠。",
    localhostQuickScanPortError: "請輸入 1 到 65535 的整數連接埠。",
    choiceTitle: "你想先保護哪裡？",
    choiceDescription: "選一個最接近的項目就好，其他檢查之後都能再加入。",
    cardDetails: "查看包含哪些檢查",
    moreWaysTitle: "更多檢查方式",
    moreWaysDescription: "一般程式碼、雲端帳號、基礎設施程式碼、容器映像與 Kubernetes",
    controlSummary: "了解掃描如何由你控制",
    cards: {
      deployed_website: {
        outcome: "在問題變成事故前，找出網站與 API 的常見弱點。",
        action: "檢查網站",
      },
      external_ip_or_domain: {
        outcome: "看清楚你的組織在公開網路上暴露了哪些服務。",
        action: "檢查對外暴露面",
      },
      internal_it_environment: {
        outcome: "找出核准內部系統的弱點與高風險設定。",
        action: "檢查內部系統",
      },
      ai_application: {
        outcome: "在上線前抓出 AI 生成程式碼的危險寫法、暴露秘密與有弱點的相依套件。",
        action: "檢查 AI 專案",
      },
      source_code: {
        outcome: "在本機檢查程式碼，找出危險寫法與暴露的秘密。",
        action: "檢查我的程式碼",
      },
      infrastructure_as_code: {
        outcome: "在部署前找出雲端與基礎設施設定裡的風險。",
        action: "檢查基礎設施程式碼",
      },
      cloud_account: {
        outcome: "把雲端資產、身分與安全設定整理成有優先順序的改善清單。",
        action: "檢查雲端帳號",
      },
      container_image: {
        outcome: "看懂映像裡有哪些套件，以及哪些已知弱點需要先修。",
        action: "檢查容器映像",
      },
      kubernetes: {
        outcome: "找出讓 Kubernetes 工作負載與節點暴露風險的設定。",
        action: "檢查 Kubernetes",
      },
    },
  },
};

export function StartPage({
  locale,
  copy,
  setup,
  setupFocusKey,
  nativeMode,
  localhostQuickScanBusy = false,
  onStartLocalhostQuickScan,
  onChoose,
  onOpenExistingCase,
}: StartPageProps) {
  const marketing = marketingCopy[locale];
  const primaryUseCases = useCaseDefinitions.slice(0, 4);
  const additionalUseCases = useCaseDefinitions.slice(4);
  const [localhostPortInput, setLocalhostPortInput] = useState(String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT));
  const localhostPort = parseLocalhostQuickScanPort(localhostPortInput);
  const localhostPortDisplay = localhostPortInput.trim() || "—";
  const localhostQuickScanAction = marketing.localhostQuickScanAction.replace(
    String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT),
    localhostPortDisplay,
  );
  const localhostQuickScanBoundary = marketing.localhostQuickScanBoundary.replace(
    String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT),
    localhostPortDisplay,
  );

  useEffect(() => {
    if (!setupFocusKey) return undefined;
    const frame = window.requestAnimationFrame(() => {
      const setupSection = document.getElementById("start-page-runtime-setup");
      setupSection?.focus({ preventScroll: true });
      setupSection?.scrollIntoView({ block: "start" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [setupFocusKey]);

  const renderUseCaseCard = (useCase: UseCaseDefinition) => {
    const card = copy.cards[useCase.id];
    const marketingCard = marketing.cards[useCase.id];
    return (
      <article className="use-case-card" key={useCase.id}>
        <header className="use-case-card__header">
          <span className="use-case-card__icon">
            <Icon name={useCase.icon} size={22} />
          </span>
          <div>
            <h3>{card.title}</h3>
            <p>{marketingCard.outcome}</p>
          </div>
        </header>

        <button
          className="button button--secondary use-case-card__action"
          type="button"
          onClick={() => onChoose(useCase)}
        >
          {marketingCard.action}
          <Icon name="arrow" size={17} />
        </button>

        <details className="use-case-card__more">
          <summary>{marketing.cardDetails}</summary>
          <dl className="use-case-card__details">
            <div>
              <dt>{copy.wantLabel}</dt>
              <dd>{card.want}</dd>
            </div>
            <div>
              <dt>{copy.prepareLabel}</dt>
              <dd>{card.prepare}</dd>
            </div>
            <div className="use-case-card__does">
              <dt><Icon name="check" size={15} /> {copy.productDoesLabel}</dt>
              <dd>{card.productDoes}</dd>
            </div>
            <div className="use-case-card__does-not">
              <dt><Icon name="close" size={15} /> {copy.productDoesNotLabel}</dt>
              <dd>{card.productDoesNot}</dd>
            </div>
          </dl>
        </details>
      </article>
    );
  };

  return (
    <div className="page start-page">
      <section className="start-page__hero" aria-labelledby="start-page-title">
        <div className="start-page__hero-copy">
          <h1 id="start-page-title" data-page-heading tabIndex={-1}>{marketing.title}</h1>
          <p className="start-page__hero-description">{nativeMode ? marketing.description : marketing.previewDescription}</p>
          <div className="start-page__hero-actions">
            {nativeMode && (
              <div className="start-page__localhost-quick-scan">
                <button
                  className="button button--primary start-page__primary-action"
                  type="button"
                  disabled={localhostQuickScanBusy || localhostPort === undefined}
                  aria-busy={localhostQuickScanBusy}
                  onClick={() => {
                    if (localhostPort !== undefined) onStartLocalhostQuickScan(localhostPort);
                  }}
                >
                  {localhostQuickScanBusy ? marketing.localhostQuickScanBusy : localhostQuickScanAction}
                  <Icon name="arrow" size={18} />
                </button>
                <p className="start-page__localhost-boundary">{localhostQuickScanBoundary}</p>
                <details className="start-page__localhost-options">
                  <summary>{marketing.localhostQuickScanOptions}</summary>
                  <label htmlFor="localhost-quick-scan-port">{marketing.localhostQuickScanPortLabel}</label>
                  <input
                    id="localhost-quick-scan-port"
                    type="number"
                    inputMode="numeric"
                    min={1}
                    max={65535}
                    step={1}
                    required
                    value={localhostPortInput}
                    aria-invalid={localhostPort === undefined}
                    aria-describedby="localhost-quick-scan-port-help"
                    onChange={(event) => setLocalhostPortInput(event.currentTarget.value)}
                  />
                  <small
                    id="localhost-quick-scan-port-help"
                    className={localhostPort === undefined ? "start-page__localhost-port-error" : undefined}
                    aria-live="polite"
                    aria-atomic="true"
                  >
                    {localhostPort === undefined
                      ? marketing.localhostQuickScanPortError
                      : marketing.localhostQuickScanPortHelp}
                  </small>
                </details>
              </div>
            )}
            {onOpenExistingCase && (
              <div className="start-page__hero-secondary-actions">
                <button className="button button--secondary" type="button" onClick={onOpenExistingCase}>
                  <Icon name="cases" size={18} />
                  {copy.existingCaseAction}
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      <section id="start-a-check" className="start-page__choices" aria-labelledby="use-case-choice-title">
        <div className="start-page__section-heading">
          <h2 id="use-case-choice-title">{marketing.choiceTitle}</h2>
          <p>{marketing.choiceDescription}</p>
        </div>

        <div className="use-case-grid">
          {primaryUseCases.map(renderUseCaseCard)}
        </div>

        <details className="start-page__more-use-cases">
          <summary>
            <span>
              <strong>{marketing.moreWaysTitle}</strong>
              <small>{marketing.moreWaysDescription}</small>
            </span>
            <Icon name="chevron" size={20} />
          </summary>
          <div className="use-case-grid">
            {additionalUseCases.map(renderUseCaseCard)}
          </div>
        </details>
      </section>

      {setup && (
        <aside id="start-page-runtime-setup" className="start-page__setup" tabIndex={-1}>
          {setup}
        </aside>
      )}

      <details className="start-page__scope-note">
        <summary>
          <Icon name="info" size={19} />
          {marketing.controlSummary}
        </summary>
        <div>
          <strong>{copy.scopeNoticeTitle}</strong>
          <p>{copy.scopeNotice}</p>
        </div>
      </details>
    </div>
  );
}
