import { useEffect, type ReactNode } from "react";

import { Icon } from "../components/Icon";
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
  onChoose: (useCase: UseCaseDefinition) => void;
  onOpenExistingCase?: () => void;
}

interface MarketingCopy {
  eyebrow: string;
  title: string;
  description: string;
  primaryAction: string;
  benefitsTitle: string;
  benefits: readonly {
    icon: "spark" | "check" | "lock";
    title: string;
    description: string;
  }[];
  journeyEyebrow: string;
  journeyTitle: string;
  journeyDescription: string;
  journeySteps: readonly {
    title: string;
    description: string;
  }[];
  choiceEyebrow: string;
  choiceTitle: string;
  choiceDescription: string;
  cardDetails: string;
  moreWaysTitle: string;
  moreWaysDescription: string;
  setupEyebrow: string;
  setupTitle: string;
  setupDescription: string;
  controlSummary: string;
  cards: Record<UseCaseId, { outcome: string; action: string }>;
}

const marketingCopy: Record<"en" | "zh-TW", MarketingCopy> = {
  en: {
    eyebrow: "Security checks, made usable",
    title: "Find the risks that matter—without juggling security tools.",
    description:
      "Choose what you want to protect. AI Security Scanner brings the right checks together and turns the results into one clear, prioritized action list.",
    primaryAction: "Start a security check",
    benefitsTitle: "What you get",
    benefits: [
      {
        icon: "spark",
        title: "One place for every check",
        description: "Web, infrastructure, cloud, code, containers, and Kubernetes work together.",
      },
      {
        icon: "check",
        title: "Answers you can act on",
        description: "See what matters first, why it matters, and where to fix it.",
      },
      {
        icon: "lock",
        title: "Your data stays with you",
        description: "Keep your scan projects and sensitive evidence on your computer.",
      },
    ],
    journeyEyebrow: "How it works",
    journeyTitle: "From “what should I check?” to a focused fix list.",
    journeyDescription: "You choose the goal. The app guides the setup and organizes the results.",
    journeySteps: [
      {
        title: "Pick what to protect",
        description: "Start with the website, system, code, or account you care about.",
      },
      {
        title: "Follow the guided check",
        description: "Provide only the few details needed for that check.",
      },
      {
        title: "Fix what matters first",
        description: "Review one prioritized list with clear next steps.",
      },
    ],
    choiceEyebrow: "Start here",
    choiceTitle: "What do you want to protect first?",
    choiceDescription: "Choose the closest match. You can add more checks later.",
    cardDetails: "See what’s included",
    moreWaysTitle: "More ways to scan",
    moreWaysDescription: "Cloud accounts, infrastructure code, container images, and Kubernetes",
    setupEyebrow: "One-time setup",
    setupTitle: "Get the scan tools ready",
    setupDescription: "Set it up once, then reuse it for every kind of check.",
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
      source_code: {
        outcome: "Catch risky code and exposed secrets before the next release.",
        action: "Check source code",
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
    eyebrow: "資安檢查，終於可以很簡單",
    title: "找出真正重要的風險，不必自己拼湊一堆工具。",
    description:
      "選擇你想保護的地方。AI Security Scanner 會整合適合的檢查，把結果變成一份清楚、有優先順序的改善清單。",
    primaryAction: "開始資安檢查",
    benefitsTitle: "你會得到",
    benefits: [
      {
        icon: "spark",
        title: "所有檢查集中在一起",
        description: "網站、IT、雲端、程式碼、容器與 Kubernetes 都能在同一處完成。",
      },
      {
        icon: "check",
        title: "一看就知道先修哪裡",
        description: "看懂問題、優先順序，以及下一步該怎麼做。",
      },
      {
        icon: "lock",
        title: "資料留在自己的電腦",
        description: "掃描專案與敏感證據都由你保管，不必交給另一個雲端平台。",
      },
    ],
    journeyEyebrow: "怎麼使用",
    journeyTitle: "從「該檢查什麼？」到一份能直接處理的清單。",
    journeyDescription: "你只要選擇目標，設定與結果整理交給產品引導。",
    journeySteps: [
      {
        title: "選擇要保護的地方",
        description: "從你最在意的網站、系統、程式碼或帳號開始。",
      },
      {
        title: "跟著畫面完成檢查",
        description: "只提供這次檢查真正需要的少量資料。",
      },
      {
        title: "先處理最重要的問題",
        description: "從一份有優先順序的清單開始改善。",
      },
    ],
    choiceEyebrow: "從這裡開始",
    choiceTitle: "你想先保護哪裡？",
    choiceDescription: "選一個最接近的項目就好，其他檢查之後都能再加入。",
    cardDetails: "查看包含哪些檢查",
    moreWaysTitle: "更多檢查方式",
    moreWaysDescription: "雲端帳號、基礎設施程式碼、容器映像與 Kubernetes",
    setupEyebrow: "只需設定一次",
    setupTitle: "準備好掃描工具",
    setupDescription: "完成一次設定，之後每種檢查都能直接使用。",
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
      source_code: {
        outcome: "在上線前抓出危險寫法與不小心放進程式碼的秘密。",
        action: "檢查程式碼",
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

export function StartPage({ locale, copy, setup, setupFocusKey, onChoose, onOpenExistingCase }: StartPageProps) {
  const marketing = marketingCopy[locale];
  const primaryUseCases = useCaseDefinitions.slice(0, 4);
  const additionalUseCases = useCaseDefinitions.slice(4);

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
          className="button button--primary use-case-card__action"
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
          <p className="eyebrow">{marketing.eyebrow}</p>
          <h1 id="start-page-title">{marketing.title}</h1>
          <p className="start-page__hero-description">{marketing.description}</p>
          <div className="start-page__hero-actions">
            <a className="button button--primary start-page__primary-action" href="#start-a-check">
              {marketing.primaryAction}
              <Icon name="arrow" size={18} />
            </a>
            {onOpenExistingCase && (
              <button className="button button--secondary" type="button" onClick={onOpenExistingCase}>
                <Icon name="cases" size={18} />
                {copy.existingCaseAction}
              </button>
            )}
          </div>
        </div>

        <aside className="start-page__benefits" aria-label={marketing.benefitsTitle}>
          <p className="eyebrow">{marketing.benefitsTitle}</p>
          <ul>
            {marketing.benefits.map((benefit) => (
              <li key={benefit.title}>
                <span><Icon name={benefit.icon} size={20} /></span>
                <div>
                  <strong>{benefit.title}</strong>
                  <p>{benefit.description}</p>
                </div>
              </li>
            ))}
          </ul>
        </aside>
      </section>

      <section className="start-page__journey" aria-labelledby="start-page-journey-title">
        <header>
          <p className="eyebrow">{marketing.journeyEyebrow}</p>
          <h2 id="start-page-journey-title">{marketing.journeyTitle}</h2>
          <p>{marketing.journeyDescription}</p>
        </header>
        <ol>
          {marketing.journeySteps.map((step, index) => (
            <li key={step.title}>
              <span className="start-page__step-number">{index + 1}</span>
              <div>
                <strong>{step.title}</strong>
                <p>{step.description}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section id="start-a-check" className="start-page__choices" aria-labelledby="use-case-choice-title">
        <div className="start-page__section-heading">
          <p className="eyebrow">{marketing.choiceEyebrow}</p>
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
        <section id="start-page-runtime-setup" className="start-page__setup" tabIndex={-1} aria-labelledby="start-page-setup-title">
          <header className="start-page__section-heading">
            <p className="eyebrow">{marketing.setupEyebrow}</p>
            <h2 id="start-page-setup-title">{marketing.setupTitle}</h2>
            <p>{marketing.setupDescription}</p>
          </header>
          {setup}
        </section>
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
