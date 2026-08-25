import { Icon } from "../components/Icon";
import type { ReactNode } from "react";
import {
  useCaseDefinitions,
  type StartPageCopy,
  type UseCaseDefinition,
} from "../useCases";

import "../start-page.css";

interface StartPageProps {
  copy: StartPageCopy;
  setup?: ReactNode;
  onChoose: (useCase: UseCaseDefinition) => void;
  onOpenExistingCase?: () => void;
}

export function StartPage({ copy, setup, onChoose, onOpenExistingCase }: StartPageProps) {
  return (
    <div className="page start-page">
      <header className="start-page__hero">
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1>{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
        {onOpenExistingCase && (
          <button className="button button--secondary" type="button" onClick={onOpenExistingCase}>
            <Icon name="cases" size={18} />
            {copy.existingCaseAction}
          </button>
        )}
      </header>

      {setup}

      <aside className="start-page__scope-note" aria-labelledby="start-page-scope-title">
        <Icon name="info" size={20} />
        <div>
          <strong id="start-page-scope-title">{copy.scopeNoticeTitle}</strong>
          <p>{copy.scopeNotice}</p>
        </div>
      </aside>

      <section aria-labelledby="use-case-choice-title">
        <div className="start-page__section-heading">
          <h2 id="use-case-choice-title">{copy.choiceTitle}</h2>
          <p>{copy.choiceDescription}</p>
        </div>

        <div className="use-case-grid">
          {useCaseDefinitions.map((useCase) => {
            const card = copy.cards[useCase.id];
            return (
              <article className="use-case-card" key={useCase.id}>
                <header className="use-case-card__header">
                  <span className="use-case-card__icon">
                    <Icon name={useCase.icon} size={22} />
                  </span>
                  <div>
                    <h3>{card.title}</h3>
                    <p>{card.summary}</p>
                  </div>
                </header>

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

                <button
                  className="button button--primary use-case-card__action"
                  type="button"
                  onClick={() => onChoose(useCase)}
                >
                  {copy.chooseAction}
                  <Icon name="arrow" size={17} />
                </button>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}
