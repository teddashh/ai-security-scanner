import Markdown, { type Components } from "react-markdown";

const heading: Components["h1"] = ({ children }) => (
  <strong className="scanner-markdown__heading">{children}</strong>
);

const components: Components = {
  h1: heading, h2: heading, h3: heading, h4: heading, h5: heading, h6: heading,
  // Scanner text must never load remote images or become executable HTML.
  img: ({ alt }) => <span>{alt}</span>,
  a: ({ href, children }) => href && /^https?:\/\//iu.test(href)
    ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
    : <span>{children}</span>,
};

// Priority cards are buttons. Keep their preview phrasing-only and leave links
// and full list semantics in the finding's detail panel.
const compactComponents: Components = {
  ...components,
  a: ({ children }) => <span>{children}</span>,
  p: ({ children }) => <span className="scanner-markdown__block">{children}</span>,
  ul: "span",
  ol: "span",
  li: ({ children }) => <span className="scanner-markdown__block">{children}</span>,
  blockquote: "span",
  pre: "span",
  hr: "br",
};

/** Format upstream wording for display without changing stored scanner evidence. */
export function ScannerMarkdown({ text, compact = false }: { text: string; compact?: boolean }) {
  const content = <Markdown components={compact ? compactComponents : components}>{text}</Markdown>;
  return compact
    ? <span className="scanner-markdown scanner-markdown--compact">{content}</span>
    : <div className="scanner-markdown">{content}</div>;
}
