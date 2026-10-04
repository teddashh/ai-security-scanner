import { useState } from "react";
import { useI18n } from "../i18n";
import { validatedModelEndpoint } from "../garakProfile";
import type { ModelEndpointInput, StartModelCheckInput } from "../types";

export function ModelEndpointPanel({ nativeMode, busy, initialInput, onStart }: {
  nativeMode: boolean;
  busy?: boolean;
  initialInput?: ModelEndpointInput;
  onStart: (input: StartModelCheckInput) => Promise<boolean>;
}) {
  const { text } = useI18n();
  const [endpoint, setEndpoint] = useState(initialInput?.endpoint ?? "");
  const [model, setModel] = useState(initialInput?.model ?? "");
  const [key, setKey] = useState("");
  const [privateNetwork, setPrivateNetwork] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const input = validatedModelEndpoint(endpoint, model);
  const ready = nativeMode && !busy && !submitting && Boolean(input && key.trim() && confirmed);
  const confirmation = text({
    en: "I am authorized to send the displayed fixed Garak probes to this exact endpoint and model, with the stated inference limits and provider charges.",
    zhTW: "我獲准向這個精確端點與模型送出畫面所列的固定 Garak 探針，並接受所列推論限制與服務商費用。",
  });
  const changed = () => setConfirmed(false);
  return <details className="coverage-form-technical coverage-scan-advanced page-secondary-feature" data-model-check>
    <summary>{text({ en: "Optional model behavior check", zhTW: "可選的模型行為檢查" })}</summary>
    <form className="coverage-form" onSubmit={async (event) => {
      event.preventDefault();
      if (!ready || !input) return;
      const localKey = key;
      setKey("");
      setSubmitting(true);
      try { await onStart({ ...input, key: localKey, privateNetwork, confirmation }); }
      finally { setSubmitting(false); setConfirmed(false); }
    }}>
      <p>{text({ en: "Garak sends 54 native DAN and ANSI test prompts to an OpenAI-compatible chat API and records the detectors' failure counts.",
        zhTW: "Garak 會向 OpenAI 相容聊天 API 送出 54 個原生 DAN 與 ANSI 測試提示，記錄偵測器判定失敗的次數。" })}</p>
      <div className="form-grid">
        <label className="field"><span>{text({ en: "Chat completions URL", zhTW: "聊天完成 API 網址" })}</span>
          <input type="url" value={endpoint} placeholder="https://api.example.com/v1/chat/completions" autoComplete="off"
            disabled={busy || submitting} onChange={(event) => { setEndpoint(event.target.value); changed(); }} />
        </label>
        <label className="field"><span>{text({ en: "Model identifier", zhTW: "模型識別碼" })}</span>
          <input value={model} autoComplete="off" disabled={busy || submitting} onChange={(event) => { setModel(event.target.value); changed(); }} />
        </label>
        <label className="field"><span>{text({ en: "API key for this check", zhTW: "這次檢查的 API 金鑰" })}</span>
          <input type="password" value={key} autoComplete="new-password" spellCheck={false} disabled={busy || submitting}
            onChange={(event) => { setKey(event.target.value); changed(); }} />
          <small>{text({ en: "Kept in app memory for up to 30 minutes and consumed once at dispatch. Enter it again for another check.",
            zhTW: "只在程式記憶體中保留最多 30 分鐘，派送時使用一次；再次檢查時請重新輸入。" })}</small>
        </label>
      </div>
      <label className="scope-mode-card">
        <input type="checkbox" checked={privateNetwork} disabled={busy || submitting}
          onChange={(event) => { setPrivateNetwork(event.target.checked); changed(); }} />
        <span>{text({ en: "This endpoint is on an internal or local network", zhTW: "這個端點位於內部或本機網路" })}</span>
      </label>
      <p>{text({ en: "One request at a time, at most 1/second; 20-second request timeout and 10-minute run limit. At most 64 requests including retries and 150 requested output tokens per attempt (9,600 maximum requested tokens). Your provider sets the charges.",
        zhTW: "一次一個請求、每秒最多一次；單次逾時 20 秒、整輪最多 10 分鐘。含重試最多 64 次請求，每次要求最多 150 個輸出 token（合計最多要求 9,600 個）。實際費用由服務商計算。" })}</p>
      {input && <p><strong>{text({ en: "Selected model", zhTW: "選定模型" })}</strong> <code>{input.model}</code><br /><code>{input.endpoint}</code></p>}
      <label className="scope-mode-card">
        <input type="checkbox" checked={confirmed} disabled={busy || submitting || !input}
          onChange={(event) => setConfirmed(event.target.checked)} />
        <span>{confirmation}</span>
      </label>
      <div className="form-actions"><button type="submit" className="button button-secondary" disabled={!ready}>
        {text(submitting ? { en: "Starting model check…", zhTW: "正在開始模型檢查…" } : { en: "Start model check", zhTW: "開始模型檢查" })}
      </button></div>
    </form>
  </details>;
}
