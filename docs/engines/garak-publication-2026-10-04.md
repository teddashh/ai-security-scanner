# Garak 0.17.0-1 publication

[Engine and update notes](garak.md) · [All-image notebook](image-build-index.md)

The owner authorized this fixed native integration for v0.4.0. The immutable
image is published and independently verified; main can explicitly dispatch it
against one approved HTTPS chat API/model with a fresh one-shot local key.

| Identity | Verified value |
| --- | --- |
| Native version / source | `0.17.0` / `93aa9cdec309ec4170559676f1826ea2a679920c` |
| Managed tag | `ghcr.io/teddashh/ai-security-scanner-engine-garak:0.17.0-1` |
| Index | `sha256:8a39b5812a4fd5aa2caecfef089ff85c39709f1bc00afa3328714346baab222f` |
| linux/amd64 | `sha256:21f2e097684de81183fb1a5815e93b78dd013bf076cc1ad5804845179acb805d` |
| linux/arm64 | `sha256:732d0e8038ef6a3e1bce66fbe956e034a662e4125c8f819b91609e718d003bb6` |
| Publication source | `c9945b672853585be832a0ff978b16a7166b92b6` |
| Workflow | [37185013509, attempt 1](https://github.com/teddashh/ai-security-scanner/actions/runs/37185013509) |
| Evidence artifact | `garak-image-evidence-37185013509-1`, ID `11296617357` |
| Artifact SHA-256 | `2410b1ec2d5bed303df63c705b5f329902ab0701999c1b9781179774d6b7f7f9` |
| Root / nested receipts | `07789a6199cb0230a5eff0e627fb02c6ff470341f5c7ba35fc9438b928c649f1` / `641ae4d419bd82c7dd7649121ce25913c8c4544359f56b1754c3cb26ec2a4bb4` |
| Managed native smoke receipt | `c6c6a42f0d377195e7b2078f31401318cb32b3748d9990af60f9e993625dd53a` |

Verification checked 16 root and ten nested evidence entries, five signed
attestations and four platform SBOMs against the exact source and workflow.
Anonymous retrieval hashed both platform manifests/configurations and every
byte of 23 distinct image layers. Configurations retain uid65532, the isolated
Python entrypoint, native source/archive and runtime dependency-lock labels.

## Native execution

The repeatable [TLS helper](../../engines/images/garak/testdata/native_smoke.py)
passed in publication and again locally with the public amd64 digest. Its own
internal-only network, mock SOCKS gateway, generated certificate/key and synthetic
API key are removed afterward; no owner model, key or live target was used.

| Case | Observed native outcome |
| --- | --- |
| Positive | 54 requests; four detector pairs, all 54 evaluated as failures; complete, exit 0 |
| Clean | 54 requests; same four pairs, zero failures; complete, exit 0 |
| Redirect | One request, no follow; incomplete `redirect_refused` |
| Invalid TLS | One attempted TLS request, zero observed HTTP prompts; incomplete |
| Short deadline | Six-second fixture expiry stops requests and backoff; incomplete `inference_deadline` |
| Cancellation | Graceful stop retains private partial native JSONL and `native_cancelled`; no requests after stop |

Native prompts, probes and detectors are unchanged. Every request uses the exact
model, POST path, verified TLS and requested output ceiling of 150 tokens. The
64-attempt ceiling includes retries. The QA certificate mount is test-only;
production exposes no trust override. Native execution evidence is amd64 only;
arm64 bytes, build/import checks and SBOMs do not establish an arm64 native run.

The first publication attempt stopped before promotion because an extra direct
import check bypassed the launcher's private HOME/XDG setup. The workflow was
corrected to provide its own tmpfs and isolated directories; production image
behavior was unchanged. The failed candidate was never admitted.

公開雙平台映像、來源簽章、四份 SBOM 與所有內容層已獨立核對。
六種 TLS 案例以公開 amd64 digest 複驗通過，未使用擁有者端點或金鑰。
金鑰在本機短暫保留、派送時使用一次，不寫入案件。執行時使用受保護、唯讀掛載的暫存憑證檔，結束後清除；四個原生探針共 54 個提示的失敗次數與未完成狀態均保留。
arm64 只記錄位元組、建置匯入及 SBOM 驗證，不宣稱已執行原生模型檢查。
