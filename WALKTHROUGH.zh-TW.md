# VEX Bench 初版：重現與閱讀教學

> 這份文件記錄初版里程碑。後續的 `codex/evidence-integration` 分支已加入
> OpenCode 證據串接與一次有上限的回饋修訂；目前用法以 `README.md` 為準。

本次接手實作已完成。這份教學讓你逐步重跑與理解，而不是把提案時程當成已完成紀錄。

## 1. 回到你的專案

```bash
cd ~/Desktop/cmu-vex-project/vex-bench
git status --short
```

目前使用 `evidence-verifier` 分支。上游版本是
`80cddeac3132826bfd47227ad59b2e6618a681bd`。尚未替你 commit 或 push。

## 2. 建立可啟動的環境

```bash
uv sync --locked --no-editable
uv run --no-editable vex-bench --help
```

原本的 `ModuleNotFoundError: No module named 'cli'` 已確認與 macOS 的隱藏檔案屬性有關：
Python 3.12.14 跳過帶 `UF_HIDDEN` 屬性的 editable-install `.pth` 檔案。
重新安裝 editable 模式仍可能重現，因此這份教學固定使用 `--no-editable`，安裝實際套件。
修改程式後，`uv run --no-editable` 會檢查是否需要重建本機套件。
需要檢查舊 editable 環境時，可執行 `.venv/bin/python scripts/repair_macos_env.py`。

`uv.lock` 原先與 `pyproject.toml` 不一致。你先前的 `uv run` 已將格式修訂號從 2 改為 3，
並移除設定中不存在的 `python-dotenv` 紀錄。這個已存在的差異有保留。

## 3. 執行測試

```bash
uv run --no-editable python -m unittest discover -s tests -v
```

本次實測：27 項測試通過。測試涵蓋偽造引文、錯誤行號、內容變動、路徑越界、
符號連結越界、註解偽裝成函式呼叫、錯誤 AST 主張、標準答案欄位與不充分的語意證據。

## 4. 重跑三個真實案例的示範

指定版本的原始碼已下載到 `benchmark/repos/`。第一次在新電腦使用才需要下載：

```bash
uv run --no-editable vex-bench download benchmark/tasks/milestone_demo.jsonl
```

然後執行：

```bash
uv run --no-editable python scripts/demo_evidence.py
```

預期結果：三個專案，各五個人工設計輸入，共 15 個示範。9 個 `unsupported`、6 個 `needs_review`。
每個專案有一個真實局部事實、一個偽造引文、一個不存在的檔案、一個與引文不符的局部主張，
以及一個從真實引文跳到「整個應用程式安全」的語意過度推論。

這些是針對真實原始碼的人工作業範例，沒有呼叫模型，也不是 benchmark 準確率。
產出位於 `results/evidence_demo/`，可直接打開 `.input.json` 與 `.report.json` 對照。

## 5. 單獨驗證 FastAPI

```bash
uv run --no-editable vex-bench verify \
  --repo benchmark/repos/fastapi/fastapi/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa \
  --input examples/evidence/fastapi-valid_local_fact.input.json \
  --snapshot-sha febf6b6a52e36e0d64920fb54670ad7fc29b2eaa \
  --output results/evidence_demo/fastapi-manual.report.json
```

原始碼 `fastapi/routing.py:247` 包含 `body = await request.form()`。
驗證器可以確認檔案、雜湊、行號、引文與 `request.form` 呼叫語法。
它不能只憑這一行就確認實際安裝的 Starlette 版本、攻擊者能否到達該處或防護措施是否有效。
因此結果應為 `needs_review`，`exploitability_verified` 為 `false`。

換成 `examples/evidence/fastapi-fabricated_quote.input.json`，預期為 `unsupported`。
這類拒絕結果的結束狀態碼是 1，代表成功發現不支持的證據。
格式錯誤的輸入使用狀態碼 2。狀態碼 0 只表示完成檢查且仍需審查，不代表安全。

## 6. 依照資料流閱讀程式

1. `src/evidence/schema.py` 定義輸入格式。每個主張引用證據 ID，每份證據記錄檔名、行號、引文與雜湊。
2. `src/evidence/verifier.py` 檢查目前檔案位元組與引文。Python AST 檢查只驗證引用範圍內的局部語法。
3. `src/evidence/cli.py` 將驗證器接到 `vex-bench verify`。
4. `src/evaluate/prompts.py` 新增 `evidence_v1` 提示詞，要求模型提供結構化證據。
5. `src/evaluate/run.py` 為提示詞填入 task ID、CVE 與 snapshot SHA。
6. `tests/test_evidence.py` 展示每項保證與已知邊界。

`verified_local_predicate` 只表示指定的局部條件成立。自由文字 statement 和 reasoning 的語意仍標示
`statement_entailment: not_checked`。例如引文真的有函式呼叫，不代表「此應用程式絕對安全」成立。

輸入格式禁止額外欄位，因此把 `ground_truth` 塞進驗證器輸入會被拒絕。但這不會自動阻止模型
在其他地方看見答案；正式實驗仍須使用原專案的來源碼容器隔離。作者在設定階段已見過資料集標籤，
這次人工示範不宣稱盲測。

## 7. 完整 baseline 的下一步

```bash
uv run --no-editable python scripts/check_baseline.py
```

本次檢查發現 Docker daemon 未啟動，且 `env/opencode/opencode.env` 與
`env/opencode/opencode.json` 尚不存在。完整模型 baseline 因此尚未執行。
啟動 Docker Desktop，依 `env/opencode/` 的 `.example` 檔案配置自己的 provider 與模型，
再建置對應映像。此處的 `<configured-model>` 必須替換成你的實際可用模型別名。

```bash
./docker/build.sh python opencode
./docker/build.sh go opencode
uv run --no-editable vex-bench evaluate run \
  --benchmark milestone_demo --agent opencode --model <configured-model> \
  --prompt vuln --repeats 1 --parallel 1
```

這段是後續操作範例，本次沒有執行。OpenCode 目前可用別名要以 `src/evaluate/agents/opencode.py`
的 `MODEL2NAME` 及你的 provider 設定為準。上游範例連接 Azure，可能需要依帳號修改設定。
完成真正模型執行後，再以相同參數執行 `evaluate parse`、`evaluate metrics`。

加入 `--prompt evidence_v1` 可要求結構化證據，但還需從 agent 的 raw result 擷取最後 JSON，
另外呼叫 `verify`。這個自動串接與回饋修正迴圈仍是後續工作。

## 8. 如何向老師說明

可以說：「完成初版證據完整性與局部語法驗證器，通過 27 項測試，
在三個指定版本專案上示範 15 個人工輸入。完整模型 baseline 與端到端語意驗證尚待完成。」

個人貢獻請由 Miles Chiang 與 Wei-Hsiang Shao 確認後填寫。
本對話能確認使用者完成下載、分支與環境操作，但無法把這些工作歸屬到某位組員。
本次實作、測試與報告有 AI 協助，尚未聲稱學生已獨立完成或理解全部內容。
