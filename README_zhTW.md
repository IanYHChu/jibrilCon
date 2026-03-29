# jibrilcon

**jibrilcon** 是一款針對嵌入式 Linux 系統的靜態風險掃描器,適用於以 root filesystem image (ext4、squashfs 等) 形式封裝的系統。它直接檢查已掛載的根檔案系統,偵測開機時啟動的容器服務,並根據規則策略評估其組態安全性 -- **不需要 chroot、不需要 QEMU、不執行任何映像內的程式**。

---

## 主要特色

| 項目 | 說明 |
| --- | --- |
| Init 系統偵測 | `systemd`、`sysvinit`、`openrc` (透過 ELF 啟發式分析) |
| 容器執行環境 | **Docker**、**Podman**、**LXC** |
| 規則引擎 | JSON DSL,支援 14 種運算子 (`equals`、`regex_match`、`not_regex_match`、`gt`、`exists` 等) |
| 安全框架對應 | MITRE ATT&CK、CIS Docker Benchmark、NIST SP 800-190 |
| 平行掃描 | 以執行緒池並行執行各掃描模組 |
| 輸出格式 | JSON 或 Gzip 壓縮 JSON |
| 零執行期依賴 | 僅讀取檔案,不執行映像內任何二進位程式 |

---

## 為什麼需要 jibrilcon?

嵌入式 Linux 系統通常有強烈的硬體相依性,在模擬的主機環境中執行系統映像往往不切實際。僅為了分析組態就要求完整開機,會帶來不必要的成本與複雜度。**jibrilcon** 採用靜態分析方式:直接掃描已掛載的根檔案系統,分析檔案內容而不執行任何程式。

此外,嵌入式系統通常缺乏使用者互動介面 -- 所有服務都在開機時自動啟動。**jibrilcon** 不依賴執行期行為,而是分析系統啟動組態 (例如 systemd service 檔案),識別哪些容器在開機時啟動,並針對這些服務進行安全分析。

---

## 安裝

```bash
# 需要 Python 3.10+
pip install -e ".[dev]"
```

---

## 使用方式

```bash
# 查詢版本
python3 -m jibrilcon --version

# 基本掃描,帶彩色終端輸出
python3 -m jibrilcon /mnt/target-rootfs

# 將報告存為 JSON
python3 -m jibrilcon /mnt/target-rootfs -o report.json

# 將報告存為 Gzip 壓縮 JSON
python3 -m jibrilcon /mnt/target-rootfs -o report.json.gz

# 停用彩色輸出 (適用於 CI 或日誌檔案)
python3 -m jibrilcon /mnt/target-rootfs --no-color

# 調整掃描並行度
python3 -m jibrilcon /mnt/target-rootfs --max-workers 4
```

未指定 `--output` 時,報告會輸出到 stdout。使用 `--no-color` 可停用 ANSI 跳脫碼。

---

## 程式化 API

jibrilcon 可作為 Python 函式庫使用,整合到更大的工具鏈或自訂自動化腳本中。

```python
from pathlib import Path
from jibrilcon.core import run_scan
from jibrilcon.util.report_writer import write_report

# 執行掃描並取得報告 dict
report = run_scan(
    "/mnt/target-rootfs",
    max_workers=4,          # 並行掃描器執行緒數 (預設: 8)
    scanner_timeout=300.0,  # 每個掃描器的逾時秒數
)

# 以程式方式檢視結果
for block in report["report"]:
    print(f"{block['scanner']}: {block['summary']}")

# 寫入磁碟 (依副檔名自動判斷 JSON 或 gzip)
write_report(report, Path("report.json"))
write_report(report, Path("report.json.gz"))  # 自動壓縮
```

`run_scan()` 回傳的 dict 結構與下方[報告格式](#報告格式)章節所述相同。`write_report()` 採用 atomic write (暫存檔 + rename),不會產生不完整的輸出檔案。

---

## 報告格式

### 頂層結構

```json
{
  "report": [
    {
      "scanner": "docker | podman | lxc",
      "summary": {
        "alerts": 3,
        "warnings": 1
      },
      "results": [
        {
          "container": "my-app",
          "status": "violated | clean",
          "violations": [ "..." ]
        }
      ]
    }
  ],
  "summary": {
    "alerts": 5,
    "warnings": 2,
    "clean": 1,
    "violated": 3,
    "scanners_run": ["docker", "podman", "lxc"]
  }
}
```

| 欄位 | 型別 | 說明 |
| --- | --- | --- |
| `report` | array | 各掃描器的結果區塊 |
| `report[].scanner` | string | 掃描器模組名稱 |
| `report[].summary` | object | 該掃描器的 alert/warning 計數 |
| `report[].results` | array | 逐容器項目,含 `status` ("clean" 或 "violated") |
| `summary` | object | 所有掃描器的彙總計數 |
| `summary.scanners_run` | array | 已執行的掃描器名稱 |

### 違規項目

每項違規都包含可操作的上下文資訊與安全框架對應:

```json
{
  "id": "privileged",
  "type": "alert",
  "severity": 9.0,
  "description": "Container is running in privileged mode",
  "risk": "Grants full access to all host devices and disables most kernel isolation.",
  "remediation": "Remove --privileged flag. Use --cap-add for specific capabilities.",
  "references": {
    "mitre_attack": ["T1611"],
    "cis_docker_benchmark": ["5.4"],
    "nist_800_190": ["4.4"]
  },
  "source": "/var/lib/docker/containers/.../config.v2.json",
  "lines": ["HostConfig.Privileged = True"]
}
```

| 欄位 | 型別 | 說明 |
| --- | --- | --- |
| `id` | string | 規則識別碼 |
| `type` | string | `"alert"` 或 `"warning"` |
| `severity` | float | 風險分數 1.0 (低) 至 10.0 (嚴重),依循 CVSS v3 定性量表 |
| `description` | string | 可讀的發現摘要 |
| `risk` | string | 此組態為何危險 |
| `remediation` | string | 建議修復方式 |
| `references` | object | 安全框架對應 (MITRE ATT&CK、CIS、NIST) |
| `source` | string | 相對於掛載點的組態檔路徑 |
| `lines` | array | 觸發規則的具體組態項目 |

### 範例輸出

一個包含兩項違規的 Docker 容器的實際報告範例:

```json
{
  "report": [
    {
      "scanner": "docker",
      "summary": { "alerts": 1, "warnings": 1 },
      "results": [
        {
          "container": "web-gateway",
          "status": "violated",
          "violations": [
            {
              "id": "privileged",
              "type": "alert",
              "severity": 9.0,
              "description": "Container is running in privileged mode",
              "risk": "Grants full access to all host devices and disables most kernel isolation.",
              "remediation": "Remove --privileged flag. Use --cap-add for specific capabilities.",
              "references": {
                "mitre_attack": ["T1611"],
                "cis_docker_benchmark": ["5.4"],
                "nist_800_190": ["4.4"]
              },
              "source": "/var/lib/docker/containers/abc123/config.v2.json",
              "lines": ["HostConfig.Privileged = True"]
            },
            {
              "id": "pid_mode",
              "type": "warning",
              "severity": 5.0,
              "description": "Container shares the host PID namespace",
              "risk": "Processes inside the container can see and signal host processes.",
              "remediation": "Remove --pid=host unless process visibility is required.",
              "references": {
                "mitre_attack": ["T1611"],
                "cis_docker_benchmark": ["5.15"]
              },
              "source": "/var/lib/docker/containers/abc123/hostconfig.json",
              "lines": ["PidMode = host"]
            }
          ]
        }
      ]
    }
  ],
  "summary": {
    "alerts": 1,
    "warnings": 1,
    "clean": 0,
    "violated": 1,
    "scanners_run": ["docker"]
  }
}
```

### 嚴重度量表

嚴重度遵循 [CVSS v3 定性評級](https://www.first.org/cvss/specification-document):

| 分數 | 等級 | 範例 |
| --- | --- | --- |
| 9.0 -- 10.0 | 嚴重 (Critical) | 特權模式、完全主機存取 |
| 7.0 -- 8.9 | 高 (High) | 缺少 capability 限縮、未啟用 user namespace |
| 4.0 -- 6.9 | 中 (Medium) | 可寫入的 bind mount、PID mode 共享 |
| 0.1 -- 3.9 | 低 (Low) | 資訊性發現 |

### 對應的安全框架

| 框架 | 涵蓋範圍 |
| --- | --- |
| [MITRE ATT&CK (Containers)](https://attack.mitre.org/matrices/enterprise/containers/) | T1611、T1078.003、T1565.001、T1003 |
| [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) | 第 5 章 (Container Runtime) |
| [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final) | 第 4.4 節 (Container Risks) |

---

## 運作原理

1. 將嵌入式 Linux rootfs 掛載到主機上 (例如 `/mnt/target-rootfs`)
2. **Init 偵測** -- 透過 ELF 啟發式分析識別 systemd / sysvinit / openrc
3. **Systemd 預收集** -- 解析 `.service` 檔案,找出哪些容器透過 systemd 開機啟動,快取 ExecStart/ExecStartPre 命令列及 User 指令
4. **平行掃描** -- 動態載入所有掃描模組 (`docker_native`、`podman`、`lxc`) 並以執行緒池平行執行
5. **規則評估** -- 各掃描器提取組態欄位,對照 JSON 規則定義進行評估
6. **報告產生** -- 合併所有結果為統一報告,包含逐容器違規清單與摘要統計

---

## 專案結構

```
src/jibrilcon/
  __main__.py              python -m jibrilcon 進入點
  cli.py                   參數解析、彩色摘要、報告輸出
  core.py                  協調器: init 偵測 -> systemd -> 掃描器 -> 報告
  init_manager_finder.py   Init 系統的 ELF 啟發式偵測

  scanners/                各容器執行環境一個模組
    docker_native.py       Docker (config.v2.json + hostconfig.json)
    lxc.py                 LXC (設定檔 + mount entries + lxc-monitord)
    podman.py              Podman (OCI config.json + containers.json)

  util/                    共用工具
    rules_engine.py        JSON DSL 規則引擎 (14 種運算子、and/or 邏輯)
    context.py             執行緒安全的掃描器間共享狀態
    systemd_unit_parser.py 解析 .service 檔案、偵測容器服務
    path_utils.py          具 rootfs 邊界檢查的安全符號連結解析
    ...

  rules/                   JSON 規則定義 (含安全框架對應)
  config/                  Systemd unit 搜尋路徑與偵測模式
```

---

## 擴充 jibrilcon

### 新增容器執行環境掃描器

1. 建立 `src/jibrilcon/scanners/<runtime>.py`
2. 實作:
   ```python
   def scan(mount_path: str, context: ScanContext) -> dict: ...
   ```
3. 新增 `src/jibrilcon/rules/<runtime>_config_rules.json` 規則定義

### 新增規則運算子

1. 在 `src/jibrilcon/util/rules_engine.py` 中實作 `_myop(a, b) -> bool`
2. 註冊到 `_OPERATOR_MAP`

### 為規則新增安全框架對應

在任何規則定義中加入以下選用欄位:

```json
{
  "severity": 7.0,
  "risk": "為什麼這是危險的",
  "remediation": "如何修復",
  "references": {
    "mitre_attack": ["T1611"],
    "cis_docker_benchmark": ["5.4"],
    "nist_800_190": ["4.4"]
  }
}
```

完整的規則 DSL 文件 -- 包含所有支援的運算子、巢狀規則群組,以及撰寫新規則的指引 -- 請參閱
[`src/jibrilcon/rules/README.md`](src/jibrilcon/rules/README.md)。

---

## 開發

```bash
# 安裝開發依賴
pip install -e ".[dev]"

# 執行測試
python3 -m pytest tests/ -v

# 程式碼檢查
ruff check src/ tests/
```

---

## Exit Codes

| 代碼 | 意義 |
| --- | --- |
| 0 | 掃描成功完成 (不論是否有違規) |
| 1 | 執行期錯誤 (例如權限不足、組態損毀) |
| 2 | 參數錯誤 (無效旗標、缺少掛載路徑) |
| 130 | 使用者中斷 (Ctrl+C / SIGINT) |

---

## 疑難排解 / FAQ

**掃描掛載路徑時出現 "Permission denied"**

掃描器需要對 rootfs 下所有檔案的讀取權限。請以 root 身分執行或調整目錄權限:

```bash
sudo python3 -m jibrilcon /mnt/target-rootfs
```

**未偵測到容器**

jibrilcon 透過解析 systemd service 檔案來發現容器。請確認 rootfs 中包含參照容器執行環境 (docker、podman、lxc) 的 `.service` unit。若映像使用 sysvinit 或 openrc,請透過 `--log-level debug` 確認 init 系統是否被正確偵測。

**掃描速度緩慢**

LXC 掃描器會對整個 rootfs 執行完整的 `os.walk`,因為 LXC 組態路徑無法預測 -- 這是設計使然,不是 bug。對於大型檔案系統,掃描時間會較長。可使用 `--max-workers 1` 降低資源使用,或增加數值以在 SSD 上獲得更高的 I/O 吞吐量。

**啟用詳細日誌**

```bash
python3 -m jibrilcon /mnt/target-rootfs --log-level debug
```

這會追蹤每個被檢查的檔案和每條被評估的規則,有助於診斷漏報或理解掃描器行為。

**如何整合 CI/CD**

使用 exit code 和 JSON 輸出進行自動化:

```bash
python3 -m jibrilcon /mnt/rootfs --no-color -o report.json
rc=$?
if [ $rc -ne 0 ]; then
  echo "Scan failed (exit code $rc)" >&2
  exit $rc
fi
# 解析 report.json 中的 alerts/warnings
alerts=$(python3 -c "import json; r=json.load(open('report.json')); print(r['summary']['alerts'])")
if [ "$alerts" -gt 0 ]; then
  echo "Found $alerts alert(s) -- failing pipeline" >&2
  exit 1
fi
```

Exit code 0 表示掃描完成 (仍可能存在違規)。請檢查 JSON 輸出中的 `summary.alerts` 來決定是否中斷 pipeline。詳見 [Exit Codes](#exit-codes)。

---

## 授權

Apache License 2.0 -- 詳見 [LICENSE](LICENSE)。
