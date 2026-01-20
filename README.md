# TrackX - 處理程序行為分析工具

## 概述

TrackX 是一個基於 Windows 事件追蹤 (ETW) 的命令列工具，用於深度監控指定執行檔及其所有子處理程序的行為。它能夠鉅細靡遺地記錄從檔案系統、註冊表到網路通訊的各類活動，並將結果匯總成一份結構化的 JSON 報告。此外，它還具備獨特的成品（Artifacts）備份功能，可將被監控處理程序所存取或建立的檔案自動打包。

本工具旨在為開發者、系統管理員及資安人員提供一個強大的動態分析工具，以了解程式在執行期間的具體行為。

## 主要功能

- **處理程序監控**: 追蹤子處理程序的建立、啟動命令列以及結束狀態。
- **檔案系統稽核**: 記錄檔案的建立 (`CreateFile`)、刪除 (`DeleteFile`) 與重新命名 (`MoveFile`)。
- **註冊表稽核**: 記錄註冊表鍵的建立 (`RegCreateKey`) 與值的設定 (`RegSetValue`)。
- **網路活動追蹤**:
    - 記錄對外的 TCP 連線 (`TCP:Connect`) 與 UDP 傳送 (`API:SendTo(UDP)`)。
    - 記錄 DNS 查詢 (`API:GetAddrInfo`, `DNS:Query`)，並自動關聯 IP 與域名。
- **高階 API 追蹤**: 監控函式庫載入 (`LoadLibrary`)、驅動程式載入 (`LoadDriver`)、WMI 查詢、RPC 呼叫等。
- **成品備份**: 使用 `-a` 參數，可自動將目標處理程序存取過的檔案備份至一個 ZIP 壓縮檔中，以便後續分析。
- **進階監控模式**:
    - `--alpc`: 啟用進階本地程序呼叫 (ALPC / IPC) 的監控。
    - `--paranoid`: 啟用極度詳細的追蹤模式，包含系統控制代碼 (Handles)、AMSI (反惡意軟體掃描介面) 掃描內容以及 PowerShell 指令。
- **JSON 報告**: 產生一份詳細的 JSON 報告，以處理程序為單位，層級化地展示其所有活動記錄。

## 使用說明

### 基本語法
```
TrackX.exe <path-to-exe> [options]
```
**注意**: 由於 ETW 需要高權限，本工具必須以 **系統管理員身分** 執行。

### 命令列選項

| 參數                  | 說明                                                               |
| --------------------- | ------------------------------------------------------------------ |
| `<path-to-exe>`       | **(必需)** 要啟動並監控的目標執行檔路徑。                          |
| `-o <file.json>`      | 指定輸出的 JSON 報告檔案路徑。預設為 `proc_report.json`。          |
| `-a <file.zip>`       | 啟用成品備份，並指定輸出的 ZIP 檔案路徑。                          |
| `-v`                  | 詳細模式，在主控台即時顯示事件。                                   |
| `--alpc`              | 啟用 ALPC (IPC) 監控。                                             |
| `--paranoid`          | 啟用極度詳細的追蹤 (包含 Handles, AMSI, PowerShell)。極耗資源。   |
| `--mapview`           | 啟用 File MapView 事件追蹤。這會產生大量雜訊。                     |
| `--no-filter`         | 停用內建的事件過濾器，捕獲所有事件 (包含大量系統底層雜訊)。        |
| `--admin`             | (已棄用) 強制以管理員身分啟動目標。                                |

### 使用範例

監控 `sample.exe`，啟用 `paranoid` 模式，將報告儲存至 `report.json`，並將所有相關檔案備份至 `artifacts.zip`。
```powershell
.\TrackX.exe C:\path\to\sample.exe -o report.json -a artifacts.zip --paranoid
```

## 報告輸出格式

輸出的 JSON 報告以 `ReportRoot` 物件為根，其中 `Processes` 陣列包含了所有被追蹤的處理程序 (包含主處理程序及其子處理程序)。每個處理程序記錄 (`ProcessRecord`) 中都包含一個 `Actions` 陣列，按時間順序列出該處理程序的所有行為。

### 輸出範例 (節錄)
```json
{
  "StartTime": "2026-01-20T10:20:00.123Z",
  "EndTime": "2026-01-20T10:21:30.456Z",
  "TargetMetadata": {
    "Path": "C:\\path\\to\\sample.exe",
    "SizeBytes": 123456
  },
  "Processes": [
    {
      "Pid": 1001,
      "ParentPid": 500,
      "Name": "sample.exe",
      "Actions": [
        {
          "Type": "ProcessStarted",
          "Detail": "C:\\Windows\\System32\\cmd.exe /c whoami",
          "Count": 1,
          "Times": ["10:20:05.100"]
        },
        {
          "Type": "API:CreateFile",
          "Detail": "C:\\Users\\tester\\AppData\\Local\\Temp\\tmp_data.log",
          "Count": 1,
          "Times": ["10:20:06.200"]
        }
      ]
    },
    {
      "Pid": 1002,
      "ParentPid": 1001,
      "Name": "cmd.exe",
      "Actions": [
        {
          "Type": "ProcessStarted",
          "Detail": "whoami.exe",
          "Count": 1,
          "Times": ["10:20:05.500"]
        }
      ]
    }
  ]
}
```

## 實作細節

- **開發語言**: C# / .NET 8
- **核心技術**: Windows 事件追蹤 (ETW)
- **主要相依性**: `Microsoft.Diagnostics.Tracing.TraceEvent`

## 建置需求

1.  **作業系統**: Windows 10/11 (x64)
2.  **.NET SDK**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) 或更新版本。

```bash
# 1. 複製專案
git clone https://github.com/Nickyangtpe/TrackX.git

# 2. 進入目錄
cd TrackX

# 3. 建置專案
dotnet build -c Release
```

## 安全性警告

本工具用於執行並分析目標程式，其中可能包含惡意軟體。請務必在安全、隔離的環境 (如虛擬機) 中使用，避免對您的主要系統造成損害。

## 授權

本專案採用 MIT 授權。
