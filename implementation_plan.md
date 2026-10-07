# Implementation Plan — LadderGuard HTML 精美体检报告与大白话风控总评

## 背景与痛点
用户反馈：当前托盘“全面体检（IP质量）”完成后的弹窗是一个 Win32 原生黑底文本框（EDIT 控件），排版与视觉类似 80 年代 DOS/终端窗口，“太掉价”。
用户需求：
1. 体检完成后直接弹出精美、现代化的 HTML 报告页面。
2. 包含一眼看懂的**大白话评价总结**（直接指出节点是否适合 Claude/ChatGPT/Gemini，封号风险高低，达里奥镰刀指数）。
3. 保持单文件与轻量，零第三方外部网络依赖（内嵌 CSS/JS，本地自包含）。
4. 保留一键复制诊断报告给 AI 的功能。

---

## 架构与模块拆解

### 模块 1：体检数据智能解析引擎（`fullcheck.go`）
从 `ip.sh` 抓取到的原始报告文本中，结构化提取核心字段：
- **基础信息**：IP、掩码、组织（ISP）、国家/地区、IP 类型（广播/机房/家宽）
- **欺诈与风控评分**：
  - IPQS 评分（0-100，及风险等级）
  - Scamalytics 评分（及低/中/高）
  - IP2Location 评分
  - ipapi 评分与 AbuseIPDB
- **风险因子**：代理（Proxy）、VPN、数据中心（Server）、滥用（Abuse）、机器人（Bot）
- **AI 与流媒体解锁**：ChatGPT、Claude（若有）、TikTok、Netflix、Disney+、YouTube 等状态
- **黑名单数据库**：已标记数、黑名单数（如 0/423）

### 模块 2：AI 冲浪防封号·大白话风控算法
根据提取的指标自动计算：
- **综合防封指数**（0~100）：
  - 🟢 **纯净安全（85-100分）**：家宽/原生IP，IPQS < 20，未标记代理，放心登录 Claude/OpenAI
  - 🟡 **中度风险（50-84分）**：普通机房节点，IPQS 20-75，ChatGPT 可用但 Claude 易被降智/封号
  - 🔴 **极度高危（< 50分）**：IPQS > 75 或多库标记代理/滥用/广播IP，“卷毛的镰刀已架在脖子上”
- **三段式大白话总结生成**：
  1. **Claude（达里奥）判定**：针对 Anthropic 最严苛的风控做直接建议（“换节点，这 IP 登上去分分钟灭号”）。
  2. **ChatGPT / Gemini 判定**：是否原生解锁、是否需要套 Warp 或换节点。
  3. **节点本质判定**：直白说明这是“万人踩机房广播 IP”还是“优质住宅/纯净机房”。

### 模块 3：旗舰级自包含 HTML 模板与渲染
- 写入 `%APPDATA%\LadderGuard\report.html`。
- **纯原生内嵌样式（Zero Dependency）**：
  - 现代化暗黑毛玻璃风格（Dark Theme / Cyberpunk Clean）
  - 醒目的安全等级徽章与仪表盘（圆形/进度条动画）
  - 核心风控指标卡片网格
  - AI & 流媒体解锁状态徽章（绿色“已解锁” / 红色“已屏蔽”）
  - **常驻置顶：【📋 一键复制 AI 诊断修复报告】**
  - **折叠展开：【极客原始终端日志】**
- **浏览器唤起**：调用 Windows 默认浏览器（`cmd.exe /c start "" "%APPDATA%\LadderGuard\report.html"`）即时秒开。

---

## 实施关键步骤
1. **[步骤 1] 编写数据解析与大白话评分逻辑**：
   在 `fullcheck.go` 中增加 `ParseReport(raw string) FullReportData` 与 `EvaluateRisk(d FullReportData) AIReview`。
2. **[步骤 2] 编写单文件自包含 HTML 生成函数**：
   在 `fullcheck.go`（或 `report_html.go`）中构建高颜值响应式 HTML。
3. **[步骤 3] 升级体检唤起逻辑**：
   `showFullReport` 改为生成 HTML 并自动调用系统默认浏览器拉起；同时保留文本报告存档 `%APPDATA%\LadderGuard\fullcheck-report.txt`。
4. **[步骤 4] 编译与真实验收**：
   编译 `LadderGuard.exe` 与 `LadderGuard-console.exe`，执行 `-test=report`，验证浏览器是否能秒级打开漂亮的 HTML 报告页面，核对大白话评价内容。
5. **[步骤 5] 提交推送与归档**：
   更新 `README.md`、`PROGRESS.md`，推送到 GitHub 远端仓库。

---

## 潜在风险与应对
- **脚本输出格式微调**：`ip.sh` 版本更新可能导致正则未完全匹配某个字段。应对：解析层全部采用容错提取（Fallback 保底），未匹配项显示“未测出/正常”，绝不崩溃。
- **默认浏览器唤起权限**：在不同环境（UAC/管理员）下，使用标准 `rundll32 url.dll,FileProtocolHandler` 或 `cmd /c start ""` 确保 100% 成功唤起。
