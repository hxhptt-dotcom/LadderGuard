# LadderGuard 架构决策与避坑记忆 (AGENTS.md)

## 1. 核心架构与设计原则
- **极简原生无外部运行时**：单仓 Go 纯标准库开发，无第三方库依赖，纯 Win32 系统调用实现 GUI 弹窗、系统托盘、剪贴板和注册表操作。
- **双模编译**：
  - `LadderGuard.exe`：无黑框后台常驻 GUI 守护进程（编译参数 `-ldflags "-s -w -H=windowsgui"`）。
  - `LadderGuard-console.exe`：命令行调试与测试工具，支持 `-diag`, `-full`, `-test=report`, `-ports` 等。

## 2. 关键系统坑点与避坑准则
1. **Windows 桌面隔离 (Desktop Station Isolation)**：
   - Agent CLI / CI / 服务环境常在独立 Desktop 或 Session 运行。
   - 打开弹窗、系统托盘及读写系统剪贴板前，必须调用 `attachDefaultDesktop()` 切换至用户的 `Default` 桌面，否则弹窗不可见或剪贴板写入失败。
2. **进程托管与 Job Object 终止**：
   - 通过 PowerShell 脚本拉起后台进程时，脚本退出可能连带销毁子进程。
   - 守护进程拉起必须使用 WMI：
     `Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '...'}`
3. **Bash 路径命中与 WSL 冲突 (Exit 127)**：
   - 严禁盲目依赖 `exec.LookPath("bash")`，在 Windows 上容易命中 `C:\Windows\System32\bash.exe`（WSL 假体），导致无法解析 Windows 盘符路径报错 127。
   - 必须通过注册表或常规路径优先锁定 Git Bash 真实路径（`D:\Program Files\Git\bin\bash.exe` 等）。
4. **HTML 模板与 Sprintf 格式化转义**：
   - 内嵌 CSS 时严禁在模板中混入未绑定的 `%s`，否则会引发参数整体错位。
   - Sprintf 中输出 CSS 百分比数值时，`%d%%` 输出为 `80%`；若误写为 `%d%%%%` 则会输出为无效的 `80%%` 导致样式失效。

## 3. UI 视觉规范
- **风格**：Linear / Vercel 极简暗黑杂志排版，深空灰底 `#08090d` + 微光边框 + 柔和呼吸灯。
- **图标**：严禁滥用廉价 Emoji，统一使用轻量级内嵌 SVG 矢量图标。
- **报告交互**：大白话核心结论横幅 + 双列雷达与矩阵 + 折叠日志抽屉 + 一键复制 AI 提示词（带 Toast 反馈）。
