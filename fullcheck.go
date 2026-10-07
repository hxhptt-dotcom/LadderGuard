// LadderGuard —— 全面体检（IPQuality）模块
// 托盘"全面体检"：调用 xykt/IPQuality 脚本（AGPL-3.0，运行时自动下载，不捆绑不分发）
// 对当前出口 IP 做深度体检，报告在专用窗口展示。
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	PM_FULL = 6
)

var (
	fullMu      sync.Mutex
	fullRunning bool

	gReportText string
	gReportTime string

	repMu     sync.Mutex
	repClosed chan struct{}
)

// findBash 找 Git Bash：config 指定 > PATH > 常见安装位置
func findBash() (string, error) {
	if gCfg != nil && strings.TrimSpace(gCfg.BashPath) != "" {
		if st, err := os.Stat(gCfg.BashPath); err == nil && !st.IsDir() {
			return gCfg.BashPath, nil
		}
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p, nil
	}
	cands := []string{
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files\Git\usr\bin\bash.exe`,
		`C:\Program Files (x86)\Git\bin\bash.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Programs\Git\bin\bash.exe`),
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("未找到 Git Bash，请先安装 Git for Windows")
}

// ensureJQ 下载官方 jq.exe（约5MB）到数据目录，让脚本输出完整评分（没有 jq 会退化成 Lite 报告）
func ensureJQ() {
	jp := filepath.Join(dataDir(), "bin", "jq.exe")
	if st, err := os.Stat(jp); err == nil && st.Size() > 512*1024 {
		return
	}
	os.MkdirAll(filepath.Join(dataDir(), "bin"), 0755)
	c := mkClient(90 * time.Second)
	resp, err := c.Get("https://github.com/jqlang/jq/releases/latest/download/jq-windows-amd64.exe")
	if err != nil {
		logf("jq 下载失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logf("jq 下载失败: HTTP %d", resp.StatusCode)
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	if err != nil || len(b) < 512*1024 {
		logf("jq 下载失败: 内容异常（%d 字节, err=%v）", len(b), err)
		return
	}
	tmp := jp + ".tmp"
	if os.WriteFile(tmp, b, 0755) == nil {
		os.Rename(tmp, jp)
	}
}

// ensureScript 每次体检都拉最新脚本（AGPL-3.0，不捆绑），失败则用本地缓存
func ensureScript() (string, error) {
	p := filepath.Join(dataDir(), "ip.sh")
	c := mkClient(30 * time.Second)
	resp, err := c.Get("https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if e == nil && len(b) > 50000 {
				os.WriteFile(p, b, 0755)
				return p, nil
			}
		}
	}
	if st, err2 := os.Stat(p); err2 == nil && st.Size() > 50000 {
		return p, nil
	}
	return "", fmt.Errorf("体检脚本下载失败，请检查网络")
}

var (
	reANSI   = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]|\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)")
	reDigSpam = regexp.MustCompile(`dig: command not found`)
)

// cleanFullReport 清 ANSI 码，只保留从报告分隔线开始的正文
func cleanFullReport(raw string) string {
	raw = reANSI.ReplaceAllString(raw, "")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	start := -1
	for i, ln := range lines {
		if strings.Contains(ln, "IP质量体检报告") {
			start = i
			for start > 0 && strings.HasPrefix(strings.TrimSpace(lines[start-1]), "#") {
				start--
			}
			break
		}
	}
	if start < 0 {
		start = 0
	}
	var out []string
	for _, ln := range lines[start:] {
		if reDigSpam.MatchString(ln) {
			continue
		}
		out = append(out, strings.TrimRight(ln, " "))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// runFullCheck 完整执行一次全面体检
func runFullCheck() (string, error) {
	bashPath, err := findBash()
	if err != nil {
		return "", err
	}
	ensureJQ() // 失败不阻塞，退化为 Lite 报告
	scriptPath, err := ensureScript()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bashPath, strings.ReplaceAll(scriptPath, "\\", "/"), "-n")
	runHiddenCmd(cmd)
	binDir := filepath.Join(dataDir(), "bin")
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdin = nil
	out, rerr := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("超时（超过 3 分钟已终止）")
	}
	if rerr != nil && len(out) == 0 {
		return "", fmt.Errorf("脚本运行失败: %v", rerr)
	}
	rep := cleanFullReport(string(out))
	if !strings.Contains(rep, "IP质量体检报告") {
		if rerr != nil {
			return "", fmt.Errorf("报告生成失败: %v", rerr)
		}
		return "", fmt.Errorf("报告内容异常（未找到报告主体）")
	}
	os.WriteFile(filepath.Join(dataDir(), "fullcheck-report.txt"), []byte(rep), 0644)
	return rep, nil
}

// startFullCheck 托盘入口：防重入 + 气球通知 + 完成后弹报告窗口
func startFullCheck() {
	fullMu.Lock()
	if fullRunning {
		fullMu.Unlock()
		trayBalloon("LadderGuard", "全面体检正在进行中，请稍候…")
		return
	}
	fullRunning = true
	fullMu.Unlock()
	trayBalloon("LadderGuard", "全面体检已启动（首次会下载组件），约 1 分钟…")
	go func() {
		defer func() {
			fullMu.Lock()
			fullRunning = false
			fullMu.Unlock()
		}()
		rep, err := runFullCheck()
		if err != nil {
			trayBalloon("LadderGuard", "全面体检失败："+err.Error())
			return
		}
		trayBalloon("LadderGuard", "全面体检完成，正在打开报告")
		showFullReport(rep)
	}()
}

func waitReportClosed(timeout time.Duration) {
	repMu.Lock()
	ch := repClosed
	repMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(timeout):
	}
}



// showFullReport 生成高颜值自包含 HTML 报告并在系统默认浏览器中唤起打开
func showFullReport(text string) {
	repMu.Lock()
	gReportText = text
	gReportTime = time.Now().Format("15:04:05")
	if repClosed != nil {
		select {
		case <-repClosed:
		default:
			close(repClosed)
		}
	}
	repClosed = make(chan struct{})
	close(repClosed)
	repMu.Unlock()

	// 自动预先复制一份大白话 AI 诊断给剪贴板
	p := parseFullReport(text)
	aiSummary := fmt.Sprintf("【LadderGuard 体检总结】%s (防封指数 %d/100)\n出口 IP：%s (%s - %s)\n风控评分：IPQS欺诈分 %d | Scamalytics %d | IP2Location %d\nClaude 建议：%s\nChatGPT 建议：%s\n总评：%s",
		p.BadgeText, p.ScoreTotal, p.IP, p.Country, p.Org, p.IPQSScore, p.ScamalyticsScore, p.IP2LocationScore, p.ClaudeAdvice, p.GPTAdvice, p.Summary)
	SetClipboardText(aiSummary)

	htmlPath, err := saveAndOpenHTMLReport(text)
	if err != nil {
		logf("生成 HTML 报告失败: %v", err)
		fmt.Printf("生成 HTML 报告失败: %v\n", err)
	} else {
		logf("全面体检 HTML 报告已在浏览器打开: %s", htmlPath)
		fmt.Printf("全面体检 HTML 报告已在浏览器打开: %s\n", htmlPath)
	}
}
