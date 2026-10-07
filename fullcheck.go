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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	PM_FULL    = 6
	ID_REPCOPY = 21
	ID_REPCLOSE = 23

	ES_MULTILINE      = 0x0004
	ES_AUTOVSCROLL    = 0x0040
	ES_READONLY       = 0x0800
	WS_VSCROLL        = 0x00200000
	WM_CTLCOLOREDIT   = 0x0133
	WM_CTLCOLORSTATIC = 0x0138
)

var (
	procSetFocusP   = user32.NewProc("SetFocus")
	procSetBkColorG = gdi32.NewProc("SetBkColor")

	fullMu      sync.Mutex
	fullRunning bool

	gReportText  string
	gReportTime  string
	gReportEdit  uintptr
	gReportBtnCopy uintptr

	repProcPtr   uintptr
	repClassOnce sync.Once
	repMu        sync.Mutex
	repClosed    chan struct{}

	fMono  uintptr
	brEdit uintptr
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

// ---- 报告窗口 ----

func reportWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		w, h := 680, 600
		hInst, _, _ := procGetModuleHandleW.Call(0)
		edit, _, _ := procCreateWindowExW.Call(0,
			uintptr(unsafe.Pointer(wp("EDIT"))), 0,
			WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_TABSTOP|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
			16, 52, uintptr(w-32), uintptr(h-104), hwnd, 7, hInst, 0)
		gReportEdit = edit
		procSendMessageW.Call(edit, WM_SETFONT, fMono, 1)
		repMu.Lock()
		txt := gReportText
		repMu.Unlock()
		procSetWindowTextW.Call(edit, uintptr(unsafe.Pointer(wp(strings.ReplaceAll(txt, "\n", "\r\n")))))
		gReportBtnCopy = mkButton(hwnd, ID_REPCOPY, "复制报告", 20, h-46, 150, 34)
		btnClose := mkButton(hwnd, ID_REPCLOSE, "关 闭", w-110, h-46, 90, 34)
		procSendMessageW.Call(gReportBtnCopy, WM_SETFONT, fBtn, 1)
		procSendMessageW.Call(btnClose, WM_SETFONT, fBtn, 1)
		procSetFocusP.Call(edit)
		return 0
	case WM_COMMAND:
		switch wparam & 0xffff {
		case ID_REPCOPY:
			repMu.Lock()
			txt := gReportText
			repMu.Unlock()
			SetClipboardText(txt)
			procSetWindowTextW.Call(gReportBtnCopy, uintptr(unsafe.Pointer(wp("✓ 已复制"))))
		case ID_REPCLOSE:
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC:
		procSetTextColorG.Call(wparam, rgb(0xD8, 0xD8, 0xD8))
		procSetBkMode.Call(wparam, TRANSPARENT)
		procSetBkColorG.Call(wparam, rgb(0x12, 0x12, 0x16))
		return brEdit
	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		procSetBkMode.Call(hdc, TRANSPARENT)
		procSetTextColorG.Call(hdc, rgb(255, 255, 255))
		procSelectObject.Call(hdc, fTitle)
		title := "全面体检报告 · IPQuality"
		if gReportTime != "" {
			title += " · " + gReportTime
		}
		r := RECT{20, 0, 680 - 20, 44}
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(title))), uintptr(utf16Count(title)),
			uintptr(unsafe.Pointer(&r)), DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX)
		return 0
	case WM_DESTROY:
		repMu.Lock()
		if repClosed != nil {
			close(repClosed)
			repClosed = nil
		}
		repMu.Unlock()
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

// showFullReport 打开报告窗口（等宽字体、可滚动、可复制）
func showFullReport(text string) {
	repMu.Lock()
	gReportText = text
	gReportTime = time.Now().Format("15:04:05")
	if repClosed == nil {
		repClosed = make(chan struct{})
	}
	repMu.Unlock()
	go func() {
		runtime.LockOSThread()
		attachDefaultDesktop()
		registerClass()
		repClassOnce.Do(func() {
			procSetProcessDPIAware.Call()
			fMono = mkFont(-14, FW_NORMAL, "NSimSun")
			brEdit, _, _ = procCreateSolidBrush.Call(rgb(0x12, 0x12, 0x16))
			repProcPtr = syscall.NewCallback(reportWndProc)
			hInst, _, _ := procGetModuleHandleW.Call(0)
			cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)
			name := wp("LadderGuardReport")
			wc := WNDCLASSEXW{
				CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
				LpfnWndProc:   repProcPtr,
				HInstance:     hInst,
				HCursor:       cursor,
				HbrBackground: brBody,
				LpszClassName: uintptr(unsafe.Pointer(name)),
			}
			procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
			runtime.KeepAlive(name)
		})
		w, h := 680, 600
		sx, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
		sy, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
		x := int(sx) - w - 24
		y := int(sy) - h - 72
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		hInst, _, _ := procGetModuleHandleW.Call(0)
		hwnd, _, err := procCreateWindowExW.Call(WS_EX_TOPMOST,
			uintptr(unsafe.Pointer(wp("LadderGuardReport"))), uintptr(unsafe.Pointer(wp("LadderGuard 全面体检报告"))),
			WS_POPUP|WS_VISIBLE,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h),
			0, 0, hInst, 0)
		if hwnd == 0 {
			fmt.Printf("LadderGuardReport 创建窗口失败: %v\n", err)
			return
		}
		fmt.Printf("LadderGuardReport 窗口创建成功: hwnd=0x%x\n", hwnd)
		procShowWindowP.Call(hwnd, SW_SHOW)
		procSetForegroundWindowP.Call(hwnd)
		var m MSG
		for {
			r, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if r == 0 || r == ^uintptr(0) {
				fmt.Printf("GetMessage 循环退出: r=0x%x, err=%v\n", r, err)
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
}
