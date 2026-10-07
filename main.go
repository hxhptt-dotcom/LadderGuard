// LadderGuard —— 梯子卫士
// 常驻监控梯子健康度：真实IP泄漏 / TUN掉线 / 系统代理裸奔 / 高危节点地区 / IP跳变 / IPv6泄漏 / 内核挂了
// 异常时右下角置顶大弹窗报警，诊断报告自动复制到剪贴板，直接粘贴给 AI 修复。
// 纯 Go 标准库，无第三方依赖。
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const Version = "1.3.0"

//go:embed icon_green.ico
var icoGreenData []byte

//go:embed icon_red.ico
var icoRedData []byte

// ---------------- Win32 基础 ----------------

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
)

var (
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procInvalidateRect      = user32.NewProc("InvalidateRect")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procSetProcessDPIAware  = user32.NewProc("SetProcessDPIAware")
	procOpenClipboard       = user32.NewProc("OpenClipboard")
	procCloseClipboard      = user32.NewProc("CloseClipboard")
	procEmptyClipboard      = user32.NewProc("EmptyClipboard")
	procSetClipboardData    = user32.NewProc("SetClipboardData")
	procMessageBeep         = user32.NewProc("MessageBeep")
	procBeginPaint          = user32.NewProc("BeginPaint")
	procEndPaint            = user32.NewProc("EndPaint")
	procFillRect            = user32.NewProc("FillRect")
	procDrawTextW           = user32.NewProc("DrawTextW")
	procLoadCursorW         = user32.NewProc("LoadCursorW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procSetWindowTextW      = user32.NewProc("SetWindowTextW")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procGetDC               = user32.NewProc("GetDC")
	procReleaseDC           = user32.NewProc("ReleaseDC")

	procGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc        = kernel32.NewProc("GlobalAlloc")
	procGlobalLock         = kernel32.NewProc("GlobalLock")
	procGlobalUnlock       = kernel32.NewProc("GlobalUnlock")
	procCreateMutexW       = kernel32.NewProc("CreateMutexW")
	procAttachConsole      = kernel32.NewProc("AttachConsole")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procGetStdHandle       = kernel32.NewProc("GetStdHandle")

	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procSetTextColorG    = gdi32.NewProc("SetTextColor")
	procSetBkMode        = gdi32.NewProc("SetBkMode")

	procRtlGetVersion = ntdll.NewProc("RtlGetVersion")
	procRegGetValueW  = advapi32.NewProc("RegGetValueW")

	procShellNotifyIconW          = shell32.NewProc("Shell_NotifyIconW")
	procShowWindowP               = user32.NewProc("ShowWindow")
	procCreatePopupMenu           = user32.NewProc("CreatePopupMenu")
	procAppendMenuW               = user32.NewProc("AppendMenuW")
	procTrackPopupMenu            = user32.NewProc("TrackPopupMenu")
	procDestroyMenu               = user32.NewProc("DestroyMenu")
	procRegisterWindowMessageW    = user32.NewProc("RegisterWindowMessageW")
	procCreateIconFromResourceEx  = user32.NewProc("CreateIconFromResourceEx")
	procSetForegroundWindowP      = user32.NewProc("SetForegroundWindow")
)

const (
	WS_POPUP          = 0x80000000
	WS_VISIBLE        = 0x10000000
	WS_CHILD          = 0x40000000
	WS_TABSTOP        = 0x00010000
	WS_EX_TOPMOST     = 0x00000008
	CS_HREDRAW        = 0x0002
	CS_VREDRAW        = 0x0001
	IDC_ARROW         = 32512
	SW_SHOW           = 5
	WM_CREATE         = 0x0001
	WM_DESTROY        = 0x0002
	WM_PAINT          = 0x000F
	WM_SETFONT        = 0x0030
	WM_COMMAND        = 0x0111
	WM_LBUTTONDOWN    = 0x0201
	WM_NCLBUTTONDOWN  = 0x00A1
	WM_LBUTTONUP      = 0x0202
	WM_LBUTTONDBLCLK  = 0x0203
	WM_RBUTTONUP      = 0x0205
	HTCAPTION         = 2
	SM_CXSCREEN       = 0
	SM_CYSCREEN       = 1
	GMEM_MOVEABLE     = 0x0002
	CF_UNICODETEXT    = 13
	DT_WORDBREAK      = 0x0010
	DT_CALCRECT       = 0x0400
	DT_SINGLELINE     = 0x0020
	DT_VCENTER        = 0x0004
	DT_NOPREFIX       = 0x0800
	TRANSPARENT       = 1
	FW_NORMAL         = 400
	FW_BOLD           = 700
	DEFAULT_CHARSET   = 1
	CLEARTYPE_QUALITY = 5
	HKEY_CURRENT_USER = 0x80000001
	RRF_RT_REG_DWORD  = 0x10
	RRF_RT_REG_SZ     = 0x02
	MB_ICONWARNING    = 0x30

	NIM_ADD            = 0
	NIM_MODIFY         = 1
	NIM_DELETE         = 2
	NIF_MESSAGE        = 0x01
	NIF_ICON           = 0x02
	NIF_TIP            = 0x04
	NIF_INFO           = 0x10
	NIIF_INFO          = 0x01
	NIM_SETVERSION     = 4
	NOTIFYICON_VERSION_4 = 4
	WM_APP_TRAY        = 0x8001 // WM_APP+1，托盘回调消息
	WM_NULL            = 0x0000
	TPM_RIGHTBUTTON    = 0x0002
	TPM_RETURNCMD      = 0x0100
	TPM_NONOTIFY       = 0x0080
	MF_STRING          = 0x0000
	MF_SEPARATOR       = 0x0800
	MF_CHECKED         = 0x0008
)

type POINT struct{ X, Y int32 }
type RECT struct{ Left, Top, Right, Bottom int32 }
type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}
type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  uintptr
	LpszClassName uintptr
	HIconSm       uintptr
}
type PAINTSTRUCT struct {
	Hdc         uintptr
	FErase      uint32
	RcPaint     RECT
	FRestore    uint32
	FIncUpdate  uint32
	RgbReserved [32]byte
}
type OSVERSIONINFOW struct {
	DwOSVersionInfoSize uint32
	DwMajorVersion      uint32
	DwMinorVersion      uint32
	DwBuildNumber       uint32
	DwPlatformId        uint32
	SzCSDVersion        [128]uint16
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type NOTIFYICONDATAW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         GUID
	HBalloonIcon     uintptr
}

// wp 返回 UTF-16 指针。必须以 uintptr(unsafe.Pointer(wp(s))) 的形式内联传给 Call，
// 保证 GC 在调用期间保活。
func wp(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func utf16Count(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}

func u16s(s string) []uint16 {
	p, _ := syscall.UTF16FromString(s)
	return p
}

func rgb(r, g, b byte) uintptr {
	return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16
}

func winVersion() string {
	var vi OSVERSIONINFOW
	vi.DwOSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	procRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	return fmt.Sprintf("Windows %d.%d build %d", vi.DwMajorVersion, vi.DwMinorVersion, vi.DwBuildNumber)
}

func regReadDWORD(path, name string) (uint32, bool) {
	var v uint32
	var sz uint32 = 4
	r1, _, _ := procRegGetValueW.Call(HKEY_CURRENT_USER,
		uintptr(unsafe.Pointer(wp(path))), uintptr(unsafe.Pointer(wp(name))),
		RRF_RT_REG_DWORD, 0, uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&sz)))
	if r1 == 0 {
		return v, true
	}
	return 0, false
}

func regReadString(path, name string) (string, bool) {
	buf := make([]uint16, 512)
	sz := uint32(len(buf) * 2)
	r1, _, _ := procRegGetValueW.Call(HKEY_CURRENT_USER,
		uintptr(unsafe.Pointer(wp(path))), uintptr(unsafe.Pointer(wp(name))),
		RRF_RT_REG_SZ, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
	if r1 == 0 {
		return syscall.UTF16ToString(buf), true
	}
	return "", false
}

// attachConsole 让 GUI 子系统的 exe 也能在 cmd/PowerShell 里打印输出（mintty 下无效）
func attachConsole() {
	// 原始 stdout 已经有效（管道/重定向）时绝不接管，否则打印会进看不见的控制台
	if h, _, _ := procGetStdHandle.Call(uintptr(0xFFFFFFF5)); h != 0 {
		procSetConsoleOutputCP.Call(65001)
		return
	}
	procAttachConsole.Call(^uintptr(0)) // ATTACH_PARENT_PROCESS = (DWORD)-1
	procSetConsoleOutputCP.Call(65001)
	hOut, _, _ := procGetStdHandle.Call(uintptr(0xFFFFFFF5)) // STD_OUTPUT_HANDLE=-11
	if hOut != 0 {
		os.Stdout = os.NewFile(hOut, "CONOUT$")
	}
	hErr, _, _ := procGetStdHandle.Call(uintptr(0xFFFFFFF4)) // STD_ERROR_HANDLE=-12
	if hErr != 0 {
		os.Stderr = os.NewFile(hErr, "CONERR$")
	}
}

// ---------------- 剪贴板 ----------------

func SetClipboardText(text string) bool {
	u := utf16.Encode([]rune(text))
	u = append(u, 0)
	n := len(u) * 2
	for i := 0; i < 10; i++ {
		r1, _, _ := procOpenClipboard.Call(0)
		if r1 == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		procEmptyClipboard.Call()
		ok := false
		h, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, uintptr(n))
		if h != 0 {
			p, _, _ := procGlobalLock.Call(h)
			if p != 0 {
				b := unsafe.Slice((*byte)(unsafe.Pointer(p)), n)
				for j, v := range u {
					b[j*2] = byte(v)
					b[j*2+1] = byte(v >> 8)
				}
				procGlobalUnlock.Call(h)
				procSetClipboardData.Call(CF_UNICODETEXT, h)
				ok = true
			}
		}
		procCloseClipboard.Call()
		if ok {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// ---------------- 配置 / 状态 / 日志 ----------------

type Config struct {
	IntervalSec        int      `json:"interval_sec"`
	ProxyPorts         []int    `json:"proxy_ports"`
	ExpectTUN          bool     `json:"expect_tun"`
	WarnSystemProxy    bool     `json:"warn_system_proxy"`
	RiskyRegions       []string `json:"risky_regions"`
	CountryChangeAlert bool     `json:"country_change_alert"`
	FlapWindowMin      int      `json:"flap_window_min"`
	FlapCount          int      `json:"flap_count"`
	AlertCooldownMin   int      `json:"alert_cooldown_min"`
	ServiceCheck       bool     `json:"service_check"`
	BashPath           string   `json:"bash_path"`
}

func defaultConfig() Config {
	return Config{
		IntervalSec:        30,
		ProxyPorts:         []int{7890, 7897},
		ExpectTUN:          true,
		WarnSystemProxy:    true,
		RiskyRegions:       []string{"CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU", "AF"},
		CountryChangeAlert: true,
		FlapWindowMin:      10,
		FlapCount:          3,
		AlertCooldownMin:   30,
		ServiceCheck:       false,
	}
}

type State struct {
	LastIP      string           `json:"last_ip"`
	LastCountry string           `json:"last_country"`
	IpChanges   []int64          `json:"ip_changes"`
	LastAlert   map[string]int64 `json:"last_alert"`
	FailStreak  int              `json:"fail_streak"`
	ProxyPort   int              `json:"proxy_port"`
}

func exeDir() string {
	d, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(d)
}

func dataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = exeDir()
	}
	return filepath.Join(base, "LadderGuard")
}

func loadConfig() Config {
	cfg := defaultConfig()
	p := filepath.Join(exeDir(), "config.json")
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &cfg) // 缺的字段保留默认值
		if cfg.IntervalSec < 10 {
			cfg.IntervalSec = 10
		}
	} else if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		os.WriteFile(p, b, 0644)
	}
	return cfg
}

func loadState() *State {
	st := &State{LastAlert: map[string]int64{}, IpChanges: []int64{}}
	if b, err := os.ReadFile(filepath.Join(dataDir(), "state.json")); err == nil {
		json.Unmarshal(b, st)
	}
	if st.LastAlert == nil {
		gState.LastAlert = map[string]int64{}
	}
	if st.IpChanges == nil {
		st.IpChanges = []int64{}
	}
	return st
}

func saveState(st *State) {
	if b, err := json.MarshalIndent(st, "", "  "); err == nil {
		os.WriteFile(filepath.Join(dataDir(), "state.json"), b, 0644)
	}
}

var logPath string

func logf(format string, a ...any) {
	if logPath == "" {
		return
	}
	if st, err := os.Stat(logPath); err == nil && st.Size() > 512*1024 {
		os.Rename(logPath, logPath+".old")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
}

// 报警冷却由监控和弹窗两个 goroutine 共用，加锁
var (
	gState  *State
	stateMu sync.Mutex
)

func cooldownGet(key string) (int64, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	t, ok := gState.LastAlert[key]
	return t, ok
}

func cooldownSet(key string, ts int64) {
	stateMu.Lock()
	gState.LastAlert[key] = ts
	stateMu.Unlock()
}

func cooldownDel(key string) {
	stateMu.Lock()
	delete(gState.LastAlert, key)
	stateMu.Unlock()
}

// ---------------- 网络检测 ----------------

type Geo struct {
	OK          bool
	IP          string
	CountryCode string
	Country     string
	City        string
	ISP         string
}

type ipAPIResp struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

type ipSbResp struct {
	IP           string `json:"ip"`
	CountryCode  string `json:"country_code"`
	Country      string `json:"country"`
	City         string `json:"city"`
	ISP          string `json:"isp"`
	Organization string `json:"organization"`
}

func mkClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 6 * time.Second}).DialContext,
			TLSHandshakeTimeout: 6 * time.Second,
			DisableKeepAlives:   true,
		},
	}
}

// clientDirect 不挂任何代理、无视系统代理 —— 测的是"裸奔路径"，也就是 AI 客户端实际看到的出口
var clientDirect = mkClient(10 * time.Second)

func clientViaProxy(port int) *http.Client {
	c := mkClient(10 * time.Second)
	c.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(port)})
	return c
}

func clientV6() *http.Client {
	c := mkClient(8 * time.Second)
	c.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 6 * time.Second}
		return d.DialContext(ctx, "tcp6", addr)
	}
	return c
}

func fetchGeoURL(c *http.Client, u string) (Geo, error) {
	resp, err := c.Get(u)
	if err != nil {
		return Geo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Geo{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return Geo{}, err
	}
	if strings.Contains(u, "ip-api.com") {
		var r ipAPIResp
		if json.Unmarshal(body, &r) != nil || r.Status != "success" {
			return Geo{}, fmt.Errorf("api fail: %s", r.Message)
		}
		return Geo{OK: true, IP: r.Query, CountryCode: r.CountryCode, Country: r.Country, City: r.City, ISP: r.ISP}, nil
	}
	var r ipSbResp
	if json.Unmarshal(body, &r) != nil || r.IP == "" {
		return Geo{}, fmt.Errorf("api fail")
	}
	isp := r.ISP
	if isp == "" {
		isp = r.Organization
	}
	return Geo{OK: true, IP: r.IP, CountryCode: strings.ToUpper(r.CountryCode), Country: r.Country, City: r.City, ISP: isp}, nil
}

func fetchGeo(c *http.Client, urls []string) Geo {
	for _, u := range urls {
		if g, err := fetchGeoURL(c, u); err == nil {
			return g
		}
	}
	return Geo{}
}

var defaultGeoURLs = []string{
	"http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,query&lang=zh-CN",
	"https://api.ip.sb/geoip",
}

var reIPv4 = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

func fetchRealIP(c *http.Client) (string, string) {
	for _, u := range []string{"http://4.ipw.cn", "https://myip.ipip.net"} {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if m := reIPv4.FindStringSubmatch(string(b)); m != nil {
			return m[1], u
		}
	}
	return "", ""
}

func runHiddenCmd(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func probePorts(ports []int) []int {
	var alive []int
	seen := map[int]bool{}
	for _, p := range ports {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 1200*time.Millisecond)
		if err == nil {
			c.Close()
			alive = append(alive, p)
		}
	}
	return alive
}

// detectAlivePorts 端口全自动识别：
// 1) 上次验证过的缓存端口  2) verge.yaml 的 verge_mixed_port  3) 配置提示端口
// 都不行才扫描代理核心进程监听的本地端口（mihomo/clash/sing-box/xray/v2ray 等）
func detectAlivePorts(cfg *Config, vergePort string) ([]int, string) {
	stateMu.Lock()
	cached := gState.ProxyPort
	stateMu.Unlock()
	verge := 0
	if v, err := strconv.Atoi(strings.TrimSpace(vergePort)); err == nil && v > 0 && v < 65536 {
		verge = v
	}
	var first []int
	if cached > 0 {
		first = append(first, cached)
	}
	if verge > 0 {
		first = append(first, verge)
	}
	first = append(first, cfg.ProxyPorts...)
	alive := probePorts(first)
	if len(alive) > 0 {
		switch alive[0] {
		case cached:
			return alive, "缓存"
		case verge:
			return alive, "verge.yaml"
		}
		return alive, "配置端口"
	}
	// 兜底：扫描核心进程监听的端口
	extra := probePorts(coreListeningPorts())
	if len(extra) == 0 {
		return nil, ""
	}
	// 逐个验证真的能当 HTTP 代理用（防止把核心的 API 端口之类误当代理）
	var ok, bad []int
	for _, p := range extra {
		if validateProxyPort(p) {
			ok = append(ok, p)
		} else {
			bad = append(bad, p)
		}
	}
	if len(ok) > 0 {
		return append(ok, bad...), "进程扫描"
	}
	return extra, "进程扫描"
}

func validateProxyPort(p int) bool {
	c := clientViaProxy(p)
	c.Timeout = 8 * time.Second
	resp, err := c.Get("http://www.gstatic.com/generate_204")
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 16))
	resp.Body.Close()
	// 走通代理的 204；核心 API 端口会返回 404/401 之类，借此排除
	return resp.StatusCode == 200 || resp.StatusCode == 204
}

var reCoreProcName = regexp.MustCompile(`(?i)mihomo|clash|sing-box|xray|v2ray|hysteria|trojan|naive|brook`)

func coreListeningPorts() []int {
	pids := map[string]bool{}
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !reCoreProcName.MatchString(line) {
				continue
			}
			f := strings.Split(line, ",")
			if len(f) < 2 {
				continue
			}
			pid := strings.Trim(f[1], `" `)
			if pid != "" {
				pids[pid] = true
			}
		}
	}
	if len(pids) == 0 {
		return nil
	}
	out2, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
	if err != nil {
		return nil
	}
	seen := map[int]bool{}
	var ports []int
	for _, line := range strings.Split(string(out2), "\n") {
		if !strings.Contains(line, "LISTENING") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		if !pids[f[len(f)-1]] {
			continue
		}
		local := f[1]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		p, err := strconv.Atoi(local[i+1:])
		if err != nil || p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	return ports
}

var reTunName = regexp.MustCompile(`(?i)meta|mihomo|clash|verge|wintun|sing-?box|^tun|tun$`)

func detectTunIface() (bool, string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				// mihomo TUN 网卡固定占 198.18.0.0/15（fake-ip 段）
				if ipn.IP[0] == 198 && (ipn.IP[1] == 18 || ipn.IP[1] == 19) {
					return true, ifc.Name
				}
			}
		}
		if reTunName.MatchString(ifc.Name) {
			return true, ifc.Name
		}
	}
	return false, ""
}

func readSystemProxy() (bool, string) {
	v, ok := regReadDWORD(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable")
	if !ok || v == 0 {
		return false, ""
	}
	srv, _ := regReadString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyServer")
	return true, srv
}

type VergeInfo struct {
	Found      bool
	Path       string
	TunMode    string
	SysProxy   string
	MixedPort  string
	AppVersion string
}

func readVergeYaml() VergeInfo {
	candidates := []string{
		filepath.Join(os.Getenv("APPDATA"), "io.github.clash-verge-rev.clash-verge-rev"),
		filepath.Join(os.Getenv("APPDATA"), "clash-verge"),
	}
	for _, dir := range candidates {
		vp := filepath.Join(dir, "verge.yaml")
		b, err := os.ReadFile(vp)
		if err != nil {
			continue
		}
		v := VergeInfo{Found: true, Path: vp}
		text := string(b)
		grab := func(key string) string {
			m := regexp.MustCompile(`(?m)^\s*` + key + `\s*:\s*(\S+)`).FindStringSubmatch(text)
			if m != nil {
				return m[1]
			}
			return "?"
		}
		v.TunMode = grab("enable_tun_mode")
		v.SysProxy = grab("enable_system_proxy")
		v.MixedPort = grab("verge_mixed_port")
		if lb, err := os.ReadFile(filepath.Join(dir, "logs", "latest.log")); err == nil {
			if m := regexp.MustCompile(`\[ClashVergeRev\] Version:\s*([0-9.]+)`).FindStringSubmatch(string(lb)); m != nil {
				v.AppVersion = m[1]
			}
		}
		return v
	}
	return VergeInfo{}
}

func serviceCheck(port int) []string {
	c := clientViaProxy(port)
	type svc struct{ name, url string }
	var blocked []string
	for _, s := range []svc{
		{"OpenAI", "https://chat.openai.com/robots.txt"},
		{"Claude", "https://claude.ai/robots.txt"},
	} {
		resp, err := c.Get(s.url)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if resp.StatusCode == 403 || resp.StatusCode == 451 {
			blocked = append(blocked, fmt.Sprintf("%s(HTTP %d)", s.name, resp.StatusCode))
		}
	}
	return blocked
}

type Snap struct {
	SysProxyOn     bool
	SysProxySrv    string
	AlivePorts     []int
	PortSource     string
	TunFound       bool
	TunName        string
	DefaultExit    Geo
	ProxyExit      Geo
	V6Exit         Geo
	RealIP         string
	RealIPSrc      string
	Verge          VergeInfo
	ServiceBlocked []string
}

func runChecks(cfg *Config) *Snap {
	s := &Snap{}
	s.SysProxyOn, s.SysProxySrv = readSystemProxy()
	s.Verge = readVergeYaml()
	s.AlivePorts, s.PortSource = detectAlivePorts(cfg, s.Verge.MixedPort)
	if len(s.AlivePorts) > 0 && gState != nil {
		stateMu.Lock()
		gState.ProxyPort = s.AlivePorts[0]
		stateMu.Unlock()
	}
	s.TunFound, s.TunName = detectTunIface()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); s.DefaultExit = fetchGeo(clientDirect, defaultGeoURLs) }()
	go func() {
		defer wg.Done()
		if len(s.AlivePorts) > 0 {
			s.ProxyExit = fetchGeo(clientViaProxy(s.AlivePorts[0]), defaultGeoURLs)
		}
	}()
	go func() { defer wg.Done(); s.V6Exit = fetchGeo(clientV6(), defaultGeoURLs) }()
	wg.Wait()

	// 需要真实IP的两种情况：默认路径已经判为中国（写报告用），或 TUN 缺失（兜底判断泄漏）
	needReal := (s.DefaultExit.OK && s.DefaultExit.CountryCode == "CN") ||
		(!s.TunFound && len(s.AlivePorts) > 0)
	if needReal {
		s.RealIP, s.RealIPSrc = fetchRealIP(clientDirect)
	}
	if cfg.ServiceCheck && len(s.AlivePorts) > 0 {
		s.ServiceBlocked = serviceCheck(s.AlivePorts[0])
	}
	return s
}

// ---------------- 问题判定 ----------------

type Issue struct {
	Level  int // 2=高危 1=警告
	Key    string
	Tag    string
	Title  string
	Detail string
	Fix    string
}

var regionNames = map[string]string{
	"CN": "中国大陆", "HK": "香港", "MO": "澳门", "RU": "俄罗斯", "BY": "白俄罗斯",
	"KP": "朝鲜", "IR": "伊朗", "SY": "叙利亚", "CU": "古巴", "AF": "阿富汗",
}

func regionCN(code string) string {
	if n, ok := regionNames[code]; ok {
		return n
	}
	return code
}

func evaluate(s *Snap, cfg *Config, st *State) []Issue {
	now := time.Now()
	var issues []Issue
	cd := time.Duration(cfg.AlertCooldownMin) * time.Minute

	tryAdd := func(is Issue, cooldown time.Duration) {
		if t, ok := cooldownGet(is.Key); ok && now.Sub(time.Unix(t, 0)) < cooldown {
			logf("抑制重复报警: %s（冷却中）", is.Key)
			return
		}
		cooldownSet(is.Key, now.Unix())
		issues = append(issues, is)
	}
	risky := func(code string) bool {
		for _, r := range cfg.RiskyRegions {
			if strings.EqualFold(r, code) {
				return true
			}
		}
		return false
	}
	coreAlive := len(s.AlivePorts) > 0

	// 1. 内核挂了
	if !coreAlive {
		tryAdd(Issue{Level: 2, Key: "core-dead", Tag: "内核",
			Title:  "代理内核没在跑，梯子已断",
			Detail: "配置端口和自动识别（verge.yaml / 代理核心进程监听端口）都没找到可用端口，Clash Verge 可能没启动或内核挂了，现在所有流量都在直连。",
			Fix:    "打开 Clash Verge 确认主开关已开；不行就重启它。改过代理端口也不用配置，本工具会自动识别。"}, cd)
	} else if cfg.ExpectTUN && !s.TunFound {
		title := "TUN 模式没开，全机流量没人接管"
		hint := ""
		if s.Verge.Found && s.Verge.TunMode == "true" {
			title = "TUN 配置开着，但实际没生效（启动失败）"
			hint = "（verge.yaml 里 enable_tun_mode=true，但系统里找不到 TUN 网卡，多半是更新后服务坏了）"
		}
		tryAdd(Issue{Level: 2, Key: "tun-off", Tag: "TUN",
			Title: title,
			Detail: "找不到 TUN 虚拟网卡。" + hint +
				" 不开 TUN，只有浏览器这类手动挂代理的软件走节点，AI 客户端和桌面 App 全在直连裸奔。",
			Fix: "Clash Verge → 设置 → 打开 TUN 模式；如果本来就开着，去 设置 → 服务模式 点重装服务，然后重启 Clash Verge。"}, cd)
	}

	// 2. 默认路径泄漏（中国出口）
	leak := s.DefaultExit.OK && s.DefaultExit.CountryCode == "CN"
	if !leak && !s.TunFound && coreAlive && s.RealIP != "" && s.ProxyExit.OK && s.RealIP != s.ProxyExit.IP {
		leak = true // 兜底：出口接口没查到，但本机宽带IP和节点IP对不上
	}
	if leak {
		loc := strings.TrimSpace(s.DefaultExit.City + " " + s.DefaultExit.ISP)
		ipShown := s.DefaultExit.IP
		if ipShown == "" {
			ipShown = s.RealIP
		}
		detail := fmt.Sprintf("普通软件（包括 AI 客户端）现在的出口是 %s（%s），这是你的真实宽带IP。", ipShown, loc)
		if s.SysProxyOn {
			detail += "你开着系统代理：浏览器走了代理，但桌面软件大多不理系统代理，全在裸奔。"
		}
		tryAdd(Issue{Level: 2, Key: "leak", Tag: "泄漏",
			Title:  "流量在裸奔，真实IP已暴露",
			Detail: detail,
			Fix:    "打开 Clash Verge → 设置 → 打开 TUN 模式（系统代理关掉）。改完等 30 秒，本工具自动复检。"}, cd)
		// 泄漏期间不跟踪跳变，避免恢复时误报"跳国家"
		stateMu.Lock()
		st.LastCountry = ""
		st.LastIP = ""
		stateMu.Unlock()
	}

	// 3. 高危地区
	riskyHit := ""
	if s.DefaultExit.OK && s.DefaultExit.CountryCode != "CN" && risky(s.DefaultExit.CountryCode) {
		riskyHit = fmt.Sprintf("%s（默认路径 %s）", regionCN(s.DefaultExit.CountryCode), s.DefaultExit.IP)
	}
	if s.ProxyExit.OK && s.ProxyExit.CountryCode != "CN" && risky(s.ProxyExit.CountryCode) {
		riskyHit = fmt.Sprintf("%s（节点 %s）", regionCN(s.ProxyExit.CountryCode), s.ProxyExit.IP)
	}
	if riskyHit != "" {
		tryAdd(Issue{Level: 2, Key: "risky-region", Tag: "高危地区",
			Title:  "当前出口在 AI 服务高危地区",
			Detail: "出口地区：" + riskyHit + "。Claude / GPT / Gemini 不支持这个地区，直接用 = 封号率飙升。",
			Fix:    "马上换节点：日本 / 新加坡 / 美国。Clash Verge → 代理 → 手动选节点。"}, cd)
	}

	// 4. 国家跳变 + IP 频繁变动（只统计境外正常出口）
	cur := s.DefaultExit
	if !cur.OK {
		cur = s.ProxyExit
	}
	if cur.OK && cur.CountryCode != "CN" {
		if cfg.CountryChangeAlert && st.LastCountry != "" && st.LastCountry != cur.CountryCode {
			tryAdd(Issue{Level: 2, Key: "country-jump", Tag: "跳国家",
				Title:  fmt.Sprintf("节点从 %s 跳到了 %s", regionCN(st.LastCountry), regionCN(cur.CountryCode)),
				Detail: "短时间内换了国家，AI 风控会判定账号异常漫游，Claude 对这个最敏感。",
				Fix:    "锁定一个固定节点：Clash Verge → 代理页 → 手动选节点，别用自动测速/负载均衡分组。"}, 60 * time.Minute)
		}
		if st.LastIP != "" && st.LastIP != cur.IP {
			stateMu.Lock()
			st.IpChanges = append(st.IpChanges, now.Unix())
			cut := now.Add(-time.Duration(cfg.FlapWindowMin) * time.Minute).Unix()
			n := 0
			for _, t := range st.IpChanges {
				if t >= cut {
					n++
				}
			}
			if len(st.IpChanges) > 200 {
				st.IpChanges = st.IpChanges[len(st.IpChanges)-200:]
			}
			stateMu.Unlock()
			if n >= cfg.FlapCount {
				tryAdd(Issue{Level: 1, Key: "ip-flap", Tag: "IP跳变",
					Title:  fmt.Sprintf("%d 分钟内出口 IP 变了 %d 次", cfg.FlapWindowMin, n),
					Detail: "你的节点是动态 IP 池，AI 风控最爱封频繁换 IP 的用户。",
					Fix:    "换固定 IP 的节点（IEPL/专线一般固定），或关掉 Clash Verge 里的 url-test 自动切换。"}, 60 * time.Minute)
			}
		}
		stateMu.Lock()
		st.LastIP = cur.IP
		st.LastCountry = cur.CountryCode
		stateMu.Unlock()
	}

	// 5. 出口检测连续失败
	if !s.DefaultExit.OK && !s.ProxyExit.OK {
		st.FailStreak++
		if st.FailStreak >= 3 {
			tryAdd(Issue{Level: 1, Key: "check-fail", Tag: "检测失败",
				Title:  fmt.Sprintf("连续 %d 次查不到出口 IP", st.FailStreak),
				Detail: "出口检测接口全部超时，可能节点全挂、断网，或被墙。",
				Fix:    "浏览器随便开个网页试试；不行就换节点或重启 Clash Verge。"}, 60 * time.Minute)
		}
	} else {
		st.FailStreak = 0
	}

	// 6. 系统代理
	if cfg.WarnSystemProxy && s.SysProxyOn {
		tryAdd(Issue{Level: 1, Key: "sysproxy", Tag: "系统代理",
			Title:  "系统代理开着 —— 系统代理 = 找死",
			Detail: "浏览器是安全了，但 AI 桌面客户端、命令行工具根本不理系统代理，照样直连暴露真实IP。卷毛（Dario）的封号镰刀专砍这种配置。",
			Fix:    "关掉系统代理改用 TUN：Clash Verge → 设置 → 系统代理关、TUN 模式开。"}, cd)
	}

	// 7. 服务拉黑（可选，service_check=true 才启用）
	if len(s.ServiceBlocked) > 0 {
		tryAdd(Issue{Level: 1, Key: "svc-block", Tag: "IP被拉黑",
			Title:  "当前节点 IP 疑似被 AI 服务拦截",
			Detail: "检测到 " + strings.Join(s.ServiceBlocked, "、") + " 返回 403，这个 IP 可能已被拉黑或触发人机验证。",
			Fix:    "换个节点再试；换好几个都 403 说明机场 IP 池被标记，考虑换机场。"}, 60 * time.Minute)
	}

	return issues
}

// ---------------- 诊断报告 ----------------

func orDash(s string) string {
	if s == "" || s == "?" {
		return "未知"
	}
	return s
}

func geoText(g Geo) string {
	if !g.OK {
		return "检测失败/超时"
	}
	loc := g.Country
	if g.City != "" {
		loc += " " + g.City
	}
	return fmt.Sprintf("%s %s（ISP: %s）", g.IP, loc, orDash(g.ISP))
}

func sysProxyText(s *Snap) string {
	if s.SysProxyOn {
		return fmt.Sprintf("开启（%s）← 有泄漏风险", s.SysProxySrv)
	}
	return "关闭"
}

func buildReport(s *Snap, issues []Issue, cfg *Config) string {
	var b strings.Builder
	b.WriteString("══════ LadderGuard 梯子诊断报告 ══════\n")
	b.WriteString("生成时间: " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	if len(issues) == 0 {
		b.WriteString("结论: 未发现问题，梯子健康\n")
	} else {
		lv := "警告"
		for _, is := range issues {
			if is.Level == 2 {
				lv = "高危"
				break
			}
		}
		b.WriteString(fmt.Sprintf("报警级别: %s（共 %d 个问题）\n", lv, len(issues)))
	}
	b.WriteString("\n【问题清单】\n")
	if len(issues) == 0 {
		b.WriteString("  无\n")
	}
	for i, is := range issues {
		fmt.Fprintf(&b, " %d. [%s] %s\n", i+1, is.Tag, is.Title)
		fmt.Fprintf(&b, "    原因: %s\n", is.Detail)
		fmt.Fprintf(&b, "    处理: %s\n", is.Fix)
	}
	b.WriteString("\n【实测数据】\n")
	fmt.Fprintf(&b, " - 系统: %s | LadderGuard v%s\n", winVersion(), Version)
	if len(s.AlivePorts) > 0 {
		fmt.Fprintf(&b, " - 本地代理端口 %v: 通（%v）\n", cfg.ProxyPorts, s.AlivePorts)
	} else {
		fmt.Fprintf(&b, " - 本地代理端口 %v: 全部不通\n", cfg.ProxyPorts)
	}
	if s.TunFound {
		fmt.Fprintf(&b, " - TUN 网卡: 已检测到（%s）\n", s.TunName)
	} else {
		b.WriteString(" - TUN 网卡: 未检测到 ← TUN 未生效\n")
	}
	if s.SysProxyOn {
		fmt.Fprintf(&b, " - 系统代理: 开启（%s）← 有泄漏风险\n", s.SysProxySrv)
	} else {
		b.WriteString(" - 系统代理: 关闭\n")
	}
	fmt.Fprintf(&b, " - 默认出口（裸奔路径，AI 客户端看到的）: %s\n", geoText(s.DefaultExit))
	fmt.Fprintf(&b, " - 代理出口（手动挂代理时看到的）: %s\n", geoText(s.ProxyExit))
	fmt.Fprintf(&b, " - IPv6 出口: %s\n", geoText(s.V6Exit))
	if s.RealIP != "" {
		src := ""
		if s.RealIPSrc != "" {
			src = "（来自 " + s.RealIPSrc + "）"
		}
		fmt.Fprintf(&b, " - 本机真实宽带IP: %s%s\n", s.RealIP, src)
	}
	if s.Verge.Found {
		fmt.Fprintf(&b, " - Clash Verge %s 配置(verge.yaml): enable_tun_mode=%s, enable_system_proxy=%s, 混合端口=%s\n",
			orDash(s.Verge.AppVersion), s.Verge.TunMode, s.Verge.SysProxy, s.Verge.MixedPort)
	} else {
		b.WriteString(" - 未找到 Clash Verge 配置目录（不影响监控，只是少一点参考信息）\n")
	}
	b.WriteString("\n【给 AI 的求助语】（连同本报告一起发）\n")
	b.WriteString("我的电脑梯子出问题了，上面是 LadderGuard 的自动诊断报告，我用的 Clash Verge。")
	b.WriteString("请按报告里的实测数据帮我恢复：目标是 TUN 生效、默认出口=境外节点IP、无泄漏、无高危地区。")
	b.WriteString("一步步给我能直接点的操作路径。\n")
	b.WriteString("\n—— LadderGuard v" + Version + " 自动生成\n")
	return b.String()
}

// ---------------- 报警弹窗（Win32 自绘） ----------------

const (
	POPUP_W  = 560
	ID_COPY  = 1
	ID_SNOOZ = 2
	ID_CLOSE = 3
)

var (
	gUI        alertUI
	gWndProc   uintptr
	gClassOnce sync.Once
	fHeader    uintptr
	fTitle     uintptr
	fBody      uintptr
	fBtn       uintptr
	brHeader   uintptr
	brBody     uintptr
	gBtnCopy   uintptr
	gBtnSnooz  uintptr
	gBtnClose  uintptr
	gCurH      = 400
)

type alertUI struct {
	mu     sync.Mutex
	issues []Issue
	report string
	hwnd   uintptr
	closed chan struct{}
}

func mkFont(h, weight int, name string) uintptr {
	r, _, _ := procCreateFontW.Call(
		uintptr(h), 0, 0, 0, uintptr(weight), 0, 0, 0,
		DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0,
		uintptr(unsafe.Pointer(wp(name))))
	return r
}

func registerClass() {
	gClassOnce.Do(func() {
		procSetProcessDPIAware.Call()
		fHeader = mkFont(-22, FW_BOLD, "Microsoft YaHei UI")
		fTitle = mkFont(-17, FW_BOLD, "Microsoft YaHei UI")
		fBody = mkFont(-15, FW_NORMAL, "Microsoft YaHei UI")
		fBtn = mkFont(-15, FW_NORMAL, "Microsoft YaHei UI")
		brHeader, _, _ = procCreateSolidBrush.Call(rgb(0xB3, 0x26, 0x1E))
		brBody, _, _ = procCreateSolidBrush.Call(rgb(0x1B, 0x1B, 0x20))
		gWndProc = syscall.NewCallback(wndProc)
		hInst, _, _ := procGetModuleHandleW.Call(0)
		cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)
		name := wp("LadderGuardAlert")
		wc := WNDCLASSEXW{
			CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
			Style:         CS_HREDRAW | CS_VREDRAW,
			LpfnWndProc:   gWndProc,
			HInstance:     hInst,
			HCursor:       cursor,
			HbrBackground: brBody,
			LpszClassName: uintptr(unsafe.Pointer(name)),
		}
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		runtime.KeepAlive(name)
	})
}

func measureWrapped(hdc uintptr, text string, width int) int {
	if text == "" {
		return 0
	}
	rc := RECT{0, 0, int32(width), 0}
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(text))), uintptr(utf16Count(text)),
		uintptr(unsafe.Pointer(&rc)), DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX)
	return int(rc.Bottom)
}

func drawWrapped(hdc uintptr, text string, y, width int) int {
	if text == "" {
		return 0
	}
	rc := RECT{20, int32(y), int32(20 + width), 0}
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(text))), uintptr(utf16Count(text)),
		uintptr(unsafe.Pointer(&rc)), DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX)
	h := int(rc.Bottom) - y
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(text))), uintptr(utf16Count(text)),
		uintptr(unsafe.Pointer(&rc)), DT_WORDBREAK|DT_NOPREFIX)
	return h + 6
}

func computeWindowSize(issues []Issue) (int, int) {
	hdc, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, hdc)
	w := POPUP_W
	procSelectObject.Call(hdc, fBody)
	y := 62 + 16
	for i, is := range issues {
		if i >= 6 {
			y += 30
			break
		}
		y += 30
		y += measureWrapped(hdc, is.Detail, w-40) + 6
		y += measureWrapped(hdc, "处理: "+is.Fix, w-40) + 14
	}
	if len(issues) > 6 {
		y += 26
	}
	y += 34 // 页脚
	y += 56 // 按钮
	if y < 300 {
		y = 300
	}
	return w, y
}

func mkButton(parent uintptr, id uintptr, text string, x, y, w, h int) uintptr {
	hInst, _, _ := procGetModuleHandleW.Call(0)
	r, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(wp("BUTTON"))),
		uintptr(unsafe.Pointer(wp(text))), WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, id, hInst, 0)
	return r
}

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		h := gCurH
		btnY := h - 48
		gBtnCopy = mkButton(hwnd, ID_COPY, "复制诊断报告", 20, btnY, 170, 34)
		gBtnSnooz = mkButton(hwnd, ID_SNOOZ, "30分钟后再说", 205, btnY, 150, 34)
		gBtnClose = mkButton(hwnd, ID_CLOSE, "关 闭", POPUP_W-20-90, btnY, 90, 34)
		for _, b := range []uintptr{gBtnCopy, gBtnSnooz, gBtnClose} {
			procSendMessageW.Call(b, WM_SETFONT, fBtn, 1)
		}
		gUI.mu.Lock()
		gUI.hwnd = hwnd
		gUI.mu.Unlock()
		return 0
	case WM_COMMAND:
		switch wparam & 0xffff {
		case ID_COPY:
			gUI.mu.Lock()
			rep := gUI.report
			gUI.mu.Unlock()
			SetClipboardText(rep)
			procSetWindowTextW.Call(gBtnCopy, uintptr(unsafe.Pointer(wp("✓ 已复制，去粘贴给 AI"))))
		case ID_SNOOZ:
			gUI.mu.Lock()
			now := time.Now().Unix()
			for _, is := range gUI.issues {
				cooldownSet(is.Key, now)
			}
			gUI.mu.Unlock()
			procDestroyWindow.Call(hwnd)
		case ID_CLOSE:
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case WM_LBUTTONDOWN:
		procSendMessageW.Call(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0)
		return 0
	case WM_PAINT:
		paintAlert(hwnd)
		return 0
	case WM_DESTROY:
		gUI.mu.Lock()
		gUI.hwnd = 0
		if gUI.closed != nil {
			close(gUI.closed)
			gUI.closed = nil
		}
		gUI.mu.Unlock()
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func paintAlert(hwnd uintptr) {
	var ps PAINTSTRUCT
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

	gUI.mu.Lock()
	issues := append([]Issue(nil), gUI.issues...)
	gUI.mu.Unlock()

	// 标题栏
	hdr := RECT{0, 0, POPUP_W, 62}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&hdr)), brHeader)
	procSetBkMode.Call(hdc, TRANSPARENT)
	procSetTextColorG.Call(hdc, rgb(255, 255, 255))
	procSelectObject.Call(hdc, fHeader)
	title := fmt.Sprintf("!! 梯子报警 —— 检测到 %d 个问题", len(issues))
	if len(issues) == 0 {
		title = "LadderGuard"
	}
	r := RECT{20, 0, POPUP_W - 20, 62}
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(title))), uintptr(utf16Count(title)),
		uintptr(unsafe.Pointer(&r)), DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX)

	// 正文
	y := 62 + 16
	for i, is := range issues {
		if i >= 6 {
			break
		}
		procSelectObject.Call(hdc, fTitle)
		procSetTextColorG.Call(hdc, rgb(0xFF, 0xC2, 0x4B))
		t := fmt.Sprintf("%d. [%s] %s", i+1, is.Tag, is.Title)
		r2 := RECT{20, int32(y), POPUP_W - 20, int32(y + 26)}
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(t))), uintptr(utf16Count(t)),
			uintptr(unsafe.Pointer(&r2)), DT_SINGLELINE|DT_NOPREFIX)
		y += 30

		procSelectObject.Call(hdc, fBody)
		procSetTextColorG.Call(hdc, rgb(0xD0, 0xD0, 0xD0))
		y += drawWrapped(hdc, is.Detail, y, POPUP_W-40)
		procSetTextColorG.Call(hdc, rgb(0x8C, 0xE0, 0x9A))
		y += drawWrapped(hdc, "处理: "+is.Fix, y, POPUP_W-40) + 14
	}
	if len(issues) > 6 {
		procSelectObject.Call(hdc, fBody)
		procSetTextColorG.Call(hdc, rgb(0x90, 0x90, 0x90))
		more := fmt.Sprintf("…还有 %d 个问题，详见诊断报告", len(issues)-6)
		r3 := RECT{20, int32(y), POPUP_W - 20, int32(y + 26)}
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(more))), uintptr(utf16Count(more)),
			uintptr(unsafe.Pointer(&r3)), DT_SINGLELINE|DT_NOPREFIX)
	}

	// 页脚
	procSetTextColorG.Call(hdc, rgb(0x53, 0xC8, 0xE8))
	ft := "诊断报告已自动复制到剪贴板 → 直接粘贴给 AI 即可 · 置顶窗口，可拖动"
	r4 := RECT{20, int32(gCurH - 86), POPUP_W - 20, int32(gCurH - 58)}
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(ft))), uintptr(utf16Count(ft)),
		uintptr(unsafe.Pointer(&r4)), DT_SINGLELINE|DT_NOPREFIX)
}

func showAlert(issues []Issue, report string) {
	gUI.mu.Lock()
	gUI.issues = issues
	gUI.report = report
	open := gUI.hwnd != 0
	hwndCur := gUI.hwnd
	if gUI.closed == nil {
		gUI.closed = make(chan struct{})
	}
	gUI.mu.Unlock()

	procMessageBeep.Call(MB_ICONWARNING)
	if open {
		procInvalidateRect.Call(hwndCur, 0, 1)
		return
	}
	go func() {
		runtime.LockOSThread()
		registerClass()
		w, h := computeWindowSize(issues)
		gCurH = h
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
		ttl := wp("LadderGuard 梯子报警")
		hwnd, _, _ := procCreateWindowExW.Call(WS_EX_TOPMOST,
			uintptr(unsafe.Pointer(wp("LadderGuardAlert"))), uintptr(unsafe.Pointer(ttl)),
			WS_POPUP|WS_VISIBLE,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h),
			0, 0, hInst, 0)
		if hwnd == 0 {
			return
		}
		procShowWindowP.Call(hwnd, SW_SHOW)
		procSetForegroundWindowP.Call(hwnd)
		var m MSG
		for {
			r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if r == 0 || r == ^uintptr(0) {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
}

func waitAlertClosed(timeout time.Duration) {
	gUI.mu.Lock()
	ch := gUI.closed
	gUI.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(timeout):
	}
}

// ---------------- 托盘图标 + 状态面板 ----------------

var (
	gCfg        *Config
	gLastMu     sync.Mutex
	gLastSnap   *Snap
	gLastIssues []Issue
	gLastAt     time.Time
	checkNowCh  = make(chan struct{}, 1)
	checkMu     sync.Mutex
	gPrevIssues = map[string]bool{}

	trayWnd   uintptr
	trayGreen uintptr
	trayRed   uintptr
	trayMsgID uint32 // TaskbarCreated，explorer 重启后重挂图标
)

func loadIconFromICO(data []byte, want int) uintptr {
	if len(data) < 6 {
		return 0
	}
	count := int(data[4]) | int(data[5])<<8
	for i := 0; i < count; i++ {
		e := data[6+16*i : 6+16*i+16]
		w := int(e[0])
		if w == 0 {
			w = 256
		}
		if w != want {
			continue
		}
		size := int(e[8]) | int(e[9])<<8 | int(e[10])<<16 | int(e[11])<<24
		off := int(e[12]) | int(e[13])<<8 | int(e[14])<<16 | int(e[15])<<24
		if off+size > len(data) {
			return 0
		}
		h, _, _ := procCreateIconFromResourceEx.Call(
			uintptr(unsafe.Pointer(&data[off])), uintptr(size), 1,
			0x00030000, uintptr(want), uintptr(want), 0)
		return h
	}
	return 0
}

func trayNID(uFlags uint32) *NOTIFYICONDATAW {
	return &NOTIFYICONDATAW{
		CbSize: uint32(unsafe.Sizeof(NOTIFYICONDATAW{})),
		HWnd:   trayWnd,
		UID:    1,
		UFlags: uFlags,
	}
}

func trayAdd() bool {
	nid := trayNID(NIF_MESSAGE | NIF_ICON | NIF_TIP)
	nid.UCallbackMessage = WM_APP_TRAY
	nid.HIcon = trayGreen
	copy(nid.SzTip[:], u16s("LadderGuard 梯子卫士 · 监控中"))
	r1, _, _ := procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(nid)))
	return r1 != 0
}

func trayModify(icon uintptr, tip string) {
	nid := trayNID(NIF_ICON | NIF_TIP)
	nid.HIcon = icon
	copy(nid.SzTip[:], u16s(tip))
	procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(nid)))
}

func trayBalloon(title, text string) {
	nid := trayNID(NIF_INFO)
	copy(nid.SzInfoTitle[:], u16s(title))
	copy(nid.SzInfo[:], u16s(text))
	nid.DwInfoFlags = NIIF_INFO
	procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(nid)))
}

func trayRemove() {
	if trayWnd == 0 {
		return
	}
	nid := trayNID(0)
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(nid)))
}

func traySetState(healthy bool) {
	if trayWnd == 0 {
		return
	}
	gLastMu.Lock()
	n := len(gLastIssues)
	gLastMu.Unlock()
	if healthy {
		trayModify(trayGreen, "LadderGuard 梯子卫士 · 一切正常")
	} else {
		trayModify(trayRed, fmt.Sprintf("LadderGuard 梯子卫士 · 检测到 %d 个问题！", n))
	}
}

const (
	PM_CHECK   = 1
	PM_REPORT  = 2
	PM_PANEL   = 3
	PM_AUTORUN = 4
	PM_EXIT    = 5
)

func autostartEnabled() bool {
	v, ok := regReadString(runKeySub, "LadderGuard")
	return ok && v != ""
}

func reportFromLast() (string, bool) {
	gLastMu.Lock()
	s, iss := gLastSnap, gLastIssues
	gLastMu.Unlock()
	if s == nil || gCfg == nil {
		return "", false
	}
	return buildReport(s, iss, gCfg), true
}

var trayProcPtr uintptr
var trayClassOnce sync.Once

func registerTrayClass() {
	trayClassOnce.Do(func() {
		trayProcPtr = syscall.NewCallback(trayWndProc)
		hInst, _, _ := procGetModuleHandleW.Call(0)
		cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)
		name := wp("LadderGuardTray")
		wc := WNDCLASSEXW{
			CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
			LpfnWndProc:   trayProcPtr,
			HInstance:     hInst,
			HCursor:       cursor,
			LpszClassName: uintptr(unsafe.Pointer(name)),
		}
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		runtime.KeepAlive(name)
	})
}

func trayWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	if trayMsgID != 0 && msg == uintptr(trayMsgID) {
		trayAdd() // explorer 重启后重挂图标
		return 0
	}
	switch msg {
	case WM_APP_TRAY:
		switch lparam & 0xffff {
		case WM_LBUTTONUP, WM_LBUTTONDBLCLK:
			showStatusPanel()
		case WM_RBUTTONUP:
			showTrayMenu(hwnd)
		}
		return 0
	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func showTrayMenu(hwnd uintptr) {
	m, _, _ := procCreatePopupMenu.Call()
	procAppendMenuW.Call(m, MF_STRING, PM_CHECK, uintptr(unsafe.Pointer(wp("立即体检"))))
	procAppendMenuW.Call(m, MF_STRING, PM_FULL, uintptr(unsafe.Pointer(wp("全面体检（IP质量）"))))
	procAppendMenuW.Call(m, MF_STRING, PM_REPORT, uintptr(unsafe.Pointer(wp("复制诊断报告"))))
	procAppendMenuW.Call(m, MF_STRING, PM_PANEL, uintptr(unsafe.Pointer(wp("状态面板"))))
	procAppendMenuW.Call(m, MF_SEPARATOR, 0, 0)
	arText := "开机自启：未开启"
	flags := uintptr(MF_STRING)
	if autostartEnabled() {
		arText = "开机自启：已开启"
		flags |= MF_CHECKED
	}
	procAppendMenuW.Call(m, flags, PM_AUTORUN, uintptr(unsafe.Pointer(wp(arText))))
	procAppendMenuW.Call(m, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(m, MF_STRING, PM_EXIT, uintptr(unsafe.Pointer(wp("退出"))))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindowP.Call(hwnd) // 托盘菜单经典焦点 bug 修复
	sel, _, _ := procTrackPopupMenu.Call(m, TPM_RIGHTBUTTON|TPM_RETURNCMD|TPM_NONOTIFY,
		uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	procDestroyMenu.Call(m)
	procPostMessageW.Call(hwnd, WM_NULL, 0, 0)

	switch sel {
	case PM_CHECK:
		select {
		case checkNowCh <- struct{}{}:
		default:
		}
		trayBalloon("LadderGuard", "已触发立即体检，几秒内出结果")
	case PM_REPORT:
		if rep, ok := reportFromLast(); ok {
			SetClipboardText(rep)
			trayBalloon("LadderGuard", "诊断报告已复制到剪贴板，去粘贴给 AI 吧")
		} else {
			trayBalloon("LadderGuard", "还没有体检数据，稍等一个检测周期")
		}
	case PM_FULL:
		startFullCheck()
	case PM_PANEL:
		showStatusPanel()
	case PM_AUTORUN:
		if autostartEnabled() {
			uninstallAutostart()
			trayBalloon("LadderGuard", "已移除开机自启")
		} else {
			installAutostart()
			trayBalloon("LadderGuard", "已设置开机自启")
		}
	case PM_EXIT:
		trayRemove()
		procPostQuitMessage.Call(0)
	}
}

// ---- 状态面板 ----

type statusLine struct {
	text  string
	color uintptr
	font  uintptr
}

var (
	gStatLines      []statusLine
	gStatH          int
	gStatBtnCopy    uintptr
	statProcPtr     uintptr
	statClassOnce   sync.Once
	statMu          sync.Mutex
	statClosed      chan struct{}
)

func closeStatClosed() {
	statMu.Lock()
	if statClosed != nil {
		close(statClosed)
		statClosed = nil
	}
	statMu.Unlock()
}

func waitStatusClosed(timeout time.Duration) {
	statMu.Lock()
	ch := statClosed
	statMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(timeout):
	}
}

func statusLines() []statusLine {
	grey := rgb(0xC8, 0xC8, 0xC8)
	amber := rgb(0xFF, 0xC2, 0x4B)
	green := rgb(0x8C, 0xE0, 0x9A)
	cyan := rgb(0x53, 0xC8, 0xE8)
	dim := rgb(0x98, 0x98, 0x98)
	white := rgb(255, 255, 255)
	ls := []statusLine{{fmt.Sprintf("LadderGuard 梯子卫士 v%s", Version), white, fTitle}}
	gLastMu.Lock()
	s, iss, at := gLastSnap, gLastIssues, gLastAt
	gLastMu.Unlock()
	if s == nil {
		ls = append(ls, statusLine{"状态：正在做第一次体检，稍等几秒…", grey, fBody})
		return ls
	}
	if len(iss) == 0 {
		ls = append(ls, statusLine{"状态：监控中，一切正常 [OK]", green, fTitle})
	} else {
		ls = append(ls, statusLine{fmt.Sprintf("状态：检测到 %d 个问题 [!!]（看右下角报警弹窗）", len(iss)), amber, fTitle})
	}
	ls = append(ls, statusLine{fmt.Sprintf("最近体检：%s · 每 %d 秒一次", at.Format("15:04:05"), gCfg.IntervalSec), grey, fBody})
	ports := "全部不通"
	if len(s.AlivePorts) > 0 {
		ports = fmt.Sprintf("%v 通", s.AlivePorts)
	}
	tun := "未检测到 ← TUN 未生效"
	if s.TunFound {
		tun = s.TunName
	}
	ls = append(ls, statusLine{fmt.Sprintf("代理端口：%s ｜ TUN 网卡：%s", ports, tun), grey, fBody})
	geoShort := s.DefaultExit.IP + " " + s.DefaultExit.Country
	if s.DefaultExit.City != "" {
		geoShort += " " + s.DefaultExit.City
	}
	ls = append(ls, statusLine{"默认出口（AI 看到的）：" + geoShort, grey, fBody})
	ls = append(ls, statusLine{"系统代理：" + sysProxyText(s), grey, fBody})
	ls = append(ls, statusLine{"", grey, fBody})
	ls = append(ls, statusLine{"这不是木马哈：本工具只在本机做只读检测（发几个 IP 查询请求、", dim, fBody})
	ls = append(ls, statusLine{"读注册表代理设置），不上传任何数据，没有后门。源码在 GitHub。", dim, fBody})
	ls = append(ls, statusLine{"报警时右下角弹窗 + 报告自动进剪贴板，粘贴给 AI 即可修复。", cyan, fBody})
	return ls
}

func statusWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		gStatBtnCopy = mkButton(hwnd, ID_COPY, "复制诊断报告", 20, gStatH-48, 170, 34)
		btnClose := mkButton(hwnd, ID_CLOSE, "关 闭", 520-20-90, gStatH-48, 90, 34)
		for _, b := range []uintptr{gStatBtnCopy, btnClose} {
			procSendMessageW.Call(b, WM_SETFONT, fBtn, 1)
		}
		return 0
	case WM_COMMAND:
		switch wparam & 0xffff {
		case ID_COPY:
			if rep, ok := reportFromLast(); ok {
				SetClipboardText(rep)
			}
			procSetWindowTextW.Call(gStatBtnCopy, uintptr(unsafe.Pointer(wp("✓ 已复制，去粘贴给 AI"))))
		case ID_CLOSE:
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case WM_PAINT:
		paintStatus(hwnd)
		return 0
	case WM_DESTROY:
		closeStatClosed()
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func paintStatus(hwnd uintptr) {
	var ps PAINTSTRUCT
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	procSetBkMode.Call(hdc, TRANSPARENT)
	y := 20
	for _, ln := range gStatLines {
		if ln.text == "" {
			y += 12
			continue
		}
		procSelectObject.Call(hdc, ln.font)
		procSetTextColorG.Call(hdc, ln.color)
		r := RECT{20, int32(y), POPUP_W - 20, int32(y + 40)}
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(wp(ln.text))), uintptr(utf16Count(ln.text)),
			uintptr(unsafe.Pointer(&r)), DT_SINGLELINE|DT_NOPREFIX)
		if ln.font == fTitle {
			y += 34
		} else {
			y += 26
		}
	}
}

func showStatusPanel() {
	statMu.Lock()
	statClosed = make(chan struct{})
	statMu.Unlock()
	go func() {
		runtime.LockOSThread()
		registerClass()
		statClassOnce.Do(func() {
			statProcPtr = syscall.NewCallback(statusWndProc)
			hInst, _, _ := procGetModuleHandleW.Call(0)
			cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)
			name := wp("LadderGuardStatus")
			wc := WNDCLASSEXW{
				CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
				LpfnWndProc:   statProcPtr,
				HInstance:     hInst,
				HCursor:       cursor,
				HbrBackground: brBody,
				LpszClassName: uintptr(unsafe.Pointer(name)),
			}
			procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
			runtime.KeepAlive(name)
		})
		gStatLines = statusLines()
		h := 20
		for _, ln := range gStatLines {
			if ln.text == "" {
				h += 12
			} else if ln.font == fTitle {
				h += 34
			} else {
				h += 26
			}
		}
		h += 56
		if h < 300 {
			h = 300
		}
		gStatH = h
		sx, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
		sy, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
		x := int(sx) - 520 - 24
		y := int(sy) - h - 72
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		hInst, _, _ := procGetModuleHandleW.Call(0)
		hwnd, _, _ := procCreateWindowExW.Call(WS_EX_TOPMOST,
			uintptr(unsafe.Pointer(wp("LadderGuardStatus"))), uintptr(unsafe.Pointer(wp("LadderGuard 状态"))),
			WS_POPUP|WS_VISIBLE,
			uintptr(x), uintptr(y), 520, uintptr(h),
			0, 0, hInst, 0)
		if hwnd == 0 {
			return
		}
		procShowWindowP.Call(hwnd, SW_SHOW)
		procSetForegroundWindowP.Call(hwnd)
		var m MSG
		for {
			r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if r == 0 || r == ^uintptr(0) {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
}

// runTrayLoop 在主线程跑：隐藏窗口接收托盘消息，退出菜单选中后循环结束、进程退出
func runTrayLoop() {
	runtime.LockOSThread()
	registerClass()
	trayGreen = loadIconFromICO(icoGreenData, 16)
	trayRed = loadIconFromICO(icoRedData, 16)
	if trayGreen == 0 {
		trayGreen = loadIconFromICO(icoGreenData, 32)
		trayRed = loadIconFromICO(icoRedData, 32)
	}
	id, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(wp("TaskbarCreated"))))
	trayMsgID = uint32(id)
	registerTrayClass()
	hInst, _, _ := procGetModuleHandleW.Call(0)
	name := wp("LadderGuardTray")
	trayWnd, _, _ = procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(wp("LadderGuard"))), 0, 0, 0, 0, 0, 0, 0, hInst, 0)
	if trayWnd == 0 {
		logf("托盘窗口创建失败，将以无图标模式继续监控")
		select {}
	}
	if !trayAdd() {
		logf("托盘图标注册失败（可能系统限制），监控继续")
	}
	gLastMu.Lock()
	n := len(gLastIssues)
	gLastMu.Unlock()
	traySetState(n == 0)
	var m MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 || r == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	logf("收到退出指令，进程结束")
}

// ---------------- 监控主循环 ----------------

func issueKeys(issues []Issue) string {
	var ks []string
	for _, is := range issues {
		ks = append(ks, is.Key)
	}
	return strings.Join(ks, ",")
}

func runOnce() {
	checkMu.Lock()
	defer checkMu.Unlock()
	if gCfg == nil || gState == nil {
		return
	}
	s := runChecks(gCfg)
	issues := evaluate(s, gCfg, gState)
	cur := map[string]bool{}
	for _, is := range issues {
		cur[is.Key] = true
	}
	for k := range gPrevIssues {
		if !cur[k] {
			logf("问题已恢复: %s", k)
			cooldownDel(k) // 恢复后清除冷却，下次再犯立刻报
		}
	}
	gPrevIssues = cur
	gLastMu.Lock()
	gLastSnap = s
	gLastIssues = issues
	gLastAt = time.Now()
	gLastMu.Unlock()
	if len(issues) > 0 {
		rep := buildReport(s, issues, gCfg)
		SetClipboardText(rep)
		logf("报警: %d 个问题 [%s]", len(issues), issueKeys(issues))
		showAlert(issues, rep)
	} else {
		logf("检查正常 ports=%v tun=%v 默认出口=%s", s.AlivePorts, s.TunFound, geoText(s.DefaultExit))
	}
	traySetState(len(issues) == 0)
	saveState(gState)
}

func monitorLoop(cfg *Config) {
	gState = loadState()
	runOnce()
	t := time.NewTicker(time.Duration(cfg.IntervalSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			runOnce()
		case <-checkNowCh:
			runOnce()
		}
	}
}

// ---------------- 开机自启 / 单实例 ----------------

func autostartTarget() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	lower := strings.ToLower(exe)
	if strings.Contains(lower, "-console.exe") {
		gui := filepath.Join(filepath.Dir(exe), "LadderGuard.exe")
		if _, err := os.Stat(gui); err == nil {
			return gui // 自启必须指向无窗口的 GUI exe，不能带起黑框
		}
	}
	return exe
}

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

// RegGetValueW 的子键参数不能带根键前缀
const runKeySub = `Software\Microsoft\Windows\CurrentVersion\Run`

func installAutostart() error {
	target := autostartTarget()
	if target == "" {
		return fmt.Errorf("拿不到自身路径")
	}
	val := `"` + target + `"`
	cmd := exec.Command("reg", "add", runKey, "/v", "LadderGuard", "/t", "REG_SZ", "/d", val, "/f")
	runHiddenCmd(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func uninstallAutostart() error {
	cmd := exec.Command("reg", "delete", runKey, "/v", "LadderGuard", "/f")
	runHiddenCmd(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func singleInstance() bool {
	_, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(wp("LadderGuard.SingleInstance.Mutex"))))
	return err != syscall.ERROR_ALREADY_EXISTS
}

// ---------------- 测试场景 ----------------

func runTestScenario(name string) {
	registerClass()
	fakeVerge := VergeInfo{Found: true, Path: "%APPDATA%\\io.github.clash-verge-rev.clash-verge-rev\\verge.yaml",
		TunMode: "true", SysProxy: "false", MixedPort: "7890", AppVersion: "2.5.7"}
	canned := map[string]struct {
		snap   *Snap
		issues []Issue
	}{
		"leak": {
			snap: &Snap{AlivePorts: []int{7890}, TunFound: false, Verge: fakeVerge,
				RealIP: "203.0.113.66",
				DefaultExit: Geo{OK: true, IP: "203.0.113.66", CountryCode: "CN", Country: "中国", City: "杭州", ISP: "中国移动"},
				ProxyExit:   Geo{OK: true, IP: "198.51.100.7", CountryCode: "JP", Country: "日本", City: "东京", ISP: "IEPL"}},
			issues: []Issue{{Level: 2, Key: "leak", Tag: "泄漏", Title: "流量在裸奔，真实IP已暴露",
				Detail: "普通软件（包括 AI 客户端）现在的出口是 203.0.113.66（杭州 中国移动），这是你的真实宽带IP。【演示数据】",
				Fix:    "打开 Clash Verge → 设置 → 打开 TUN 模式（系统代理关掉）。改完等 30 秒，本工具自动复检。"}},
		},
		"sysproxy": {
			snap: &Snap{AlivePorts: []int{7890}, TunFound: true, SysProxyOn: true, SysProxySrv: "127.0.0.1:7890", Verge: fakeVerge,
				DefaultExit: Geo{OK: true, IP: "203.0.113.66", CountryCode: "CN", Country: "中国", City: "杭州", ISP: "中国移动"},
				ProxyExit:   Geo{OK: true, IP: "198.51.100.7", CountryCode: "JP", Country: "日本", City: "东京", ISP: "IEPL"}},
			issues: []Issue{{Level: 1, Key: "sysproxy", Tag: "系统代理", Title: "系统代理开着 —— 系统代理 = 找死",
				Detail: "浏览器是安全了，但 AI 桌面客户端、命令行工具根本不理系统代理，照样直连暴露真实IP。卷毛（Dario）的封号镰刀专砍这种配置。【演示数据】",
				Fix:    "关掉系统代理改用 TUN：Clash Verge → 设置 → 系统代理关、TUN 模式开。"}},
		},
		"region": {
			snap: &Snap{AlivePorts: []int{7890}, TunFound: true, Verge: fakeVerge,
				DefaultExit: Geo{OK: true, IP: "1.2.3.4", CountryCode: "HK", Country: "香港", City: "香港", ISP: "HKT"}},
			issues: []Issue{{Level: 2, Key: "risky-region", Tag: "高危地区", Title: "当前出口在 AI 服务高危地区",
				Detail: "出口地区：香港（节点 1.2.3.4）。Claude / GPT / Gemini 不支持这个地区，直接用 = 封号率飙升。【演示数据】",
				Fix:    "马上换节点：日本 / 新加坡 / 美国。Clash Verge → 代理 → 手动选节点。"}},
		},
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "panel" {
		cfg0 := defaultConfig()
		gCfg = &cfg0
		gLastMu.Lock()
		gLastSnap = &Snap{AlivePorts: []int{7890}, TunFound: true, TunName: "Meta",
			DefaultExit: Geo{OK: true, IP: "198.51.100.7", CountryCode: "JP", Country: "日本", City: "東京都", ISP: "IEPL"},
			ProxyExit:   Geo{OK: true, IP: "198.51.100.7", CountryCode: "JP", Country: "日本", City: "東京都", ISP: "IEPL"},
			Verge:       fakeVerge}
		gLastIssues = nil
		gLastAt = time.Now()
		gLastMu.Unlock()
		showStatusPanel()
		waitStatusClosed(10 * time.Minute)
		return
	}
	sc, ok := canned[name]
	if !ok {
		// all：把三个场景揉一起
		sc = canned["leak"]
		sc.issues = append(append([]Issue{}, canned["leak"].issues...), canned["sysproxy"].issues...)
		sc.issues = append(sc.issues, canned["region"].issues...)
	}
	cfg := defaultConfig()
	rep := buildReport(sc.snap, sc.issues, &cfg)
	SetClipboardText(rep)
	showAlert(sc.issues, rep)
	waitAlertClosed(10 * time.Minute)
}

// ---------------- 主入口 ----------------

func main() {
	arg0 := ""
	if len(os.Args) > 1 {
		arg0 = os.Args[1]
	}
	cmd := arg0
	scenario := ""
	if strings.HasPrefix(arg0, "-test=") {
		cmd = "-test"
		scenario = arg0[6:]
	}
	os.MkdirAll(dataDir(), 0755)
	logPath = filepath.Join(dataDir(), "LadderGuard.log")
	cfg := loadConfig()

	switch cmd {
	case "-version":
		attachConsole()
		fmt.Printf("LadderGuard v%s\n", Version)
	case "-diag":
		attachConsole()
		gState = loadState()
		s := runChecks(&cfg)
		stateMu.Lock()
		gState.LastAlert = map[string]int64{} // 诊断模式无视冷却，全量输出
		stateMu.Unlock()
		issues := evaluate(s, &cfg, gState)
		rep := buildReport(s, issues, &cfg)
		SetClipboardText(rep)
		fmt.Println(rep)
		fmt.Println("── 诊断报告已复制到剪贴板 ──")
	case "-ports":
		attachConsole()
		gState = loadState()
		s := runChecks(&cfg)
		fmt.Printf("识别到的代理端口: %v（来源: %s）\n", s.AlivePorts, orDash(s.PortSource))
		fmt.Printf("默认出口: %s\n", geoText(s.DefaultExit))
		fmt.Printf("代理出口: %s\n", geoText(s.ProxyExit))
	case "-full":
		attachConsole()
		gCfg = &cfg
		gState = loadState()
		rep, err := runFullCheck()
		if err != nil {
			fmt.Println("全面体检失败:", err)
			os.Exit(1)
		}
		fmt.Println(rep)
		fmt.Println("-- 报告已保存:", filepath.Join(dataDir(), "fullcheck-report.txt"))
		showFullReport(rep)
		waitReportClosed(15 * time.Minute)
	case "-test":
		runTestScenario(scenario)
	case "-install-autostart":
		attachConsole()
		if err := installAutostart(); err != nil {
			fmt.Println("失败:", err)
			os.Exit(1)
		}
		fmt.Println("已写入开机自启: HKCU\\...\\Run\\LadderGuard ->", autostartTarget())
	case "-uninstall-autostart":
		attachConsole()
		if err := uninstallAutostart(); err != nil {
			fmt.Println("失败:", err)
			os.Exit(1)
		}
		fmt.Println("已移除开机自启")
	default:
		if !singleInstance() {
			return
		}
		gCfg = &cfg
		logf("LadderGuard v%s 启动 | interval=%ds | ports=%v | expect_tun=%v | risky=%v",
			Version, cfg.IntervalSec, cfg.ProxyPorts, cfg.ExpectTUN, cfg.RiskyRegions)
		go monitorLoop(&cfg)
		runTrayLoop() // 主线程跑托盘消息循环，"退出"选中后进程结束
	}
}
