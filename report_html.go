package main

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParsedReport 结构化提取的体检数据
type ParsedReport struct {
	Raw         string
	IP          string
	ASN         string
	Org         string
	Country     string
	City        string
	Timezone    string
	IPType      string
	UsageType   string // 机房/商业/家庭宽带等

	// 风控评分
	IPQSScore       int
	IPQSLevel       string
	ScamalyticsScore int
	ScamalyticsLevel string
	IP2LocationScore int
	IP2LocationLevel string
	AbuseIPDBScore   int
	AbuseIPDBLevel   string

	// 风险因子
	IsProxy  bool
	IsVPN    bool
	IsServer bool
	IsAbuse  bool
	IsBot    bool

	// 解锁状态
	ChatGPTStatus string
	ChatGPTRegion string
	NetflixStatus string
	DisneyStatus  string
	TikTokStatus  string
	YouTubeStatus string

	// 黑名单
	BlacklistClean bool
	BlacklistText  string

	// 综合评价
	OverallRating string // safe, warning, danger
	ScoreTotal    int
	BadgeText     string
	Headline      string
	ClaudeAdvice  string
	GPTAdvice     string
	Summary       string
}

// parseFullReport 从原始文本中提取结构化字段并做风控判定
func parseFullReport(raw string) ParsedReport {
	p := ParsedReport{
		Raw:            raw,
		BlacklistClean: true,
		OverallRating:  "warning",
		ScoreTotal:     60,
	}

	// 1. IP
	if m := regexp.MustCompile(`IP质量体检报告：([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.IP = strings.TrimSpace(m[1])
	} else if m := regexp.MustCompile(`IPv4:\s*([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.IP = strings.TrimSpace(m[1])
	}
	if p.IP == "" {
		p.IP = "当前出口 IP"
	}

	// 2. ASN & 组织
	if m := regexp.MustCompile(`自治系统号：\s*([^\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.ASN = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`组织：\s*([^\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.Org = strings.TrimSpace(m[1])
	}

	// 3. 地区 & 城市
	if m := regexp.MustCompile(`使用地：\s*([^\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.Country = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`城市：\s*([^\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.City = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`IP类型：\s*([^\r\n]+)`).FindStringSubmatch(raw); len(m) > 1 {
		p.IPType = strings.TrimSpace(m[1])
	}

	// 4. 使用类型
	if strings.Contains(raw, "家庭宽带") || strings.Contains(raw, "住宅") {
		p.UsageType = "住宅原生 (ISP)"
	} else if strings.Contains(raw, "机房") {
		p.UsageType = "数据中心机房 (Hosting)"
	} else {
		p.UsageType = "商业/企业专线"
	}

	// 5. 评分提取
	if m := regexp.MustCompile(`IPQS[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.IPQSScore, _ = strconv.Atoi(m[1])
		p.IPQSLevel = m[2]
	}
	if m := regexp.MustCompile(`Scamalytics[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.ScamalyticsScore, _ = strconv.Atoi(m[1])
		p.ScamalyticsLevel = m[2]
	}
	if m := regexp.MustCompile(`IP2Location[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.IP2LocationScore, _ = strconv.Atoi(m[1])
		p.IP2LocationLevel = m[2]
	}
	if m := regexp.MustCompile(`AbuseIPDB[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.AbuseIPDBScore, _ = strconv.Atoi(m[1])
		p.AbuseIPDBLevel = m[2]
	}

	// 6. 风险因子判断
	p.IsProxy = strings.Contains(raw, "代理：") && strings.Contains(raw, "是")
	p.IsVPN = strings.Contains(raw, "VPN：") && strings.Contains(raw, "是")
	p.IsServer = strings.Contains(raw, "服务器：") && strings.Contains(raw, "是")
	p.IsAbuse = strings.Contains(raw, "滥用：") && strings.Contains(raw, "是")
	p.IsBot = strings.Contains(raw, "机器人：") && strings.Contains(raw, "是")

	// 7. 解锁服务状态
	if m := regexp.MustCompile(`ChatGPT[^\r\n]*\n[^\r\n]*状态：[^\r\n]*(解锁|屏蔽|失败)`).FindStringSubmatch(raw); len(m) > 1 {
		p.ChatGPTStatus = m[1]
	} else if strings.Contains(raw, "ChatGPT") && strings.Contains(raw, "解锁") {
		p.ChatGPTStatus = "解锁"
	} else if strings.Contains(raw, "ChatGPT") && strings.Contains(raw, "失败") {
		p.ChatGPTStatus = "失败/屏蔽"
	} else {
		p.ChatGPTStatus = "未检测"
	}

	if strings.Contains(raw, "Netflix") && strings.Contains(raw, "解锁") {
		p.NetflixStatus = "原生解锁"
	} else {
		p.NetflixStatus = "未解锁/部分"
	}

	if strings.Contains(raw, "Disney+") && strings.Contains(raw, "解锁") {
		p.DisneyStatus = "解锁"
	} else {
		p.DisneyStatus = "屏蔽/未解锁"
	}

	if strings.Contains(raw, "TikTok") && strings.Contains(raw, "解锁") {
		p.TikTokStatus = "解锁"
	} else {
		p.TikTokStatus = "限制"
	}

	if strings.Contains(raw, "Youtube") && (strings.Contains(raw, "解锁") || strings.Contains(raw, "原生")) {
		p.YouTubeStatus = "解锁"
	} else {
		p.YouTubeStatus = "正常访问"
	}

	// 8. 黑名单
	if m := regexp.MustCompile(`IP地址黑名单数据库：[^\r\n]*已标记\s*(\d+)[^\r\n]*黑名单\s*(\d+)`).FindStringSubmatch(raw); len(m) > 2 {
		mk, _ := strconv.Atoi(m[1])
		bl, _ := strconv.Atoi(m[2])
		if mk > 0 || bl > 0 {
			p.BlacklistClean = false
			p.BlacklistText = fmt.Sprintf("已标记 %d 处，黑名单 %d 处（存在风控拦截）", mk, bl)
		} else {
			p.BlacklistText = "423 个反欺诈库 0 标记（全绿放行）"
		}
	} else {
		p.BlacklistText = "主流反垃圾库无明显标记"
	}

	// 9. 大白话风控裁决算法
	calcAIRating(&p)
	return p
}

// calcAIRating 根据风控指标计算大白话评级
func calcAIRating(p *ParsedReport) {
	score := 100

	if p.IPQSScore > 0 {
		score -= int(float64(p.IPQSScore) * 0.45)
	}
	if p.IP2LocationScore > 50 {
		score -= 15
	}
	if p.ScamalyticsScore > 30 {
		score -= 20
	}
	if p.IsProxy {
		score -= 10
	}
	if p.IsAbuse {
		score -= 15
	}
	if strings.Contains(p.IPType, "广播") {
		score -= 10
	}
	if strings.Contains(p.Country, "香港") || strings.Contains(p.Country, "HK") {
		score -= 25
	}
	if p.ChatGPTStatus == "失败/屏蔽" || p.ChatGPTStatus == "失败" {
		score -= 15
	}
	if !p.BlacklistClean {
		score -= 20
	}

	if score < 0 {
		score = 0
	}
	p.ScoreTotal = score

	if score <= 45 || p.IPQSScore >= 80 || (strings.Contains(p.Country, "香港") && p.IPQSScore >= 50) {
		p.OverallRating = "danger"
		p.BadgeText = "极度高危 · 劝退切节点"
		p.Headline = "达里奥的封号镰刀已悬在头顶！严禁在此节点登录 Claude 账号"

		p.ClaudeAdvice = fmt.Sprintf("此 IP 在权威反欺诈库 IPQS 评分高达 %d 分（高危），且为数据中心/广播特征。Claude 对机房指纹实行零容忍清洗政策，登录大概率直接触发封号或静音封禁，请立即更换为纯净原生节点！", p.IPQSScore)
		if p.ChatGPTStatus == "失败/屏蔽" || p.ChatGPTStatus == "失败" {
			p.GPTAdvice = "OpenAI 防火墙已拦截该 IP 出口，无法直接访问 ChatGPT，强行使用会提示 Access Denied。"
		} else {
			p.GPTAdvice = "ChatGPT 虽然勉强放行，但高欺诈分会导致频繁弹出 Cloudflare 验证码、降智到基础模型甚至突发封号。"
		}
		p.Summary = fmt.Sprintf("典型“万人踩机场机房 IP”（组织: %s, 地区: %s）。刷常规流媒体尚可，用于核心 AI 账号无异于裸奔找死。", p.Org, p.Country)

	} else if score <= 75 || p.IPQSScore >= 35 || p.IsProxy {
		p.OverallRating = "warning"
		p.BadgeText = "中度风险 · 谨慎冲浪"
		p.Headline = "普通商业机房节点，日常浏览可用，关键 AI 资产请留意"

		p.ClaudeAdvice = "该节点具有常规机房特征，若用于 Claude 必须保持该节点固定，严禁频繁异地乱跳，否则易遭连坐风控。"
		p.GPTAdvice = "ChatGPT / Gemini 能够正常对话，偶有验证码属于正常现象。"
		p.Summary = fmt.Sprintf("常规数据中心商业 IP（组织: %s），综合欺诈分 %d。建议重要付费订阅号尽量避开高峰期并发使用。", p.Org, p.IPQSScore)

	} else {
		p.OverallRating = "safe"
		p.BadgeText = "纯净安全 · 放心使用"
		p.Headline = "低风险优质节点！IP 纯净度高，AI 冲浪安心无忧"

		p.ClaudeAdvice = "IPQS 欺诈分极低，未见明显滥用标记，Claude 封号风险极低，可放心进行核心生产力工作。"
		p.GPTAdvice = "OpenAI 官方服务原生支持良好，网络指纹纯净，访问流畅无阻碍。"
		p.Summary = fmt.Sprintf("高质量网络环境（组织: %s, 地区: %s），各项全球风控库表现优异。", p.Org, p.Country)
	}
}

func formatASN(asn string) string {
	asn = strings.TrimSpace(asn)
	if asn == "" {
		return "ASN 未知"
	}
	if strings.HasPrefix(strings.ToUpper(asn), "AS") {
		return asn
	}
	return "AS" + asn
}

// generateHTMLReport 采用 Cyber Tactical Threat Dossier（网络战术防封情报站）设计语言
func generateHTMLReport(p ParsedReport) string {
	accentColor := "#ff2a55" // tactical neon rose
	accentBg := "rgba(255, 42, 85, 0.08)"
	accentBorder := "rgba(255, 42, 85, 0.3)"
	accentGlow := "rgba(255, 42, 85, 0.22)"
	scoreColor := "#ff4d6d"

	if p.OverallRating == "warning" {
		accentColor = "#ffaa00" // tactical amber
		accentBg = "rgba(255, 170, 0, 0.08)"
		accentBorder = "rgba(255, 170, 0, 0.3)"
		accentGlow = "rgba(255, 170, 0, 0.22)"
		scoreColor = "#ffc107"
	} else if p.OverallRating == "safe" {
		accentColor = "#00e599" // tactical neon emerald
		accentBg = "rgba(0, 229, 153, 0.08)"
		accentBorder = "rgba(0, 229, 153, 0.3)"
		accentGlow = "rgba(0, 229, 153, 0.22)"
		scoreColor = "#2ee59d"
	}

	purityText := "广播 / 机房共享"
	if !strings.Contains(p.IPType, "广播") && !strings.Contains(p.UsageType, "机房") {
		purityText = "原生 / 纯净宽带"
	}

	arcOffset := 314.16 * (1.0 - float64(p.ScoreTotal)/100.0)
	if arcOffset < 0 {
		arcOffset = 0
	} else if arcOffset > 314.16 {
		arcOffset = 314.16
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")

	aiPromptText := fmt.Sprintf(`【LadderGuard 梯子体检报告】
体检时间：%s
当前出口 IP：%s (%s - %s)
IP 属性：%s | %s
风控评分：IPQS欺诈分 %d/100 | Scamalytics %d | IP2Location %d
安全因子：代理=%v, VPN=%v, 滥用=%v, 机器人=%v
AI 解锁：ChatGPT=%s
综合判定：%s (防封指数 %d/100)
Claude 专评：%s
ChatGPT 专评：%s
节点定性：%s`,
		nowStr, p.IP, p.Country, p.Org, p.IPType, p.UsageType,
		p.IPQSScore, p.ScamalyticsScore, p.IP2LocationScore,
		p.IsProxy, p.IsVPN, p.IsAbuse, p.IsBot,
		p.ChatGPTStatus,
		p.BadgeText, p.ScoreTotal,
		p.ClaudeAdvice, p.GPTAdvice, p.Summary,
	)

	templateHTML := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LadderGuard // 战术级网络风控与防封情报</title>
<style>
  :root {
    --bg-base: #06070a;
    --bg-card: rgba(13, 17, 24, 0.88);
    --border-card: rgba(255, 255, 255, 0.08);
    --border-highlight: rgba(255, 255, 255, 0.16);
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent: {{ACCENT_COLOR}};
    --accent-bg: {{ACCENT_BG}};
    --accent-border: {{ACCENT_BORDER}};
    --accent-glow: {{ACCENT_GLOW}};
    --font-mono: "JetBrains Mono", "SF Mono", "Roboto Mono", Consolas, monospace;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg-base);
    background-image: 
      radial-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
      radial-gradient(ellipse 90% 40% at 50% -10%, var(--accent-glow) 0%, transparent 65%);
    background-size: 24px 24px, 100% 100%;
    color: var(--text-primary);
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
    padding: 32px 20px 80px;
    line-height: 1.5;
    min-height: 100vh;
  }
  .app-layout { max-width: 1100px; margin: 0 auto; }

  @keyframes beaconPulse {
    0%, 100% { opacity: 1; transform: scale(1); box-shadow: 0 0 0 0 var(--accent); }
    50% { opacity: 0.85; transform: scale(1.15); box-shadow: 0 0 10px 4px var(--accent); }
  }

  /* Header */
  .top-bar {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 24px; padding-bottom: 16px;
    border-bottom: 1px solid var(--border-card);
  }
  .brand-group { display: flex; align-items: center; gap: 14px; }
  .shield-box {
    width: 40px; height: 40px; border-radius: 10px;
    background: linear-gradient(135deg, #1e293b, #090d16);
    border: 1px solid var(--border-highlight);
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.1);
  }
  .shield-box svg { width: 20px; height: 20px; stroke: #38bdf8; fill: none; stroke-width: 2; }
  .brand-title-row { display: flex; align-items: center; gap: 10px; }
  .brand-name { font-size: 18px; font-weight: 800; letter-spacing: -0.02em; color: #fff; }
  .status-badge {
    font-family: var(--font-mono); font-size: 10.5px; font-weight: 700;
    padding: 2px 8px; border-radius: 4px;
    background: rgba(56, 189, 248, 0.12); color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.28);
    letter-spacing: 0.05em; text-transform: uppercase;
  }
  .brand-meta {
    display: flex; align-items: center; gap: 8px; margin-top: 4px;
    font-size: 12px; color: var(--text-muted);
  }
  .meta-chip {
    font-family: var(--font-mono); font-size: 11px;
    padding: 2px 8px; border-radius: 4px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #e2e8f0;
  }
  .btn-copy {
    background: linear-gradient(180deg, #1e293b, #0f172a);
    color: #f8fafc; border: 1px solid rgba(56, 189, 248, 0.35);
    padding: 9px 18px; border-radius: 8px;
    font-size: 13px; font-weight: 700; cursor: pointer;
    display: flex; align-items: center; gap: 8px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.1);
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .btn-copy svg { width: 14px; height: 14px; stroke: #38bdf8; fill: none; stroke-width: 2; }
  .btn-copy:hover {
    background: linear-gradient(180deg, #334155, #1e293b);
    border-color: #38bdf8; transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(56, 189, 248, 0.2);
  }
  .btn-copy:active { transform: translateY(0); }

  /* Hero Split Grid */
  .hero-grid {
    display: grid; grid-template-columns: 310px 1fr; gap: 20px;
    margin-bottom: 24px;
  }
  .card-module {
    background: var(--bg-card);
    backdrop-filter: blur(14px);
    border: 1px solid var(--border-card);
    border-radius: 14px; padding: 22px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.45);
    position: relative; overflow: hidden;
  }
  .card-module::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent);
  }

  /* Left Gauge Panel */
  .gauge-card {
    display: flex; flex-direction: column; align-items: center; justify-content: space-between;
    text-align: center; border-color: var(--accent-border);
    background: linear-gradient(180deg, var(--accent-bg) 0%, var(--bg-card) 60%);
    box-shadow: 0 12px 36px var(--accent-glow);
  }
  .panel-eyebrow {
    width: 100%; display: flex; justify-content: space-between; align-items: center;
    font-family: var(--font-mono); font-size: 11px; font-weight: 700;
    color: var(--text-muted); letter-spacing: 0.06em;
  }
  .live-dot {
    display: inline-flex; align-items: center; gap: 6px;
    color: var(--accent); font-size: 10.5px;
  }
  .beacon-led {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--accent);
    animation: beaconPulse 2s infinite ease-in-out;
  }
  .gauge-svg-wrap {
    width: 230px; height: 185px; position: relative;
    display: flex; align-items: center; justify-content: center;
    margin: 6px 0;
  }
  .gauge-svg { width: 100%; height: 100%; overflow: visible; }
  .gauge-status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 14px; border-radius: 20px;
    background: rgba(0, 0, 0, 0.45);
    border: 1px solid var(--accent-border);
    color: var(--accent); font-size: 12px; font-weight: 800;
    letter-spacing: 0.03em;
  }
  .gauge-sub-row {
    width: 100%; display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
    margin-top: 14px; padding-top: 14px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
  }
  .gauge-meta-cell { text-align: center; }
  .meta-title { font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; }
  .meta-val { font-size: 12px; font-weight: 700; color: #f1f5f9; margin-top: 2px; }

  /* Right Directives Panel */
  .directive-card {
    display: flex; flex-direction: column; justify-content: space-between;
  }
  .threat-flag-row {
    display: flex; align-items: center; gap: 8px; margin-bottom: 12px;
  }
  .threat-flag-tag {
    font-family: var(--font-mono); font-size: 11px; font-weight: 800;
    color: #fff; background: var(--accent);
    padding: 2px 10px; border-radius: 4px;
    letter-spacing: 0.06em; text-transform: uppercase;
  }
  .threat-flag-sub { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }
  .threat-headline {
    font-size: 21px; font-weight: 800; color: #ffffff;
    letter-spacing: -0.025em; line-height: 1.35; margin-bottom: 8px;
  }
  .threat-desc {
    font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 18px;
  }
  .advisor-deck {
    display: grid; grid-template-columns: 1fr 1fr; gap: 14px;
  }
  .advisor-box {
    background: rgba(0, 0, 0, 0.28);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 10px; padding: 14px 16px;
  }
  .advisor-box.claude { border-left: 3px solid #f97316; }
  .advisor-box.gpt { border-left: 3px solid #10b981; }
  .advisor-head {
    display: flex; align-items: center; gap: 8px; margin-bottom: 8px;
  }
  .advisor-head svg { width: 16px; height: 16px; stroke-width: 2; fill: none; }
  .advisor-box.claude .advisor-head svg { stroke: #f97316; }
  .advisor-box.gpt .advisor-head svg { stroke: #10b981; }
  .advisor-label { font-size: 12.5px; font-weight: 800; color: #f1f5f9; letter-spacing: -0.01em; }
  .advisor-text { font-size: 12.5px; color: var(--text-secondary); line-height: 1.55; }

  /* 2-Column Dashboard */
  .main-grid {
    display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 20px;
    margin-bottom: 24px;
  }
  .module-head {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 18px; padding-bottom: 10px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }
  .module-title {
    font-size: 13.5px; font-weight: 800; color: #fff;
    display: flex; align-items: center; gap: 8px; letter-spacing: -0.01em;
  }
  .module-title svg { width: 16px; height: 16px; stroke: #38bdf8; fill: none; stroke-width: 2; }
  
  /* Telemetry Bars */
  .telemetry-list { display: flex; flex-direction: column; gap: 14px; margin-bottom: 20px; }
  .bar-item { display: flex; flex-direction: column; gap: 5px; }
  .bar-meta { display: flex; justify-content: space-between; align-items: baseline; }
  .bar-name { font-size: 12px; font-weight: 600; color: #cbd5e1; }
  .bar-score { font-family: var(--font-mono); font-size: 12px; font-weight: 700; }
  .bar-track {
    height: 7px; border-radius: 4px;
    background: rgba(255, 255, 255, 0.05);
    overflow: hidden; position: relative;
  }
  .bar-fill { height: 100%; border-radius: 4px; transition: width 0.8s ease; }
  .bar-ruler {
    display: flex; justify-content: space-between;
    font-family: var(--font-mono); font-size: 9px; color: #475569;
    padding: 2px 2px 0;
  }

  /* Chip Matrix */
  .chip-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .tactical-chip {
    padding: 8px 12px; border-radius: 8px;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.05);
    display: flex; flex-direction: column; gap: 2px;
  }
  .tactical-chip.active { border-color: rgba(244, 63, 94, 0.35); background: rgba(244, 63, 94, 0.06); }
  .tactical-chip.clean { border-color: rgba(16, 185, 129, 0.35); background: rgba(16, 185, 129, 0.06); }
  .chip-k { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); text-transform: uppercase; }
  .chip-v { font-size: 12px; font-weight: 700; color: #f1f5f9; }
  .tactical-chip.active .chip-v { color: #fb7185; }
  .tactical-chip.clean .chip-v { color: #34d399; }

  /* Service Matrix */
  .service-list { display: flex; flex-direction: column; gap: 9px; }
  .service-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 9px 14px; border-radius: 8px;
    background: rgba(255, 255, 255, 0.015);
    border: 1px solid rgba(255, 255, 255, 0.04);
  }
  .service-id {
    display: flex; align-items: center; gap: 10px;
    font-size: 13px; font-weight: 700; color: #f1f5f9;
  }
  .service-id svg { width: 16px; height: 16px; stroke-width: 2; fill: none; }
  .tag-status {
    font-family: var(--font-mono); font-size: 11px; font-weight: 700;
    padding: 3px 9px; border-radius: 5px; letter-spacing: 0.03em;
  }
  .tag-status.ok { color: #34d399; background: rgba(52, 211, 153, 0.12); border: 1px solid rgba(52, 211, 153, 0.3); }
  .tag-status.fail { color: #f87171; background: rgba(248, 113, 113, 0.12); border: 1px solid rgba(248, 113, 113, 0.3); }
  .tag-status.warn { color: #fbbf24; background: rgba(251, 191, 36, 0.12); border: 1px solid rgba(251, 191, 36, 0.3); }

  /* Terminal Window */
  .terminal-card {
    background: #040507; border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px; overflow: hidden;
  }
  .terminal-chrome {
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 16px; background: #0c0f17;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    cursor: pointer; user-select: none;
  }
  .terminal-dots { display: flex; gap: 6px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot.r { background: #ef4444; } .dot.y { background: #f59e0b; } .dot.g { background: #10b981; }
  .terminal-title { font-family: var(--font-mono); font-size: 11.5px; color: #94a3b8; font-weight: 600; }
  .terminal-toggle { font-family: var(--font-mono); font-size: 11px; color: #38bdf8; }
  .terminal-body {
    padding: 18px; font-family: var(--font-mono);
    font-size: 11.5px; color: #818cf8; line-height: 1.65;
    white-space: pre-wrap; overflow-x: auto; max-height: 380px;
  }

  /* Toast Notification */
  #toast {
    position: fixed; bottom: 28px; right: 28px;
    background: #0f172a; color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.4);
    box-shadow: 0 12px 36px rgba(0,0,0,0.6);
    padding: 12px 22px; border-radius: 8px;
    font-size: 13px; font-weight: 700;
    opacity: 0; transform: translateY(12px);
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    pointer-events: none; display: flex; align-items: center; gap: 10px;
    z-index: 999;
  }
  #toast.show { opacity: 1; transform: translateY(0); }

  @media (max-width: 860px) {
    .hero-grid { grid-template-columns: 1fr; }
    .advisor-deck { grid-template-columns: 1fr; }
    .main-grid { grid-template-columns: 1fr; }
    .chip-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="app-layout">

  <!-- Top Bar -->
  <header class="top-bar">
    <div class="brand-group">
      <div class="shield-box">
        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <div class="brand-title-row">
          <span class="brand-name">LadderGuard // 战术风控情报</span>
          <span class="status-badge">TACTICAL AUDIT</span>
        </div>
        <div class="brand-meta">
          <span>{{TIME}}</span>
          <span>·</span>
          <span class="meta-chip">{{COUNTRY}}</span>
          <span class="meta-chip">{{IP}}</span>
          <span>·</span>
          <a href="https://github.com/xykt/IPQuality" target="_blank" rel="noopener noreferrer" style="color: #38bdf8; text-decoration: none; font-size: 11px; font-family: var(--font-mono); display: inline-flex; align-items: center; gap: 4px;">引擎: xykt/IPQuality</a>
        </div>
      </div>
    </div>
    <div>
      <button class="btn-copy" onclick="copyAIPrompt()">
        <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        复制 AI 诊断报告
      </button>
    </div>
  </header>

  <!-- Hero Split Grid: Left Master Gauge, Right Intercept Directives -->
  <section class="hero-grid">
    <!-- Left: Master Arc Gauge Card -->
    <div class="card-module gauge-card">
      <div class="panel-eyebrow">
        <span>RISK METER // 0-100</span>
        <span class="live-dot"><span class="beacon-led"></span>实时监控</span>
      </div>

      <div class="gauge-svg-wrap">
        <svg viewBox="0 0 240 200" class="gauge-svg">
          <defs>
            <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="{{ACCENT_COLOR}}"/>
              <stop offset="100%" stop-color="{{SCORE_COLOR}}"/>
            </linearGradient>
          </defs>
          <!-- Background Track (240 deg arc) -->
          <circle cx="120" cy="115" r="75" fill="none" stroke="rgba(255, 255, 255, 0.08)" stroke-width="12" stroke-linecap="round" stroke-dasharray="314.16 157.08" stroke-dashoffset="0" transform="rotate(150 120 115)"/>
          <!-- Active Progress Arc -->
          <circle cx="120" cy="115" r="75" fill="none" stroke="url(#gaugeGrad)" stroke-width="12" stroke-linecap="round" stroke-dasharray="314.16 157.08" stroke-dashoffset="{{GAUGE_OFFSET}}" transform="rotate(150 120 115)" style="transition: stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1);"/>
          <!-- Numeric Score -->
          <text x="120" y="112" text-anchor="middle" fill="#ffffff" font-size="46" font-weight="900" font-family="'JetBrains Mono', Consolas, monospace">{{SCORE}}</text>
          <text x="120" y="132" text-anchor="middle" fill="#94a3b8" font-size="10.5" font-weight="700" letter-spacing="1.5">防封指数 (满分100)</text>
        </svg>
      </div>

      <div class="gauge-status-pill">
        <span class="beacon-led"></span>
        <span>{{BADGE_TEXT}}</span>
      </div>

      <div class="gauge-sub-row">
        <div class="gauge-meta-cell">
          <div class="meta-title">防封状态</div>
          <div class="meta-val" style="color: {{SCORE_COLOR}};">{{BADGE_TEXT}}</div>
        </div>
        <div class="gauge-meta-cell">
          <div class="meta-title">节点纯净度</div>
          <div class="meta-val">{{PURITY}}</div>
        </div>
      </div>
    </div>

    <!-- Right: Intercept Directives & AI Advisor -->
    <div class="card-module directive-card">
      <div>
        <div class="threat-flag-row">
          <span class="threat-flag-tag">THREAT INTERCEPT // 拦截通牒</span>
          <span class="threat-flag-sub">组织: {{ORG}}</span>
        </div>
        <h2 class="threat-headline">{{HEADLINE}}</h2>
        <p class="threat-desc">{{SUMMARY}}</p>
      </div>

      <div class="advisor-deck">
        <div class="advisor-box claude">
          <div class="advisor-head">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polygon points="12 8 8 16 16 16"/></svg>
            <span class="advisor-label">Claude (Anthropic) 封号研判</span>
          </div>
          <p class="advisor-text">{{CLAUDE_ADVICE}}</p>
        </div>

        <div class="advisor-box gpt">
          <div class="advisor-head">
            <svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14.93V17a1 1 0 0 1-2 0v-.07a6 6 0 1 1 2 0z"/></svg>
            <span class="advisor-label">ChatGPT / Gemini 可用性</span>
          </div>
          <p class="advisor-text">{{GPT_ADVICE}}</p>
        </div>
      </div>
    </div>
  </section>

  <!-- 2-Column Main Dashboard -->
  <div class="main-grid">
    
    <!-- Left: Security & Fraud Engine -->
    <div class="card-module">
      <div class="module-head">
        <span class="module-title">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0 1 10 10"/><path d="m12 12 7-7"/></svg>
          反欺诈与网络指纹雷达
        </span>
        <span class="meta-chip">{{ORG}}</span>
      </div>

      <div class="telemetry-list">
        <!-- IPQS -->
        <div class="bar-item">
          <div class="bar-meta">
            <span class="bar-name">IPQS 欺诈评分 (行业最严风控库)</span>
            <span class="bar-score" style="color: {{IPQS_COLOR}};">{{IPQS_SCORE}} / 100 ({{IPQS_LEVEL}})</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: {{IPQS_PCT}}%; background: {{IPQS_COLOR}};"></div>
          </div>
          <div class="bar-ruler">
            <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
          </div>
        </div>

        <!-- Scamalytics -->
        <div class="bar-item">
          <div class="bar-meta">
            <span class="bar-name">Scamalytics 风险分</span>
            <span class="bar-score" style="color: {{SCAM_COLOR}};">{{SCAM_SCORE}} / 100 ({{SCAM_LEVEL}})</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: {{SCAM_PCT}}%; background: {{SCAM_COLOR}};"></div>
          </div>
          <div class="bar-ruler">
            <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
          </div>
        </div>

        <!-- IP2Location -->
        <div class="bar-item">
          <div class="bar-meta">
            <span class="bar-name">IP2Location 代理威胁</span>
            <span class="bar-score" style="color: {{IP2LOC_COLOR}};">{{IP2LOC_SCORE}} / 100 ({{IP2LOC_LEVEL}})</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: {{IP2LOC_PCT}}%; background: {{IP2LOC_COLOR}};"></div>
          </div>
          <div class="bar-ruler">
            <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
          </div>
        </div>
      </div>

      <!-- Feature Tags -->
      <div class="chip-grid">
        <div class="tactical-chip {{IP_TYPE_CLASS}}">
          <span class="chip-k">网络类型</span>
          <span class="chip-v">{{IP_TYPE}}</span>
        </div>
        <div class="tactical-chip {{USAGE_TYPE_CLASS}}">
          <span class="chip-k">使用属性</span>
          <span class="chip-v">{{USAGE_TYPE}}</span>
        </div>
        <div class="tactical-chip {{PROXY_CLASS}}">
          <span class="chip-k">代理标记</span>
          <span class="chip-v">{{PROXY_TEXT}}</span>
        </div>
        <div class="tactical-chip {{BLACKLIST_CLASS}}">
          <span class="chip-k">黑名单库</span>
          <span class="chip-v">{{BLACKLIST_TEXT}}</span>
        </div>
      </div>
    </div>

    <!-- Right: Service Unlock Matrix -->
    <div class="card-module">
      <div class="module-head">
        <span class="module-title">
          <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          平台准入与解锁矩阵
        </span>
        <span class="meta-chip">多协议实测</span>
      </div>

      <div class="service-list">
        <div class="service-row">
          <span class="service-id">
            <svg viewBox="0 0 24 24" stroke="#10b981"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14.93V17a1 1 0 0 1-2 0v-.07a6 6 0 1 1 2 0z"/></svg>
            ChatGPT (OpenAI)
          </span>
          <span class="tag-status {{GPT_STATUS_CLASS}}">{{GPT_STATUS}}</span>
        </div>
        <div class="service-row">
          <span class="service-id">
            <svg viewBox="0 0 24 24" stroke="#e50914"><path d="M4 2v20l6-4V2zm10 0v16l6 4V2z"/></svg>
            Netflix
          </span>
          <span class="tag-status {{NETFLIX_STATUS_CLASS}}">{{NETFLIX_STATUS}}</span>
        </div>
        <div class="service-row">
          <span class="service-id">
            <svg viewBox="0 0 24 24" stroke="#38bdf8"><path d="M12 2a10 10 0 0 0-9.95 9h19.9A10 10 0 0 0 12 2zm-8.66 11A10 10 0 0 0 12 22a10 10 0 0 0 8.66-9z"/></svg>
            Disney+
          </span>
          <span class="tag-status {{DISNEY_STATUS_CLASS}}">{{DISNEY_STATUS}}</span>
        </div>
        <div class="service-row">
          <span class="service-id">
            <svg viewBox="0 0 24 24" stroke="#ec4899"><path d="M9 12a4 4 0 1 0 4 4V4a5 5 0 0 0 5 5"/></svg>
            TikTok
          </span>
          <span class="tag-status {{TIKTOK_STATUS_CLASS}}">{{TIKTOK_STATUS}}</span>
        </div>
        <div class="service-row">
          <span class="service-id">
            <svg viewBox="0 0 24 24" stroke="#ef4444"><rect x="2" y="5" width="20" height="14" rx="4"/><polygon points="10 9 15 12 10 15"/></svg>
            YouTube Premium
          </span>
          <span class="tag-status {{YOUTUBE_STATUS_CLASS}}">{{YOUTUBE_STATUS}}</span>
        </div>
      </div>

      <div style="margin-top: 18px; font-size: 11.5px; color: var(--text-muted); line-height: 1.55; border-top: 1px solid rgba(255,255,255,0.04); padding-top: 12px;">
        准入提示：流媒体放行仅代表 CDN 节点直通；AI 核心模型需同时保证 IPQS 欺诈分 &lt; 35 且无广播/机房标签。
      </div>
    </div>

  </div>

  <!-- Terminal Raw Log Window -->
  <div class="terminal-card">
    <div class="terminal-chrome" onclick="toggleTerminal()">
      <div class="terminal-dots">
        <span class="dot r"></span>
        <span class="dot y"></span>
        <span class="dot g"></span>
      </div>
      <span class="terminal-title">ladderguard // powered by xykt/IPQuality engine</span>
      <span class="terminal-toggle" id="terminalToggleBtn">[ 点击折叠 / 展开 90+ 项原始日志 ]</span>
    </div>
    <div class="terminal-body" id="terminalBody">{{RAW_LOG}}</div>
  </div>

  <!-- Credits & Attribution -->
  <footer style="margin-top: 32px; padding-top: 18px; border-top: 1px solid rgba(255, 255, 255, 0.06); display: flex; justify-content: center; align-items: center; font-size: 11.5px; color: var(--text-muted); gap: 6px; flex-wrap: wrap; text-align: center;">
    <span>核心体检引擎基于开源项目</span>
    <a href="https://github.com/xykt/IPQuality" target="_blank" rel="noopener noreferrer" style="color: #38bdf8; text-decoration: none; font-weight: 700; font-family: var(--font-mono);">xykt/IPQuality</a>
    <span>· 遵循开源规范 · 特别致敬并感谢原作者 @xykt</span>
  </footer>

</div>

<!-- Copy Feedback Toast -->
<div id="toast">
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
  已将结构化 AI 诊断报告复制到剪贴板！
</div>

<script>
  const promptData = {{AI_PROMPT_DATA}};

  function copyAIPrompt() {
    navigator.clipboard.writeText(promptData).then(() => {
      showToast();
    }).catch(() => {
      const ta = document.createElement("textarea");
      ta.value = promptData;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      showToast();
    });
  }

  function showToast() {
    const t = document.getElementById("toast");
    t.classList.add("show");
    setTimeout(() => { t.classList.remove("show"); }, 2600);
  }

  function toggleTerminal() {
    const b = document.getElementById("terminalBody");
    const btn = document.getElementById("terminalToggleBtn");
    if (b.style.display === "none") {
      b.style.display = "block";
      btn.innerText = "[ 点击收起日志 ]";
    } else {
      b.style.display = "none";
      btn.innerText = "[ 点击展开 90+ 项原始日志 ]";
    }
  }
</script>
</body>
</html>`

	replacer := strings.NewReplacer(
		"{{ACCENT_COLOR}}", accentColor,
		"{{ACCENT_BG}}", accentBg,
		"{{ACCENT_BORDER}}", accentBorder,
		"{{ACCENT_GLOW}}", accentGlow,
		"{{SCORE_COLOR}}", scoreColor,
		"{{SCORE}}", fmt.Sprintf("%d", p.ScoreTotal),
		"{{GAUGE_OFFSET}}", fmt.Sprintf("%.1f", arcOffset),
		"{{TIME}}", nowStr,
		"{{IP}}", html.EscapeString(p.IP),
		"{{COUNTRY}}", html.EscapeString(p.Country),
		"{{ORG}}", html.EscapeString(p.Org),
		"{{BADGE_TEXT}}", html.EscapeString(p.BadgeText),
		"{{HEADLINE}}", html.EscapeString(p.Headline),
		"{{SUMMARY}}", html.EscapeString(p.Summary),
		"{{CLAUDE_ADVICE}}", html.EscapeString(p.ClaudeAdvice),
		"{{GPT_ADVICE}}", html.EscapeString(p.GPTAdvice),
		"{{PURITY}}", purityText,

		// IPQS
		"{{IPQS_COLOR}}", scoreBarColor(p.IPQSScore),
		"{{IPQS_SCORE}}", fmt.Sprintf("%d", p.IPQSScore),
		"{{IPQS_LEVEL}}", html.EscapeString(p.IPQSLevel),
		"{{IPQS_PCT}}", fmt.Sprintf("%d", clampPct(p.IPQSScore)),

		// Scamalytics
		"{{SCAM_COLOR}}", scoreBarColor(p.ScamalyticsScore),
		"{{SCAM_SCORE}}", fmt.Sprintf("%d", p.ScamalyticsScore),
		"{{SCAM_LEVEL}}", html.EscapeString(p.ScamalyticsLevel),
		"{{SCAM_PCT}}", fmt.Sprintf("%d", clampPct(p.ScamalyticsScore)),

		// IP2Location
		"{{IP2LOC_COLOR}}", scoreBarColor(p.IP2LocationScore),
		"{{IP2LOC_SCORE}}", fmt.Sprintf("%d", p.IP2LocationScore),
		"{{IP2LOC_LEVEL}}", html.EscapeString(p.IP2LocationLevel),
		"{{IP2LOC_PCT}}", fmt.Sprintf("%d", clampPct(p.IP2LocationScore)),

		// Feature Chips
		"{{IP_TYPE}}", html.EscapeString(p.IPType),
		"{{IP_TYPE_CLASS}}", pillRiskClass(p.IPType == "广播IP"),
		"{{USAGE_TYPE}}", html.EscapeString(p.UsageType),
		"{{USAGE_TYPE_CLASS}}", pillRiskClass(strings.Contains(p.UsageType, "机房")),
		"{{PROXY_TEXT}}", boolText(p.IsProxy, "被标记为代理", "未标记代理"),
		"{{PROXY_CLASS}}", pillRiskClass(p.IsProxy),
		"{{BLACKLIST_TEXT}}", html.EscapeString(p.BlacklistText),
		"{{BLACKLIST_CLASS}}", pillRiskClass(!p.BlacklistClean),

		// Platforms
		"{{GPT_STATUS}}", html.EscapeString(p.ChatGPTStatus),
		"{{GPT_STATUS_CLASS}}", unlockTagClass(p.ChatGPTStatus),
		"{{NETFLIX_STATUS}}", html.EscapeString(p.NetflixStatus),
		"{{NETFLIX_STATUS_CLASS}}", unlockTagClass(p.NetflixStatus),
		"{{DISNEY_STATUS}}", html.EscapeString(p.DisneyStatus),
		"{{DISNEY_STATUS_CLASS}}", unlockTagClass(p.DisneyStatus),
		"{{TIKTOK_STATUS}}", html.EscapeString(p.TikTokStatus),
		"{{TIKTOK_STATUS_CLASS}}", unlockTagClass(p.TikTokStatus),
		"{{YOUTUBE_STATUS}}", html.EscapeString(p.YouTubeStatus),
		"{{YOUTUBE_STATUS_CLASS}}", unlockTagClass(p.YouTubeStatus),

		// Terminal & JS
		"{{RAW_LOG}}", html.EscapeString(p.Raw),
		"{{AI_PROMPT_DATA}}", fmt.Sprintf("%q", aiPromptText),
	)

	return replacer.Replace(templateHTML)
}

func clampPct(val int) int {
	if val < 0 {
		return 0
	}
	if val > 100 {
		return 100
	}
	return val
}

func scoreBarColor(score int) string {
	if score >= 75 {
		return "#f43f5e" // rose-500
	} else if score >= 35 {
		return "#f59e0b" // amber-500
	}
	return "#10b981" // emerald-500
}

func pillRiskClass(isRisky bool) string {
	if isRisky {
		return "active"
	}
	return "clean"
}

func unlockTagClass(status string) string {
	if strings.Contains(status, "解锁") || strings.Contains(status, "正常") {
		return "ok"
	} else if strings.Contains(status, "屏蔽") || strings.Contains(status, "失败") {
		return "fail"
	}
	return "warn"
}

func boolText(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// openBrowserInDefault 打开系统默认浏览器展示 HTML 报告
func openBrowserInDefault(htmlPath string) error {
	cmd := exec.Command("cmd", "/c", "start", "", htmlPath)
	runHiddenCmd(cmd)
	return cmd.Start()
}

// saveAndOpenHTMLReport 核心入口：解析文本、生成 HTML 并唤起浏览器
func saveAndOpenHTMLReport(rawReport string) (string, error) {
	p := parseFullReport(rawReport)
	htmlContent := generateHTMLReport(p)

	dir := dataDir()
	os.MkdirAll(dir, 0755)
	target := filepath.Join(dir, "report.html")

	if err := os.WriteFile(target, []byte(htmlContent), 0644); err != nil {
		return "", fmt.Errorf("写入 HTML 报告失败: %w", err)
	}

	_ = openBrowserInDefault(target)
	return target, nil
}
