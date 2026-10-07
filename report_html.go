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

// generateHTMLReport 采用 Linear / Vercel 极简暗黑杂志化排版
func generateHTMLReport(p ParsedReport) string {
	accentColor := "#f43f5e" // rose-500
	accentBg := "rgba(244, 63, 94, 0.08)"
	accentBorder := "rgba(244, 63, 94, 0.22)"
	accentGlow := "rgba(244, 63, 94, 0.15)"
	scoreColor := "#fb7185"

	if p.OverallRating == "warning" {
		accentColor = "#f59e0b" // amber-500
		accentBg = "rgba(245, 158, 11, 0.08)"
		accentBorder = "rgba(245, 158, 11, 0.22)"
		accentGlow = "rgba(245, 158, 11, 0.15)"
		scoreColor = "#fbbf24"
	} else if p.OverallRating == "safe" {
		accentColor = "#10b981" // emerald-500
		accentBg = "rgba(16, 185, 129, 0.08)"
		accentBorder = "rgba(16, 185, 129, 0.22)"
		accentGlow = "rgba(16, 185, 129, 0.15)"
		scoreColor = "#34d399"
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

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LadderGuard 梯子全面体检报告 · IPQuality</title>
<style>
  :root {
    --bg-base: #08090d;
    --card-surface: rgba(255, 255, 255, 0.024);
    --card-surface-hover: rgba(255, 255, 255, 0.04);
    --border-subtle: rgba(255, 255, 255, 0.065);
    --border-highlight: rgba(255, 255, 255, 0.12);
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent: %s;
    --accent-bg: %s;
    --accent-border: %s;
    --accent-glow: %s;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg-base);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
    -webkit-font-smoothing: antialiased;
    padding: 36px 20px 80px;
    line-height: 1.55;
    min-height: 100vh;
  }
  .app-layout { max-width: 1080px; margin: 0 auto; }
  
  /* Topbar Header */
  .top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 28px;
    padding-bottom: 18px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .brand-group { display: flex; align-items: center; gap: 14px; }
  .shield-icon {
    width: 36px; height: 36px; border-radius: 9px;
    background: linear-gradient(145deg, #1e293b, #0f172a);
    border: 1px solid var(--border-highlight);
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
  }
  .shield-icon svg { width: 18px; height: 18px; fill: none; stroke: #38bdf8; stroke-width: 2; }
  .brand-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
  .brand-meta {
    display: flex; align-items: center; gap: 8px; margin-top: 2px;
    font-size: 12px; color: var(--text-muted);
  }
  .node-chip {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-subtle);
    padding: 1px 8px; border-radius: 4px;
    font-family: "SFMono-Regular", Consolas, monospace;
    color: #e2e8f0; font-size: 11px;
  }

  /* Actions */
  .btn-action {
    background: #0f172a;
    color: #f1f5f9;
    border: 1px solid var(--border-highlight);
    padding: 8px 16px; border-radius: 8px;
    font-size: 13px; font-weight: 600;
    cursor: pointer; transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    display: flex; align-items: center; gap: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  }
  .btn-action svg { width: 14px; height: 14px; stroke: #38bdf8; stroke-width: 2; fill: none; }
  .btn-action:hover {
    background: #1e293b; border-color: rgba(56, 189, 248, 0.4);
    transform: translateY(-1px); box-shadow: 0 4px 14px rgba(0,0,0,0.4);
  }
  .btn-action:active { transform: translateY(0); }

  /* Hero Verdict Banner */
  .hero-panel {
    background: linear-gradient(180deg, var(--accent-bg) 0%%, rgba(8, 9, 13, 0.6) 100%%);
    border: 1px solid var(--accent-border);
    border-radius: 14px;
    padding: 28px;
    margin-bottom: 24px;
    position: relative;
    box-shadow: 0 10px 40px var(--accent-glow);
  }
  .hero-header {
    display: flex; justify-content: space-between; align-items: flex-start;
    margin-bottom: 18px;
  }
  .rating-badge {
    display: inline-flex; align-items: center; gap: 8px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--accent-border);
    padding: 4px 12px; border-radius: 20px;
    font-size: 12px; font-weight: 700; letter-spacing: 0.03em;
    color: var(--accent); text-transform: uppercase;
  }
  .rating-dot { width: 7px; height: 7px; border-radius: 50%%; background: var(--accent); box-shadow: 0 0 8px var(--accent); }
  
  .score-box {
    text-align: right; font-family: "SFMono-Regular", Consolas, monospace;
  }
  .score-num { font-size: 38px; font-weight: 800; line-height: 1; }
  .score-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-top: 4px; }
  
  .verdict-headline {
    font-size: 22px; font-weight: 700; color: #ffffff;
    letter-spacing: -0.02em; margin-bottom: 10px; line-height: 1.35;
  }
  .verdict-desc {
    font-size: 14px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 22px; max-width: 880px;
  }

  /* Split Advisor Grid */
  .advisor-row {
    display: grid; grid-template-columns: 1fr 1fr; gap: 14px;
  }
  .advisor-box {
    background: rgba(0, 0, 0, 0.22);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 10px; padding: 16px 18px;
  }
  .advisor-header {
    display: flex; align-items: center; gap: 8px; margin-bottom: 8px;
  }
  .advisor-header svg { width: 16px; height: 16px; stroke-width: 2; fill: none; }
  .advisor-header.claude svg { stroke: #f97316; }
  .advisor-header.gpt svg { stroke: #10b981; }
  .advisor-title { font-size: 13px; font-weight: 700; color: #f1f5f9; letter-spacing: -0.01em; }
  .advisor-body { font-size: 13px; color: var(--text-secondary); line-height: 1.6; }

  /* 2-Column Dashboard */
  .main-grid {
    display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 20px;
  }

  .card-module {
    background: var(--card-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 20px;
  }
  .card-module-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-subtle);
  }
  .module-title {
    font-size: 13px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--text-secondary);
    display: flex; align-items: center; gap: 8px;
  }
  .module-title svg { width: 15px; height: 15px; stroke: var(--text-muted); stroke-width: 2; fill: none; }

  /* Metric Progress Rows */
  .metric-list { display: flex; flex-direction: column; gap: 14px; }
  .metric-entry { display: flex; flex-direction: column; gap: 6px; }
  .metric-meta { display: flex; justify-content: space-between; font-size: 12px; }
  .metric-name { color: #cbd5e1; font-weight: 500; }
  .metric-val { font-family: "SFMono-Regular", Consolas, monospace; font-weight: 700; }
  .bar-rail {
    height: 5px; width: 100%%; background: rgba(255, 255, 255, 0.05);
    border-radius: 3px; overflow: hidden;
  }
  .bar-fill { height: 100%%; border-radius: 3px; }

  /* Pills & Tags */
  .tag-cloud {
    display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; padding-top: 14px;
    border-top: 1px solid rgba(255,255,255,0.04);
  }
  .tech-pill {
    font-size: 11px; padding: 3px 10px; border-radius: 6px;
    background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-subtle);
    color: var(--text-muted); display: flex; align-items: center; gap: 6px;
  }
  .tech-pill.active { color: #f87171; border-color: rgba(248, 113, 113, 0.3); background: rgba(248, 113, 113, 0.06); }
  .tech-pill.clean { color: #34d399; border-color: rgba(52, 211, 153, 0.3); background: rgba(52, 211, 153, 0.06); }

  /* Service Unlock List */
  .unlock-table { display: flex; flex-direction: column; gap: 8px; }
  .unlock-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 12px; border-radius: 8px;
    background: rgba(255, 255, 255, 0.015);
    border: 1px solid rgba(255, 255, 255, 0.03);
  }
  .service-identity { font-size: 13px; font-weight: 600; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
  .status-tag {
    font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px;
    letter-spacing: 0.02em;
  }
  .status-tag.ok { color: #34d399; background: rgba(52, 211, 153, 0.1); border: 1px solid rgba(52, 211, 153, 0.25); }
  .status-tag.fail { color: #f87171; background: rgba(248, 113, 113, 0.1); border: 1px solid rgba(248, 113, 113, 0.25); }
  .status-tag.warn { color: #fbbf24; background: rgba(251, 191, 36, 0.1); border: 1px solid rgba(251, 191, 36, 0.25); }

  /* Details Log */
  .drawer-section { margin-top: 24px; }
  details {
    background: var(--card-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 12px; overflow: hidden;
  }
  summary {
    padding: 12px 18px; font-size: 13px; font-weight: 600; color: var(--text-muted);
    cursor: pointer; display: flex; justify-content: space-between; align-items: center;
    user-select: none; transition: background 0.2s;
  }
  summary:hover { background: rgba(255, 255, 255, 0.02); color: #e2e8f0; }
  .terminal-content {
    background: #040507; padding: 18px;
    font-family: "SFMono-Regular", Consolas, "Courier New", monospace;
    font-size: 11.5px; color: #818cf8; line-height: 1.65;
    overflow-x: auto; max-height: 380px; white-space: pre-wrap;
    border-top: 1px solid var(--border-subtle);
  }

  /* Toast */
  #toast {
    position: fixed; bottom: 24px; right: 24px;
    background: #0f172a; color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.35);
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600;
    opacity: 0; transform: translateY(8px); transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    pointer-events: none; display: flex; align-items: center; gap: 8px;
  }
  #toast.show { opacity: 1; transform: translateY(0); }

  @media (max-width: 820px) {
    .advisor-row { grid-template-columns: 1fr; }
    .main-grid { grid-template-columns: 1fr; }
    .score-box { text-align: left; margin-top: 10px; }
    .hero-header { flex-direction: column; }
  }
</style>
</head>
<body>
<div class="app-layout">

  <!-- Top Bar -->
  <header class="top-bar">
    <div class="brand-group">
      <div class="shield-icon">
        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <div class="brand-title">LadderGuard 梯子风控评估</div>
        <div class="brand-meta">
          <span>%s</span>
          <span>·</span>
          <span class="node-chip">%s</span>
          <span class="node-chip">%s</span>
        </div>
      </div>
    </div>
    <div>
      <button class="btn-action" onclick="copyAIPrompt()">
        <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        复制 AI 诊断报告
      </button>
    </div>
  </header>

  <!-- Hero Verdict Banner -->
  <section class="hero-panel">
    <div class="hero-header">
      <div class="rating-badge">
        <span class="rating-dot"></span>
        %s
      </div>
      <div class="score-box">
        <div class="score-num" style="color: %s;">%d</div>
        <div class="score-label">防封指数 (满分100)</div>
      </div>
    </div>
    
    <h2 class="verdict-headline">%s</h2>
    <p class="verdict-desc">%s</p>

    <div class="advisor-row">
      <div class="advisor-box">
        <div class="advisor-header claude">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="m10 15 5-3-5-3v6z"/></svg>
          <span class="advisor-title">Claude (Anthropic) 封号研判</span>
        </div>
        <p class="advisor-body">%s</p>
      </div>
      <div class="advisor-box">
        <div class="advisor-header gpt">
          <svg viewBox="0 0 24 24"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
          <span class="advisor-title">ChatGPT / Gemini 可用性</span>
        </div>
        <p class="advisor-body">%s</p>
      </div>
    </div>
  </section>

  <!-- 2-Column Main Dashboard -->
  <div class="main-grid">
    
    <!-- Left: Security & Fraud Engine -->
    <div class="card-module">
      <div class="card-module-header">
        <span class="module-title">
          <svg viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          反欺诈与网络指纹雷达
        </span>
        <span class="node-chip">%s</span>
      </div>

      <div class="metric-list">
        <!-- IPQS -->
        <div class="metric-entry">
          <div class="metric-meta">
            <span class="metric-name">IPQS 欺诈评分 (行业最严)</span>
            <span class="metric-val" style="color: %s;">%d / 100 (%s)</span>
          </div>
          <div class="bar-rail">
            <div class="bar-fill" style="width: %d%%; background: %s;"></div>
          </div>
        </div>

        <!-- Scamalytics -->
        <div class="metric-entry">
          <div class="metric-meta">
            <span class="metric-name">Scamalytics 风险分</span>
            <span class="metric-val" style="color: %s;">%d / 100 (%s)</span>
          </div>
          <div class="bar-rail">
            <div class="bar-fill" style="width: %d%%; background: %s;"></div>
          </div>
        </div>

        <!-- IP2Location -->
        <div class="metric-entry">
          <div class="metric-meta">
            <span class="metric-name">IP2Location 代理威胁</span>
            <span class="metric-val" style="color: %s;">%d / 100 (%s)</span>
          </div>
          <div class="bar-rail">
            <div class="bar-fill" style="width: %d%%; background: %s;"></div>
          </div>
        </div>
      </div>

      <!-- Feature Tags -->
      <div class="tag-cloud">
        <span class="tech-pill %s">网络类型: %s</span>
        <span class="tech-pill %s">使用属性: %s</span>
        <span class="tech-pill %s">代理标记: %s</span>
        <span class="tech-pill %s">黑名单库: %s</span>
      </div>
    </div>

    <!-- Right: Service Unlock Matrix -->
    <div class="card-module">
      <div class="card-module-header">
        <span class="module-title">
          <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          AI 平台与流媒体解锁状态
        </span>
        <span class="node-chip">多协议实测</span>
      </div>

      <div class="unlock-table">
        <div class="unlock-row">
          <span class="service-identity">ChatGPT (OpenAI)</span>
          <span class="status-tag %s">%s</span>
        </div>
        <div class="unlock-row">
          <span class="service-identity">Netflix</span>
          <span class="status-tag %s">%s</span>
        </div>
        <div class="unlock-row">
          <span class="service-identity">Disney+</span>
          <span class="status-tag %s">%s</span>
        </div>
        <div class="unlock-row">
          <span class="service-identity">TikTok</span>
          <span class="status-tag %s">%s</span>
        </div>
        <div class="unlock-row">
          <span class="service-identity">YouTube Premium</span>
          <span class="status-tag %s">%s</span>
        </div>
      </div>

      <div style="margin-top: 16px; font-size: 11.5px; color: var(--text-muted); line-height: 1.5;">
        注：流媒体仅代表 CDN 节点路由，AI 模型访问需同时满足 IPQS 欺诈分 &lt; 35 以及纯净无滥用记录。
      </div>
    </div>

  </div>

  <!-- Raw Log Drawer -->
  <div class="drawer-section">
    <details>
      <summary>
        <span>查看完整诊断终端日志（90+ 项指标明细）</span>
        <span style="font-family: monospace; font-size: 11px;">[展开/折叠]</span>
      </summary>
      <div class="terminal-content">%s</div>
    </details>
  </div>

</div>

<!-- Copy Feedback Toast -->
<div id="toast">
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
  已将结构化 AI 诊断报告复制到剪贴板！
</div>

<script>
  const promptData = %q;

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
</script>
</body>
</html>`,
		// CSS Vars
		accentColor, accentBg, accentBorder, accentGlow,
		// Header meta
		nowStr,
		html.EscapeString(p.Country),
		html.EscapeString(p.IP),

		// Hero banner
		html.EscapeString(p.BadgeText),
		scoreColor, p.ScoreTotal,
		html.EscapeString(p.Headline),
		html.EscapeString(p.Summary),
		html.EscapeString(p.ClaudeAdvice),
		html.EscapeString(p.GPTAdvice),

		// Left Card Header chip
		html.EscapeString(p.Org),

		// IPQS bar
		scoreBarColor(p.IPQSScore), p.IPQSScore, html.EscapeString(p.IPQSLevel),
		clampPct(p.IPQSScore), scoreBarColor(p.IPQSScore),

		// Scamalytics bar
		scoreBarColor(p.ScamalyticsScore), p.ScamalyticsScore, html.EscapeString(p.ScamalyticsLevel),
		clampPct(p.ScamalyticsScore), scoreBarColor(p.ScamalyticsScore),

		// IP2Location bar
		scoreBarColor(p.IP2LocationScore), p.IP2LocationScore, html.EscapeString(p.IP2LocationLevel),
		clampPct(p.IP2LocationScore), scoreBarColor(p.IP2LocationScore),

		// Feature Pills
		pillRiskClass(p.IPType == "广播IP"), html.EscapeString(p.IPType),
		pillRiskClass(strings.Contains(p.UsageType, "机房")), html.EscapeString(p.UsageType),
		pillRiskClass(p.IsProxy), boolText(p.IsProxy, "被标记为代理", "未标记代理"),
		pillRiskClass(!p.BlacklistClean), html.EscapeString(p.BlacklistText),

		// Right Unlocks
		unlockTagClass(p.ChatGPTStatus), html.EscapeString(p.ChatGPTStatus),
		unlockTagClass(p.NetflixStatus), html.EscapeString(p.NetflixStatus),
		unlockTagClass(p.DisneyStatus), html.EscapeString(p.DisneyStatus),
		unlockTagClass(p.TikTokStatus), html.EscapeString(p.TikTokStatus),
		unlockTagClass(p.YouTubeStatus), html.EscapeString(p.YouTubeStatus),

		// Raw Content
		html.EscapeString(p.Raw),
		aiPromptText,
	)
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
