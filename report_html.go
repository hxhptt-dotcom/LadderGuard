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
		p.UsageType = "住宅宽带 (ISP)"
	} else if strings.Contains(raw, "机房") {
		p.UsageType = "数据中心机房 (Hosting)"
	} else {
		p.UsageType = "商业/企业专线"
	}

	// 5. 评分提取
	// IPQS
	if m := regexp.MustCompile(`IPQS[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.IPQSScore, _ = strconv.Atoi(m[1])
		p.IPQSLevel = m[2]
	}
	// Scamalytics
	if m := regexp.MustCompile(`Scamalytics[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.ScamalyticsScore, _ = strconv.Atoi(m[1])
		p.ScamalyticsLevel = m[2]
	}
	// IP2Location
	if m := regexp.MustCompile(`IP2Location[^\d\r\n]*(\d+)[|/]([^\s\r\n]+)`).FindStringSubmatch(raw); len(m) > 2 {
		p.IP2LocationScore, _ = strconv.Atoi(m[1])
		p.IP2LocationLevel = m[2]
	}
	// AbuseIPDB
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
	// 基础分 100
	score := 100

	// 扣分项
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

	// 判定等级
	if score <= 45 || p.IPQSScore >= 80 || (strings.Contains(p.Country, "香港") && p.IPQSScore >= 50) {
		p.OverallRating = "danger"
		p.BadgeText = "💀 极度高危 · 劝退切节点"
		p.Headline = "达里奥的封号镰刀已悬在头顶！严禁在此节点登录 Claude 账号"

		p.ClaudeAdvice = fmt.Sprintf("【严重警告】此 IP 在 IPQS 欺诈评分高达 %d 分（高危），且被识别为数据中心/广播IP。Claude 对机房指纹实行零容忍清洗政策，登录几乎必触发封号或静音封禁，快换干净家宽或原生专线！", p.IPQSScore)
		if p.ChatGPTStatus == "失败/屏蔽" || p.ChatGPTStatus == "失败" {
			p.GPTAdvice = "【直接屏蔽】OpenAI 节点防火墙已拦截该 IP 出口，无法直接访问 ChatGPT，强行使用会提示 Access Denied。"
		} else {
			p.GPTAdvice = "【高危预警】ChatGPT 虽然勉强放行，但高欺诈分会导致频繁要求 Cloudflare 验证码、降智到简易模型或突发封号。"
		}
		p.Summary = fmt.Sprintf("这是一个典型的“万人踩机场机房 IP”（组织: %s, 地区: %s）。看流媒体剧集或许能爽，但用于 AI 账号无异于裸奔找死。", p.Org, p.Country)

	} else if score <= 75 || p.IPQSScore >= 35 || p.IsProxy {
		p.OverallRating = "warning"
		p.BadgeText = "⚠️ 中度风险 · 谨慎冲浪"
		p.Headline = "普通机房节点，日常浏览可用，关键 AI 资产请留意"

		p.ClaudeAdvice = "【建议观察】该节点具有一定的代理/机房特征，如果用于 Claude 必须保持该节点固定，严禁频繁与其它节点乱跳，否则易遭风控连坐。"
		p.GPTAdvice = "【基本可用】ChatGPT / Gemini 能够正常对话，偶有验证码属于正常现象。"
		p.Summary = fmt.Sprintf("常规数据中心商业 IP（组织: %s），欺诈分 %d。建议重要付费订阅号尽量避开高峰期并发使用。", p.Org, p.IPQSScore)

	} else {
		p.OverallRating = "safe"
		p.BadgeText = "🟢 纯净安全 · 放心使用"
		p.Headline = "低风险优质节点！IP 纯净度高，AI 冲浪安心无忧"

		p.ClaudeAdvice = "【安全放行】IPQS 欺诈分极低，未见明显滥用标记，Claude 封号风险极低，可放心进行生产力工作。"
		p.GPTAdvice = "【畅通无阻】OpenAI 服务原生支持良好，访问流畅无阻碍。"
		p.Summary = fmt.Sprintf("高质量原生网络环境（组织: %s, 地区: %s），各项风控库表现优异。", p.Org, p.Country)
	}
}

// generateHTMLReport 生成高颜值自包含 HTML 报告页面
func generateHTMLReport(p ParsedReport) string {
	themeColor := "#ef4444" // danger
	themeBg := "rgba(239, 68, 68, 0.12)"
	themeBorder := "rgba(239, 68, 68, 0.35)"
	if p.OverallRating == "warning" {
		themeColor = "#f59e0b"
		themeBg = "rgba(245, 158, 11, 0.12)"
		themeBorder = "rgba(245, 158, 11, 0.35)"
	} else if p.OverallRating == "safe" {
		themeColor = "#10b981"
		themeBg = "rgba(16, 185, 129, 0.12)"
		themeBorder = "rgba(16, 185, 129, 0.35)"
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")

	// 格式化一份一键复制给 AI 的诊断摘要
	aiPromptText := fmt.Sprintf(`【LadderGuard 梯子全面体检报告】
体检时间：%s
当前出口 IP：%s (%s - %s)
IP 类型：%s | %s
风控评分：IPQS欺诈分 %d/100 | Scamalytics %d | IP2Location %d
代理/滥用标记：代理=%v, VPN=%v, 滥用=%v, 机器人=%v
AI解锁：ChatGPT=%s
综合判定：%s (防封指数 %d/100)
大白话建议：%s
%s
原始报告：%s`,
		nowStr, p.IP, p.Country, p.Org, p.IPType, p.UsageType,
		p.IPQSScore, p.ScamalyticsScore, p.IP2LocationScore,
		p.IsProxy, p.IsVPN, p.IsAbuse, p.IsBot,
		p.ChatGPTStatus,
		p.BadgeText, p.ScoreTotal,
		p.ClaudeAdvice, p.Summary,
		p.Raw,
	)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LadderGuard 梯子体检报告 · IPQuality</title>
<style>
  :root {
    --bg: #0b0f19;
    --card: #131a29;
    --card-border: #1f2a40;
    --text-main: #f1f5f9;
    --text-muted: #94a3b8;
    --accent: %s;
    --accent-bg: %s;
    --accent-border: %s;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg);
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
    padding: 28px 20px 60px;
    line-height: 1.5;
    min-height: 100vh;
  }
  .container { max-width: 960px; margin: 0 auto; }
  
  /* Header */
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--card-border);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-logo {
    width: 38px; height: 38px; border-radius: 10px;
    background: linear-gradient(135deg, #10b981, #06b6d4);
    display: flex; align-items: center; justify-content: center;
    font-size: 20px; font-weight: bold; color: white;
    box-shadow: 0 4px 14px rgba(16, 185, 129, 0.3);
  }
  .brand h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
  .brand p { font-size: 13px; color: var(--text-muted); }
  
  .header-actions { display: flex; align-items: center; gap: 12px; }
  .btn-copy {
    background: linear-gradient(135deg, #3b82f6, #2563eb);
    color: white; border: none; padding: 9px 18px;
    border-radius: 8px; font-size: 13px; font-weight: 600;
    cursor: pointer; transition: all 0.2s; display: flex; align-items: center; gap: 6px;
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
  }
  .btn-copy:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(37, 99, 235, 0.35); }
  .btn-copy:active { transform: translateY(0); }
  
  /* Big Verdict Banner */
  .verdict-card {
    background: var(--accent-bg);
    border: 1px solid var(--accent-border);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 24px;
    backdrop-filter: blur(12px);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    position: relative;
    overflow: hidden;
  }
  .verdict-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .badge {
    background: var(--accent); color: white;
    padding: 5px 14px; border-radius: 20px;
    font-size: 13px; font-weight: 700; letter-spacing: 0.3px;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .score-dial {
    font-size: 28px; font-weight: 800; color: var(--accent);
    display: flex; align-items: baseline; gap: 4px;
  }
  .score-dial span { font-size: 13px; color: var(--text-muted); font-weight: normal; }
  
  .verdict-headline {
    font-size: 20px; font-weight: 700; margin-bottom: 12px;
    color: #ffffff;
  }
  .verdict-summary {
    font-size: 14px; color: #cbd5e1; margin-bottom: 16px; line-height: 1.6;
  }
  
  .advice-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 14px;
    background: rgba(0,0,0,0.25); border-radius: 12px; padding: 16px;
  }
  .advice-item h4 { font-size: 13px; font-weight: 700; margin-bottom: 6px; color: #f8fafc; }
  .advice-item p { font-size: 13px; color: #94a3b8; line-height: 1.5; }

  /* 4 Quadrants */
  .section-title {
    font-size: 15px; font-weight: 700; color: #cbd5e1;
    margin: 28px 0 14px; display: flex; align-items: center; gap: 8px;
  }
  .grid-4 {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px;
  }
  .metric-card {
    background: var(--card); border: 1px solid var(--card-border);
    border-radius: 12px; padding: 16px;
  }
  .metric-label { font-size: 12px; color: var(--text-muted); margin-bottom: 8px; }
  .metric-value { font-size: 22px; font-weight: 800; color: #f8fafc; margin-bottom: 4px; }
  .metric-tag { font-size: 11px; color: var(--text-muted); }
  
  /* Unlock Matrix */
  .grid-unlock {
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px;
  }
  .unlock-item {
    background: var(--card); border: 1px solid var(--card-border);
    border-radius: 10px; padding: 14px 12px; text-align: center;
  }
  .unlock-name { font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #cbd5e1; }
  .pill {
    display: inline-block; font-size: 12px; font-weight: 600;
    padding: 3px 10px; border-radius: 6px;
  }
  .pill-ok { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
  .pill-fail { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
  .pill-warn { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }

  /* Details Fold */
  details {
    margin-top: 28px; background: var(--card);
    border: 1px solid var(--card-border); border-radius: 12px;
    overflow: hidden;
  }
  summary {
    padding: 14px 18px; font-size: 14px; font-weight: 600;
    cursor: pointer; user-select: none; color: #cbd5e1;
    background: rgba(255, 255, 255, 0.02);
  }
  summary:hover { background: rgba(255, 255, 255, 0.05); }
  .terminal-box {
    padding: 16px; background: #07090e; font-family: "Consolas", "Courier New", monospace;
    font-size: 12px; color: #94a3b8; line-height: 1.6; overflow-x: auto;
    white-space: pre-wrap; border-top: 1px solid var(--card-border); max-height: 400px;
  }

  /* Toast */
  #toast {
    position: fixed; bottom: 24px; right: 24px;
    background: #10b981; color: white; padding: 10px 20px;
    border-radius: 8px; font-size: 13px; font-weight: 600;
    box-shadow: 0 4px 16px rgba(0,0,0,0.3); opacity: 0;
    transform: translateY(10px); transition: all 0.25s; pointer-events: none;
  }
  #toast.show { opacity: 1; transform: translateY(0); }

  @media (max-width: 768px) {
    .grid-4 { grid-template-columns: 1fr 1fr; }
    .grid-unlock { grid-template-columns: repeat(3, 1fr); }
    .advice-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="container">
  
  <!-- Header -->
  <div class="header">
    <div class="brand">
      <div class="brand-logo">🛡️</div>
      <div>
        <h1>LadderGuard 梯子全面体检报告</h1>
        <p>检测时间: %s · 引擎: xykt/IPQuality</p>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn-copy" onclick="copyAIPrompt()">
        📋 一键复制 AI 诊断报告
      </button>
    </div>
  </div>

  <!-- Big Verdict Card -->
  <div class="verdict-card">
    <div class="verdict-header">
      <div class="badge">%s</div>
      <div class="score-dial">%d <span>/ 100 防封指数</span></div>
    </div>
    <div class="verdict-headline">%s</div>
    <div class="verdict-summary">%s</div>
    
    <div class="advice-grid">
      <div class="advice-item">
        <h4>🤖 Claude / 达里奥防封专评</h4>
        <p>%s</p>
      </div>
      <div class="advice-item">
        <h4>🧠 ChatGPT / Gemini 可用性</h4>
        <p>%s</p>
      </div>
    </div>
  </div>

  <!-- 4 Core Metrics -->
  <div class="section-title">📊 核心风控指标四象限</div>
  <div class="grid-4">
    <div class="metric-card">
      <div class="metric-label">IPQS 欺诈评分 (最严)</div>
      <div class="metric-value" style="color: %s;">%d</div>
      <div class="metric-tag">%s</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Scamalytics 风险分</div>
      <div class="metric-value">%d</div>
      <div class="metric-tag">%s</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">IP 网络类型</div>
      <div class="metric-value" style="font-size: 16px; padding-top: 4px;">%s</div>
      <div class="metric-tag">%s</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">全球黑名单标记</div>
      <div class="metric-value" style="font-size: 16px; padding-top: 4px;">%s</div>
      <div class="metric-tag">%s</div>
    </div>
  </div>

  <!-- Basic Info -->
  <div class="section-title">🌐 出口网络身份</div>
  <div class="grid-4">
    <div class="metric-card">
      <div class="metric-label">当前出口 IP</div>
      <div class="metric-value" style="font-size: 16px;">%s</div>
      <div class="metric-tag">%s</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">所属组织 / ISP</div>
      <div class="metric-value" style="font-size: 15px;">%s</div>
      <div class="metric-tag">%s</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">地理位置</div>
      <div class="metric-value" style="font-size: 16px;">%s</div>
      <div class="metric-tag">%s</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">代理标记判定</div>
      <div class="metric-value" style="font-size: 15px;">%s</div>
      <div class="metric-tag">%s</div>
    </div>
  </div>

  <!-- AI & Stream Unlock -->
  <div class="section-title">🔓 AI & 流媒体解锁看板</div>
  <div class="grid-unlock">
    <div class="unlock-item">
      <div class="unlock-name">ChatGPT</div>
      <span class="pill %s">%s</span>
    </div>
    <div class="unlock-item">
      <div class="unlock-name">Netflix</div>
      <span class="pill %s">%s</span>
    </div>
    <div class="unlock-item">
      <div class="unlock-name">Disney+</div>
      <span class="pill %s">%s</span>
    </div>
    <div class="unlock-item">
      <div class="unlock-name">TikTok</div>
      <span class="pill %s">%s</span>
    </div>
    <div class="unlock-item">
      <div class="unlock-name">YouTube</div>
      <span class="pill %s">%s</span>
    </div>
  </div>

  <!-- Raw Output Details -->
  <details>
    <summary>📜 点击展开：极客终端详细诊断原始日志</summary>
    <div class="terminal-box">%s</div>
  </details>

</div>

<div id="toast">✓ 已复制 AI 诊断报告，去粘贴给 AI 吧！</div>

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
    setTimeout(() => { t.classList.remove("show"); }, 2500);
  }
</script>
</body>
</html>`,
		themeColor, themeBg, themeBorder,
		nowStr,
		html.EscapeString(p.BadgeText), p.ScoreTotal,
		html.EscapeString(p.Headline),
		html.EscapeString(p.Summary),
		html.EscapeString(p.ClaudeAdvice),
		html.EscapeString(p.GPTAdvice),

		// 4 Metrics
		themeColor, p.IPQSScore, html.EscapeString(p.IPQSLevel),
		p.ScamalyticsScore, html.EscapeString(p.ScamalyticsLevel),
		html.EscapeString(p.IPType), html.EscapeString(p.UsageType),
		boolText(p.BlacklistClean, "0 标记", "有标记"), html.EscapeString(p.BlacklistText),

		// 4 Network identity
		html.EscapeString(p.IP), html.EscapeString(p.Country),
		html.EscapeString(p.Org), html.EscapeString(formatASN(p.ASN)),
		html.EscapeString(p.Country), html.EscapeString(p.City),
		boolText(p.IsProxy, "被标为代理", "未被标为代理"), boolText(p.IsAbuse, "有滥用记录", "无滥用记录"),

		// 5 Unlocks
		unlockPillClass(p.ChatGPTStatus), html.EscapeString(p.ChatGPTStatus),
		unlockPillClass(p.NetflixStatus), html.EscapeString(p.NetflixStatus),
		unlockPillClass(p.DisneyStatus), html.EscapeString(p.DisneyStatus),
		unlockPillClass(p.TikTokStatus), html.EscapeString(p.TikTokStatus),
		unlockPillClass(p.YouTubeStatus), html.EscapeString(p.YouTubeStatus),

		// Raw text
		html.EscapeString(p.Raw),
		aiPromptText,
	)
}

func boolText(b bool, t, f string) string {
	if b {
		return t
	}
	return f
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

func unlockPillClass(status string) string {
	if strings.Contains(status, "解锁") || strings.Contains(status, "正常") {
		return "pill-ok"
	} else if strings.Contains(status, "屏蔽") || strings.Contains(status, "失败") {
		return "pill-fail"
	}
	return "pill-warn"
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
