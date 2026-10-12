package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const maxRoutesPerUser = 64 // §14.2 约束：单用户 route 数上限

type ccdLayer struct {
	Global []ccdRule            `json:"global"`
	Groups []map[string]interface{} `json:"groups"`
	User   []ccdRule            `json:"user"`
}

// collectUserRules：§14.2 步骤① —— 三条查询取全量规则
func (a *App) collectUserRules(userID int64) (global, userRules []ccdRule, groupRules map[int64][]ccdRule, groupNames map[int64]string) {
	global = []ccdRule{}
	userRules = []ccdRule{}
	groupRules = map[int64][]ccdRule{}
	groupNames = map[int64]string{}

	rows, err := a.db.Query(`SELECT id,name,type,value,priority,group_id,user_id,enabled FROM ccd_rules
		WHERE enabled=1 AND group_id IS NULL AND user_id IS NULL ORDER BY priority DESC, id`)
	if err == nil {
		for rows.Next() {
			var c ccdRule
			var en int
			if rows.Scan(&c.ID, &c.Name, &c.Type, &c.Value, &c.Priority, &c.GroupID, &c.UserID, &en) == nil {
				c.Enabled = en == 1
				global = append(global, c)
			}
		}
		rows.Close()
	}
	rows, err = a.db.Query(`SELECT id,name,type,value,priority,group_id,user_id,enabled FROM ccd_rules
		WHERE enabled=1 AND user_id=? ORDER BY priority DESC, id`, userID)
	if err == nil {
		for rows.Next() {
			var c ccdRule
			var en int
			if rows.Scan(&c.ID, &c.Name, &c.Type, &c.Value, &c.Priority, &c.GroupID, &c.UserID, &en) == nil {
				c.Enabled = en == 1
				userRules = append(userRules, c)
			}
		}
		rows.Close()
	}
	// 用户所在组（无论该组有无规则——纯资源绑定组也必须出现在 layers 里）
	grows, gErr := a.db.Query(`SELECT g.id, g.name FROM group_members gm
		JOIN user_groups g ON g.id=gm.group_id WHERE gm.user_id=? ORDER BY g.id`, userID)
	if gErr == nil {
		for grows.Next() {
			var gid int64
			var gname string
			if grows.Scan(&gid, &gname) == nil {
				groupNames[gid] = gname
				groupRules[gid] = []ccdRule{}
			}
		}
		grows.Close()
	}
	if len(groupNames) > 0 {
		ids := make([]string, 0, len(groupNames))
		args := make([]interface{}, 0, len(groupNames))
		for gid := range groupNames {
			ids = append(ids, "?")
			args = append(args, gid)
		}
		inSQL := strings.Join(ids, ",")
		rows, rErr := a.db.Query(`SELECT id,name,type,value,priority,group_id,user_id,enabled FROM ccd_rules
			WHERE enabled=1 AND group_id IN (`+inSQL+`) ORDER BY group_id, priority DESC, id`, args...)
		if rErr == nil {
			for rows.Next() {
				var c ccdRule
				var en int64
				if rows.Scan(&c.ID, &c.Name, &c.Type, &c.Value, &c.Priority, &c.GroupID, &c.UserID, &en) == nil {
					c.Enabled = en == 1
					c.Scope = "group"
					if c.GroupID != nil {
						groupRules[*c.GroupID] = append(groupRules[*c.GroupID], c)
					}
				}
			}
			rows.Close()
		}
	}
	// 组绑定资源 → 合成为该组的 route 规则（§3.2 资源管理语义落地）
	for gid := range groupNames {
		resRows, rErr := a.db.Query(`SELECT res.name, res.cidr FROM group_resources gr
			JOIN resources res ON res.id=gr.resource_id WHERE gr.group_id=? ORDER BY res.id`, gid)
		if rErr != nil {
			continue
		}
		for resRows.Next() {
			var rname, cidr string
			if resRows.Scan(&rname, &cidr) == nil {
				groupRules[gid] = append(groupRules[gid], ccdRule{
					Name: "资源:" + rname, Type: "route", Value: cidr, Scope: "group", Enabled: true,
				})
			}
		}
		resRows.Close()
	}
	return global, userRules, groupRules, groupNames
}

type ccdEffective struct {
	Routes          []string `json:"routes"`
	Iroutes         []string `json:"iroutes,omitempty"`
	DNS             []string `json:"dns"`
	RedirectGateway bool     `json:"redirect_gateway"`
	RouteMetric     *int     `json:"route_metric,omitempty"`
	Truncated       bool     `json:"truncated"`
}

// mergeEffective：§14.2 步骤②③ —— 合并语义 + 约束校验。
// route/iroute：三层取并集去重；dns/redirect_gateway/route_metric：**按类型独立**高层级覆盖（L3 > L2 > L1），
// 用户层定义了 metric 不应吞掉组层的 dns（曾因三类联合判断导致跨类型误覆盖）。
func mergeEffective(global, userRules []ccdRule, groupRules map[int64][]ccdRule, groupIDs []int64) ccdEffective {
	ef := ccdEffective{Routes: []string{}, Iroutes: []string{}, DNS: []string{}}
	seen := map[string]bool{}

	collect := func(rules []ccdRule) {
		for _, c := range rules {
			p := parseCIDROrNil(c.Type, c.Value)
			if p == nil {
				continue
			}
			key := c.Type + "|" + p.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			if c.Type == "route" {
				ef.Routes = append(ef.Routes, p.String())
			} else if c.Type == "iroute" {
				ef.Iroutes = append(ef.Iroutes, p.String())
			}
		}
	}
	// 收集顺序 = 保留优先级：用户层先入（去重先占位），组层次之，全局最后——
	// 超限截断保头时丢的是全局层，与 L3>L2>L1 语义一致（此前全局先入导致用户层最先被截，2026-09-29 修复）
	collect(userRules)
	for _, gid := range groupIDs {
		collect(groupRules[gid])
	}
	collect(global)
	if len(ef.Routes) > maxRoutesPerUser {
		ef.Routes = ef.Routes[:maxRoutesPerUser]
		ef.Truncated = true
	}
	if len(ef.Iroutes) > maxRoutesPerUser {
		ef.Iroutes = ef.Iroutes[:maxRoutesPerUser]
		ef.Truncated = true
	}

	// dns：用户层定义了 dns 列表 → 覆盖；否则组层并集；否则全局
	userDNS, groupDNS, globalDNS := []string{}, []string{}, []string{}
	// redirect_gateway / route_metric：单值，按层取"该层有定义即生效"（组层多组按组序后者覆盖）
	userRG, groupRG, globalRG := (*ccdRule)(nil), (*ccdRule)(nil), (*ccdRule)(nil)
	userMetric, groupMetric, globalMetric := (*ccdRule)(nil), (*ccdRule)(nil), (*ccdRule)(nil)
	classify := func(rules []ccdRule, dnsp *[]string, rgp, metricp **ccdRule) {
		for _, c := range rules {
			switch c.Type {
			case "dns":
				*dnsp = append(*dnsp, c.Value)
			case "redirect_gateway":
				*rgp = &c
			case "route_metric":
				*metricp = &c
			}
		}
	}
	classify(userRules, &userDNS, &userRG, &userMetric)
	for _, gid := range groupIDs {
		classify(groupRules[gid], &groupDNS, &groupRG, &groupMetric)
	}
	classify(global, &globalDNS, &globalRG, &globalMetric)

	if len(userDNS) > 0 {
		ef.DNS = userDNS
	} else if len(groupDNS) > 0 {
		ef.DNS = groupDNS
	} else {
		ef.DNS = globalDNS
	}

	pickRG := func(r *ccdRule) *bool {
		if r == nil {
			return nil
		}
		v := strings.TrimSpace(r.Value) != "false"
		return &v
	}
	if b := pickRG(userRG); b != nil {
		ef.RedirectGateway = *b
	} else if b := pickRG(groupRG); b != nil {
		ef.RedirectGateway = *b
	} else if b := pickRG(globalRG); b != nil {
		ef.RedirectGateway = *b
	}

	pickMetric := func(r *ccdRule) *int {
		if r == nil {
			return nil
		}
		if n, err := strconv.Atoi(strings.TrimSpace(r.Value)); err == nil {
			return &n
		}
		return nil
	}
	if v := pickMetric(userMetric); v != nil {
		ef.RouteMetric = v
	} else if v := pickMetric(groupMetric); v != nil {
		ef.RouteMetric = v
	} else if v := pickMetric(globalMetric); v != nil {
		ef.RouteMetric = v
	}
	return ef
}

// renderCCD：§14.2 步骤④ —— 渲染 CCD 文件内容。
// route/dns/redirect-gateway/metric 走 push（下发给客户端）；
// iroute 是服务端路由指令（声明该客户端身后子网），CCD 中不带 push 前缀。
// v4 渲染为 route <net> <mask> / iroute <net> <mask>；v6 渲染为
// route-ipv6 <prefix> / iroute-ipv6 <prefix>（2026-10-02 IPv6 支持，此前 v6 被 Is4 过滤静默丢弃）。
func renderCCD(ef ccdEffective) string {
	var b strings.Builder
	for _, cidr := range ef.Routes {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			if p.Addr().Is4() {
				mask := net.CIDRMask(p.Bits(), 32)
				fmt.Fprintf(&b, "push \"route %s %d.%d.%d.%d\"\n", p.Addr(), mask[0], mask[1], mask[2], mask[3])
			} else {
				fmt.Fprintf(&b, "push \"route-ipv6 %s\"\n", p.String())
			}
		}
	}
	for _, cidr := range ef.Iroutes {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			if p.Addr().Is4() {
				mask := net.CIDRMask(p.Bits(), 32)
				fmt.Fprintf(&b, "iroute %s %d.%d.%d.%d\n", p.Addr(), mask[0], mask[1], mask[2], mask[3])
			} else {
				fmt.Fprintf(&b, "iroute-ipv6 %s\n", p.String())
			}
		}
	}
	for _, dns := range ef.DNS {
		fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", dns)
	}
	if ef.RedirectGateway {
		b.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")
	}
	if ef.RouteMetric != nil {
		fmt.Fprintf(&b, "push \"route-metric %d\"\n", *ef.RouteMetric)
	}
	return b.String()
}

func (a *App) buildPreview(userID int64) (map[string]interface{}, bool) {
	var exists int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, userID).Scan(&exists); err != nil || exists == 0 {
		return nil, false
	}
	global, userRules, groupRules, groupNames := a.collectUserRules(userID)

	gids := make([]int64, 0, len(groupNames))
	for gid := range groupNames {
		gids = append(gids, gid)
	}
	sort.Slice(gids, func(i, j int) bool { return gids[i] < gids[j] })

	ef := mergeEffective(global, userRules, groupRules, gids)
	layers := ccdLayer{Global: global, User: userRules, Groups: []map[string]interface{}{}}
	for _, gid := range gids {
		layers.Groups = append(layers.Groups, map[string]interface{}{
			"group": groupNames[gid], "rules": groupRules[gid],
		})
	}
	warnings := []string{}
	if len(ef.Routes) >= maxRoutesPerUser {
		warnings = append(warnings, fmt.Sprintf("route 数量 %d/%d（已达上限）", len(ef.Routes), maxRoutesPerUser))
	}
	if ef.Truncated {
		warnings = append(warnings, "route 数超限已截断，审计将记录 ccd_truncated")
	}
	write := map[string]interface{}{
		"layers":      layers,
		"effective":   ef,
		"ccd_content": renderCCD(ef),
		"warnings":    warnings,
	}
	return write, true
}

func (a *App) handleCcdPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID int64 `json:"user_id"`
	}
	if err := jsonDecode(r, &req); err != nil || req.UserID == 0 {
		failParam(w, r, "user_id 必填")
		return
	}
	preview, ok := a.buildPreview(req.UserID)
	if !ok {
		notFound(w, r, "用户")
		return
	}
	writeOK(w, r, preview)
}

func (a *App) handleCcdEffective(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	preview, ok := a.buildPreview(userID)
	if !ok {
		notFound(w, r, "用户")
		return
	}
	writeOK(w, r, preview["effective"])
}
