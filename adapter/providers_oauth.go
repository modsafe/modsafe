package main

// 三个 OAuth 私有协议 IdP（钉钉/飞书/企业微信）：authorize URL 构造 + code 换用户信息
// + 通讯录拉取（§23 防腐层统一格式）。URL/参数/错误文案与 Python 版逐条对应。

import (
	"fmt"
	"net/url"
	"sort"
	"time"
)

// ---------- 钉钉 ----------

func dingtalkAuthorizeURL(internalState string) (string, error) {
	c := idpc()["dingtalk"]
	if mStr(c, "client_id") == "" || mStr(c, "client_secret") == "" {
		return "", fmt.Errorf("钉钉未配置完整（缺 client_id / client_secret）")
	}
	qs := urlValues(map[string]string{
		"redirect_uri":  ADAPTER_BASE + "/callback/dingtalk",
		"response_type": "code",
		"client_id":     mStr(c, "client_id"),
		"scope":         "openid",
		"state":         internalState,
		"prompt":        "consent",
	})
	return "https://login.dingtalk.com/oauth2/auth?" + qs, nil
}

func dingtalkCallback(dingCode string) (map[string]any, error) {
	c := idpc()["dingtalk"]
	resp, err := httpJSON("https://api.dingtalk.com/v1.0/oauth2/userAccessToken", "POST",
		map[string]string{"Content-Type": "application/json"},
		map[string]any{"clientId": mStr(c, "client_id"), "clientSecret": mStr(c, "client_secret"),
			"code": dingCode, "grantType": "authorization_code"}, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("钉钉 token: %v", err)
	}
	at := mStr(resp, "accessToken")
	if at == "" {
		return nil, fmt.Errorf("钉钉 token 响应缺少 accessToken: %v", resp)
	}
	info, err := httpJSON("https://api.dingtalk.com/v1.0/contact/users/me", "GET",
		map[string]string{"x-acs-dingtalk-access-token": at}, nil, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("钉钉 userinfo: %v", err)
	}
	u := map[string]any{
		"sub":   firstNonEmpty(mStr(info, "unionId"), mStr(info, "openId"), "unknown"),
		"name":  firstNonEmpty(mStr(info, "nick"), "unknown"),
		"email": mStr(info, "email"),
	}
	if rt := mStr(resp, "refreshToken"); rt != "" {
		u["_rt"] = rt
	}
	return u, nil
}

// ---------- 飞书 ----------

func feishuAuthorizeURL(internalState string) (string, error) {
	c := idpc()["feishu"]
	if mStr(c, "app_id") == "" || mStr(c, "app_secret") == "" {
		return "", fmt.Errorf("飞书未配置完整（缺 app_id / app_secret）")
	}
	qs := urlValues(map[string]string{
		"app_id":       mStr(c, "app_id"),
		"redirect_uri": ADAPTER_BASE + "/callback/feishu",
		"state":        internalState,
	})
	return "https://open.feishu.cn/open-apis/authen/v1/authorize?" + qs, nil
}

func feishuCallback(code string) (map[string]any, error) {
	c := idpc()["feishu"]
	resp, err := httpJSON("https://open.feishu.cn/open-apis/authen/v2/oauth/token", "POST",
		map[string]string{"Content-Type": "application/json"},
		map[string]any{"grant_type": "authorization_code",
			"client_id": mStr(c, "app_id"), "client_secret": mStr(c, "app_secret"),
			"code": code, "redirect_uri": ADAPTER_BASE + "/callback/feishu"}, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("飞书 token: %v", err)
	}
	at := mStr(resp, "access_token")
	if at == "" {
		if d, ok := resp["data"].(map[string]any); ok {
			at = mStr(d, "access_token")
		}
	}
	if at == "" {
		return nil, fmt.Errorf("飞书 token 响应缺少 access_token: %v", resp)
	}
	info, err := httpJSON("https://open.feishu.cn/open-apis/authen/v1/user_info", "GET",
		map[string]string{"Authorization": "Bearer " + at}, nil, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("飞书 userinfo: %v", err)
	}
	logf("feishu userinfo raw: %s", truncateJSON(info, 400))
	if codeVal := mInt(info, "code"); codeVal != 0 && info["code"] != nil {
		return nil, fmt.Errorf("飞书 userinfo 业务错误 code=%d: %s", codeVal, mStr(info, "msg"))
	}
	data, _ := info["data"].(map[string]any)
	u := data
	if data == nil {
		u = info
	} else if inner, ok := data["user"].(map[string]any); ok {
		u = inner
	}
	// #60：sub 恒用 union_id（跨应用稳定键，与目录 union_id 同域）；缺失明确报错不静默换键
	sub := firstNonEmpty(mStr(u, "union_id"), mStr(u, "unionId"))
	if sub == "" {
		return nil, fmt.Errorf("飞书 userinfo 缺少 union_id（检查应用「获取用户 user ID」等权限配置）")
	}
	name := firstNonEmpty(mStr(u, "name"), mStr(u, "nickname"), sub)
	u2 := map[string]any{"sub": sub, "name": name, "email": mStr(u, "email")}
	if rt := mStr(resp, "refresh_token"); rt != "" {
		u2["_rt"] = rt
	}
	return u2, nil
}

// ---------- 企业微信 ----------

func wecomAuthorizeURL(internalState string) (string, error) {
	c := idpc()["wecom"]
	if mStr(c, "corp_id") == "" || mStr(c, "agent_id") == "" || mStr(c, "secret") == "" {
		return "", fmt.Errorf("企业微信未配置完整（缺 corp_id / agent_id / secret）")
	}
	// 企微要求备案域名回调（不接受 IP），redirect_base 由配置指定；默认退回 ADAPTER_BASE
	base := mStr(c, "redirect_base")
	if base == "" {
		base = ADAPTER_BASE
	}
	qs := urlValues(map[string]string{
		"login_type":   "CorpApp",
		"appid":        mStr(c, "corp_id"),
		"agentid":      mStr(c, "agent_id"),
		"redirect_uri": base + "/callback/wecom",
		"state":        internalState,
	})
	return "https://login.work.weixin.qq.com/wwlogin/sso/login?" + qs, nil
}

func wecomCallback(code string) (map[string]any, error) {
	c := idpc()["wecom"]
	tok, err := httpJSON("https://qyapi.weixin.qq.com/cgi-bin/gettoken?"+urlValues(map[string]string{
		"corpid": mStr(c, "corp_id"), "corpsecret": mStr(c, "secret")}), "GET", nil, nil, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("企微 gettoken: %v", err)
	}
	at := mStr(tok, "access_token")
	if at == "" {
		return nil, fmt.Errorf("企微 gettoken 失败: %v", tok)
	}
	info, err := httpJSON("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?"+urlValues(map[string]string{
		"access_token": at, "code": code}), "GET", nil, nil, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("企微 getuserinfo: %v", err)
	}
	userid := firstNonEmpty(mStr(info, "userid"), mStr(info, "UserId"))
	if userid == "" {
		return nil, fmt.Errorf("企微 getuserinfo 无 userid: %v", info)
	}
	name, email := "", ""
	detail, err2 := httpJSON("https://qyapi.weixin.qq.com/cgi-bin/user/get?"+urlValues(map[string]string{
		"access_token": at, "userid": userid}), "GET", nil, nil, 15*time.Second)
	if err2 == nil && detail != nil {
		name = mStr(detail, "name")
		email = firstNonEmpty(mStr(detail, "biz_mail"), mStr(detail, "email"))
	}
	// #60：sub 直接用 userid（与目录同步 external_id 同域）
	return map[string]any{"sub": userid, "name": firstNonEmpty(name, userid), "email": email}, nil
}

type oauthHandler struct {
	authorize func(internalState string) (string, error)
	callback  func(code string) (map[string]any, error)
}

var OAUTH_HANDLERS = map[string]oauthHandler{
	"dingtalk": {dingtalkAuthorizeURL, dingtalkCallback},
	"feishu":   {feishuAuthorizeURL, feishuCallback},
	"wecom":    {wecomAuthorizeURL, wecomCallback},
}

// ---------- §23 目录同步：通讯录拉取 ----------

func dingtalkAppToken() (string, error) {
	c := idpc()["dingtalk"]
	resp, err := httpJSON("https://oapi.dingtalk.com/gettoken?appkey="+mStr(c, "client_id")+
		"&appsecret="+mStr(c, "client_secret"), "GET", nil, nil, 15*time.Second)
	if err != nil {
		return "", fmt.Errorf("钉钉 gettoken: %v", err)
	}
	at := mStr(resp, "access_token")
	if at == "" {
		if result, ok := resp["result"].(map[string]any); ok {
			at = mStr(result, "access_token")
		}
	}
	if at == "" {
		return "", fmt.Errorf("钉钉 token 响应无 access_token（检查 AppKey/Secret 与权限）")
	}
	return at, nil
}

// dingCheck：钉钉 200+errcode!=0 的业务错误（60011=缺权限）
func dingCheck(resp map[string]any, what string) error {
	if resp == nil {
		return nil
	}
	if _, has := resp["errcode"]; has {
		if ec := mInt(resp, "errcode"); ec != 0 {
			return fmt.Errorf("钉钉%s: [%d] %s", what, ec, firstNonEmpty(mStr(resp, "sub_msg"), mStr(resp, "errmsg")))
		}
	}
	return nil
}

func fetchDingtalkDirectory() (map[string]any, error) {
	at, err := dingtalkAppToken()
	if err != nil {
		return nil, err
	}
	var departments []any
	seen := map[string]bool{}

	var listsub func(deptID string) error
	listsub = func(deptID string) error {
		resp, err := httpJSON(fmt.Sprintf("https://oapi.dingtalk.com/topapi/v2/department/listsub?access_token=%s&dept_id=%s", at, deptID), "GET", nil, nil, 15*time.Second)
		if err != nil {
			return fmt.Errorf("钉钉部门列表: %v", err)
		}
		if err := dingCheck(resp, "部门列表"); err != nil {
			return err
		}
		result, _ := resp["result"].([]any)
		for _, it := range result {
			d, _ := it.(map[string]any)
			id := fmt.Sprintf("%v", d["dept_id"])
			if seen[id] {
				continue
			}
			seen[id] = true
			departments = append(departments, map[string]any{"id": id, "name": mStr(d, "name"), "parent": deptID})
			if err := listsub(id); err != nil {
				return err
			}
		}
		return nil
	}
	if err := listsub("1"); err != nil {
		return nil, err
	}
	var users []map[string]any
	// 扫描集 = 全部子部门 + 根部门（id=1 直属用户此前漏采，2026-09-29 修复）
	type deptScan struct{ id, name string }
	scans := []deptScan{{"1", "根部门"}}
	for _, d := range departments {
		dm, _ := d.(map[string]any)
		scans = append(scans, deptScan{mStr(dm, "id"), mStr(dm, "name")})
	}
	for _, d := range scans {
		offset := 0
		for {
			resp, err := httpJSON(fmt.Sprintf("https://oapi.dingtalk.com/topapi/v2/user/list?access_token=%s&dept_id=%s&cursor=%d&size=100", at, d.id, offset), "GET", nil, nil, 15*time.Second)
			if err != nil {
				return nil, fmt.Errorf("钉钉用户列表(dept=%s): %v", d.name, err)
			}
			if err := dingCheck(resp, fmt.Sprintf("用户列表(dept=%s)", d.name)); err != nil {
				return nil, err
			}
			page, _ := resp["result"].(map[string]any)
			list, _ := page["list"].([]any)
			for _, it := range list {
				u, _ := it.(map[string]any)
				// unionid：扫码 OAuth 的 sub 即 unionid——目录阶段捕获，扫码/同步才能绑定同一身份
				users = append(users, map[string]any{
					"external_id": mStr(u, "userid"), "union_id": mStr(u, "unionid"),
					"name": mStr(u, "name"), "email": mStr(u, "email"),
					"dept_ids": []any{d.id},
				})
			}
			offset = mInt(page, "next_cursor")
			if offset == 0 {
				break
			}
		}
	}
	return map[string]any{"departments": departments, "users": mergeDirUsers(users)}, nil
}

// wecomCheck：企微 200+errcode!=0（60011=缺权限/60020=IP 不在白名单）
func wecomCheck(resp map[string]any, what string) error {
	if resp == nil {
		return nil
	}
	if _, has := resp["errcode"]; has {
		if ec := mInt(resp, "errcode"); ec != 0 {
			return fmt.Errorf("企微%s: [%d] %s", what, ec, mStr(resp, "errmsg"))
		}
	}
	return nil
}

func fetchWecomDirectory() (map[string]any, error) {
	c := idpc()["wecom"]
	secret := mStr(c, "contacts_secret")
	if secret == "" {
		return nil, fmt.Errorf("企微通讯录同步未配置：请在凭证配置的 wecom 段增加 contacts_secret（企业微信后台-管理工具-通讯录同步的 Secret，不是应用 Secret）")
	}
	resp, err := httpJSON(fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", mStr(c, "corp_id"), secret), "GET", nil, nil, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("企微 gettoken: %v", err)
	}
	if err := wecomCheck(resp, "gettoken"); err != nil {
		return nil, err
	}
	at := mStr(resp, "access_token")
	if at == "" {
		return nil, fmt.Errorf("企微 token: %v", resp)
	}
	resp, err = httpJSON("https://qyapi.weixin.qq.com/cgi-bin/department/list?access_token="+at, "GET", nil, nil, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("企微部门列表: %v", err)
	}
	if err := wecomCheck(resp, "部门列表"); err != nil {
		return nil, err
	}
	var departments []any
	deptList, _ := resp["department"].([]any)
	for _, it := range deptList {
		d, _ := it.(map[string]any)
		departments = append(departments, map[string]any{
			"id": fmt.Sprintf("%v", d["id"]), "name": mStr(d, "name"),
			"parent": fmt.Sprintf("%v", d["parentid"]),
		})
	}
	// 根部门(id=1)不建组但必须扫人（直属员工此前被漏采）
	var scanIDs []string
	scanIDs = append(scanIDs, "1")
	for _, d := range departments {
		dm, _ := d.(map[string]any)
		if mStr(dm, "id") != "1" {
			scanIDs = append(scanIDs, mStr(dm, "id"))
		}
	}
	var users []map[string]any
	for _, did := range scanIDs {
		resp, err := httpJSON(fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/user/list?access_token=%s&department_id=%s&fetch_child=0", at, did), "GET", nil, nil, 15*time.Second)
		if err != nil {
			return nil, fmt.Errorf("企微用户列表(dept=%s): %v", did, err)
		}
		if err := wecomCheck(resp, fmt.Sprintf("用户列表(dept=%s)", did)); err != nil {
			return nil, err
		}
		ulist, _ := resp["userlist"].([]any)
		for _, it := range ulist {
			u, _ := it.(map[string]any)
			if mStr(u, "name") == "" {
				continue
			}
			users = append(users, map[string]any{
				"external_id": mStr(u, "userid"), "name": mStr(u, "name"),
				"email": mStr(u, "email"), "dept_ids": []any{did},
			})
		}
	}
	var outDepts []any
	for _, d := range departments {
		dm, _ := d.(map[string]any)
		if mStr(dm, "id") != "1" {
			outDepts = append(outDepts, d)
		}
	}
	return map[string]any{"departments": outDepts, "users": mergeDirUsers(users)}, nil
}

// feishuCheck：飞书 200+code!=0（IP 拒绝 99991401 / 权限不足 99991672 等）
func feishuCheck(resp map[string]any, what string) error {
	if resp == nil {
		return nil
	}
	if _, has := resp["code"]; has {
		if c := mInt(resp, "code"); c != 0 {
			return fmt.Errorf("飞书%s: [%d] %s", what, c, mStr(resp, "msg"))
		}
	}
	return nil
}

func fetchFeishuDirectory() (map[string]any, error) {
	c := idpc()["feishu"]
	resp, err := httpJSON("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal", "POST",
		map[string]string{"Content-Type": "application/json"},
		map[string]any{"app_id": mStr(c, "app_id"), "app_secret": mStr(c, "app_secret")}, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("飞书 tenant_token: %v", err)
	}
	at := mStr(resp, "tenant_access_token")
	if at == "" {
		return nil, fmt.Errorf("飞书 token: %v", resp)
	}
	H := map[string]string{"Authorization": "Bearer " + at}
	var departments []any
	seen := map[string]bool{}

	var children func(deptID string) error
	children = func(deptID string) error {
		// department_id 是路径参数（此前 query 形式被飞书解析为字面量 id → 99992357，2026-09-30 修复）
		resp, err := httpJSON(fmt.Sprintf("https://open.feishu.cn/open-apis/contact/v3/departments/%s/children?page_size=50", deptID), "GET", H, nil, 15*time.Second)
		if err != nil {
			return fmt.Errorf("飞书部门列表: %v", err)
		}
		if err := feishuCheck(resp, "部门列表"); err != nil {
			return err
		}
		data, _ := resp["data"].(map[string]any)
		items, _ := data["items"].([]any)
		for _, it := range items {
			d, _ := it.(map[string]any)
			did := mStr(d, "department_id")
			if did == "" || seen[did] {
				continue
			}
			seen[did] = true
			departments = append(departments, map[string]any{"id": did, "name": mStr(d, "name"), "parent": deptID})
			if err := children(did); err != nil {
				return err
			}
		}
		return nil
	}
	if err := children("0"); err != nil {
		return nil, err
	}
	// 根部门直属用户也纳入扫描（不建组，仅采人）
	type deptScan struct{ id, name string }
	scans := []deptScan{{"0", "根部门"}}
	for _, d := range departments {
		dm, _ := d.(map[string]any)
		scans = append(scans, deptScan{mStr(dm, "id"), mStr(dm, "name")})
	}
	var users []map[string]any
	for _, d := range scans {
		pageToken := ""
		for {
			u := fmt.Sprintf("https://open.feishu.cn/open-apis/contact/v3/users/find_by_department?department_id=%s&page_size=50", d.id)
			if pageToken != "" {
				u += "&page_token=" + pageToken
			}
			resp, err := httpJSON(u, "GET", H, nil, 15*time.Second)
			if err != nil {
				return nil, fmt.Errorf("飞书用户列表(dept=%s): %v", d.name, err)
			}
			if err := feishuCheck(resp, fmt.Sprintf("用户列表(dept=%s)", d.name)); err != nil {
				return nil, err
			}
			data, _ := resp["data"].(map[string]any)
			items, _ := data["items"].([]any)
			for _, it := range items {
				usr, _ := it.(map[string]any)
				// #60：扫码 sub=union_id，目录捕获它两侧才能绑定同一身份
				users = append(users, map[string]any{
					"external_id": mStr(usr, "open_id"), "union_id": mStr(usr, "union_id"),
					"name":     mStr(usr, "name"),
					"email":    firstNonEmpty(mStr(usr, "enterprise_email"), mStr(usr, "email")),
					"dept_ids": []any{d.id},
				})
			}
			pageToken = mStr(data, "page_token")
			hasMore := false
			if data != nil {
				if b, ok := data["has_more"].(bool); ok {
					hasMore = b
				}
			}
			if !hasMore || pageToken == "" {
				break
			}
		}
	}
	return map[string]any{"departments": departments, "users": mergeDirUsers(users)}, nil
}

var DIRECTORY_FETCHERS = map[string]func() (map[string]any, error){
	"dingtalk": fetchDingtalkDirectory,
	"wecom":    fetchWecomDirectory,
	"feishu":   fetchFeishuDirectory,
}

// mergeDirUsers：同一人多部门去重合并 dept_ids（external_id 键；钉/飞书跳过无名者）
func mergeDirUsers(users []map[string]any) []any {
	merged := map[string]map[string]any{}
	var order []string
	for _, u := range users {
		eid := mStr(u, "external_id")
		if eid == "" || mStr(u, "name") == "" {
			continue
		}
		if exist, ok := merged[eid]; ok {
			old, _ := exist["dept_ids"].([]any)
			add, _ := u["dept_ids"].([]any)
			exist["dept_ids"] = mergeSortedUnique(old, add)
		} else {
			merged[eid] = u
			order = append(order, eid)
		}
	}
	out := make([]any, 0, len(order))
	for _, k := range order {
		out = append(out, merged[k])
	}
	return out
}

func mergeSortedUnique(a, b []any) []any {
	set := map[string]bool{}
	for _, v := range append(append([]any{}, a...), b...) {
		set[fmt.Sprintf("%v", v)] = true
	}
	out := make([]any, 0, len(set))
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k)
	}
	return out
}

// ---------- 小工具 ----------

func urlValues(m map[string]string) string {
	v := url.Values{}
	for k, val := range m {
		v.Set(k, val)
	}
	return v.Encode()
}

func truncateJSON(v any, n int) string {
	j, _ := jsonMarshal(v)
	s := string(j)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
