package main

// LDAP 类认证源（AD / OpenLDAP）：search-then-bind（服务账号查 DN → 用户密码 bind 验证）。
// 错误语义与 Python 版对齐：凭据错误 →「账号或密码错误」；服务故障 →「认证服务不可用」。

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var ldapDialTimeout = 8 * time.Second

func ldapDial(server string) (*ldap.Conn, error) {
	return ldap.DialURL(server, ldap.DialWithDialer(&net.Dialer{Timeout: ldapDialTimeout}))
}

func ldapAuthenticate(provider, username, password string) (map[string]any, error) {
	c := idpc()[provider]
	server := mStr(c, "server")
	bindDN := mStr(c, "bind_dn")
	bindPW := mStr(c, "bind_password")
	baseDN := mStr(c, "base_dn")
	filterTpl := mStr(c, "user_filter")

	conn, err := ldapDial(server)
	if err != nil {
		return nil, fmt.Errorf("认证服务不可用")
	}
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPW); err != nil {
		return nil, fmt.Errorf("认证服务不可用")
	}
	// 过滤器注入防御：剔除括号（与 Python 同策略）
	safe := strings.ReplaceAll(username, ")", "")
	safe = strings.ReplaceAll(safe, "(", "")
	filter := strings.ReplaceAll(filterTpl, "{username}", safe)
	search := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, filter, []string{"*"}, nil)
	res, err := conn.Search(search)
	if err != nil {
		return nil, fmt.Errorf("认证服务不可用")
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("用户不存在")
	}
	e := res.Entries[0]
	userDN := e.DN
	display := e.GetAttributeValue("displayName")
	if display == "" {
		display = e.GetAttributeValue("cn")
	}
	if display == "" {
		display = username
	}
	mail := e.GetAttributeValue("mail")

	// 用户密码 bind 验证（新连接，同 Python 行为）
	uconn, err := ldapDial(server)
	if err != nil {
		return nil, fmt.Errorf("认证服务不可用")
	}
	defer uconn.Close()
	if err := uconn.Bind(userDN, password); err != nil {
		if le, ok := err.(*ldap.Error); ok && le.ResultCode == ldap.LDAPResultInvalidCredentials {
			return nil, fmt.Errorf("账号或密码错误")
		}
		return nil, fmt.Errorf("认证服务不可用")
	}
	return map[string]any{"sub": fmt.Sprintf("%s:%s", provider, userDN), "name": display, "email": mail}, nil
}
