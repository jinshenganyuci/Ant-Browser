package backend

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortableSessionInterruptedRequiresExplicitChoice(t *testing.T) {
	oldAsk := askPortableSessionRecovery
	defer func() { askPortableSessionRecovery = oldAsk }()
	for _, tc := range []struct {
		name     string
		answers  []bool
		expected string
	}{
		{"取消保留快照", []bool{false, false}, "pending"},
		{"明确恢复", []bool{true}, "armed"},
		{"明确放弃", []bool{false, true}, "removed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := newProfilePackageImportTestApp(t, nil, nil)
			profile := &BrowserProfile{ProfileId: "interrupted", UserDataDir: "interrupted", ProfileName: "中断测试"}
			dir := app.browserMgr.ResolveUserDataDir(profile)
			session := &portableSession{Version: 1, ProfileDirectory: "Default", Cookies: []portableCookie{}, RequireConfirmation: true}
			if err := writePortableSessionPending(dir, session); err != nil {
				t.Fatal(err)
			}
			if err := restorePortableSession(1, dir, session); err == nil {
				t.Fatal("关闭状态不明时不能自动重放旧登录态")
			}
			index := 0
			askPortableSessionRecovery = func(_ *App, _ string) (bool, error) {
				if index >= len(tc.answers) {
					t.Fatal("出现多余的确认请求")
				}
				answer := tc.answers[index]
				index++
				return answer, nil
			}
			err := app.confirmPortableSessionRecovery(profile, false)
			got, readErr := readPortableSessionPending(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			switch tc.expected {
			case "pending":
				if err == nil || got == nil || !got.RequireConfirmation {
					t.Fatal("取消后必须保留不自动重放的快照")
				}
			case "armed":
				if err != nil || got == nil || got.RequireConfirmation {
					t.Fatal("明确授权后才能启用快照")
				}
			case "removed":
				if err != nil || got != nil {
					t.Fatal("明确放弃后应删除快照")
				}
			}
		})
	}
}

func TestPortableCookieParamsPreserveScope(t *testing.T) {
	expiry := float64(-1)
	c := portableCookie{Name: "__Host-test", Value: "fixture", Domain: "example.test", Path: "/", Secure: true, HTTPOnly: true, Session: true, Expires: &expiry, SameSite: "Lax", PartitionKey: &portableCookiePartitionKey{TopLevelSite: "https://top.test", HasCrossSiteAncestor: true}}
	params, err := c.params()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := params["domain"]; ok {
		t.Fatal("host-only Cookie 不应变为 domain Cookie")
	}
	if params["url"] != "https://example.test/" {
		t.Fatal("host-only Cookie URL 错误")
	}
	if _, ok := params["expires"]; ok {
		t.Fatal("会话 Cookie 不能传入 expires=-1 而被删除")
	}
	if params["partitionKey"] == nil || params["httpOnly"] != true || params["sameSite"] != "Lax" {
		t.Fatal("Cookie 安全/分区属性丢失")
	}
	c.Domain = ".example.test"
	params, err = c.params()
	if err != nil || params["domain"] != ".example.test" {
		t.Fatal("domain Cookie 作用域丢失")
	}
	c.PartitionKeyOpaque = true
	if _, err := c.params(); err == nil {
		t.Fatal("不透明 Cookie 分区不能静默丢失")
	}
}

func TestPortableSessionFailureKeepsPending(t *testing.T) {
	dir := t.TempDir()
	session := &portableSession{Version: 1, ProfileDirectory: "Default", Cookies: []portableCookie{{Name: "fixture", Value: "fixture", Domain: "example.test", Path: "/", Session: true}}}
	if err := writePortableSessionPending(dir, session); err != nil {
		t.Fatal(err)
	}
	port, err := nextAvailablePort()
	if err != nil {
		t.Fatal(err)
	}
	if err := restorePortableSession(port, dir, session); err == nil {
		t.Fatal("CDP 失败不能报告恢复成功")
	}
	if got, err := readPortableSessionPending(dir); err != nil || got == nil {
		t.Fatal("失败后必须保留待恢复登录态")
	}
}

func TestPortableSessionLaunchRejectsEarlyNavigation(t *testing.T) {
	session := &portableSession{Version: 1, ProfileDirectory: "Default", Cookies: []portableCookie{}}
	args := portableSessionLaunchArgs(t.TempDir(), 12345, "direct://", []string{"--fingerprint=123", "--fingerprinting-client-rects-noise", "--disable-non-proxied-udp", "--disable-spoofing=font,gpu", "--window-size=1200,800", "--lang=zh-CN", "--restore-last-session", "--app=https://example.test", "--load-extension=/tmp/no-extension", "https://example.test"}, session)
	joined := strings.Join(args, " ")
	for _, forbidden := range []string{"--restore-last-session", "--app=", "--load-extension=", "https://example.test"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal("恢复前存在提前导航入口")
		}
	}
	for _, required := range []string{"--no-startup-window", "--disable-extensions", "--fingerprint=123", "--fingerprinting-client-rects-noise", "--disable-non-proxied-udp", "--disable-spoofing=font,gpu", "--window-size=1200,800", "--lang=zh-CN"} {
		if !strings.Contains(joined, required) {
			t.Fatal("恢复专用启动缺少必要开关")
		}
	}
}

func TestPortableSessionArchiveKeepsCookieStoresButSkipsRuntimeFiles(t *testing.T) {
	dir := t.TempDir()
	names := []string{"Local State", "Default/Network/Cookies", "DevToolsActivePort", "SingletonLock", portableSessionPendingFile}
	for _, name := range names {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture-only"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "test.zip"))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	if _, err := writeProfilePackageDir(zw, dir, "user-data/source"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	found := map[string]bool{}
	for _, f := range zr.File {
		found[strings.TrimPrefix(f.Name, "user-data/source/")] = true
	}
	if !found["Local State"] || !found["Default/Network/Cookies"] {
		t.Fatal("不得通过删除 Cookie/密钥文件伪装修复")
	}
	if found["DevToolsActivePort"] || found["SingletonLock"] || found[portableSessionPendingFile] {
		t.Fatal("不得把源电脑运行锁、调试端口或待恢复文件当成持久用户数据搬运")
	}
}
