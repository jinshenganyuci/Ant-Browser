package backend

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
)

// 全程使用临时目录与虚构 Cookie；不访问真实网站或个人浏览器资料。
func TestPortableSessionRealBrowserRoundTrip(t *testing.T) {
	chrome := os.Getenv("ANT_TEST_CHROME")
	if chrome == "" {
		t.Skip("真实浏览器用例仅由配置 ANT_TEST_CHROME 的云端 Runner 执行")
	}
	source, _ := newProfilePackageImportTestApp(t, nil, nil)
	source.db = newProfilePackageDatabase(t, source.appRoot)
	profile := browser.Profile{ProfileId: "source", ProfileName: "登录态云端回归", UserDataDir: "source"}
	sourceDir := source.browserMgr.ResolveUserDataDir(&profile)
	sourcePort, closeSource := startPortableTestChrome(t, chrome, sourceDir, nil)
	expires := float64(time.Now().Add(24 * time.Hour).Unix())
	fixtures := []map[string]any{
		{"name": "__Host-fixture", "value": "synthetic-host-only", "url": "https://accounts.example.test/", "path": "/", "secure": true, "httpOnly": true, "sameSite": "Lax", "expires": expires},
		{"name": "fixture_session", "value": "synthetic-session", "domain": ".example.test", "path": "/", "secure": true, "httpOnly": true, "sameSite": "Strict"},
		{"name": "fixture_domain", "value": "synthetic-domain", "domain": ".example.test", "path": "/settings", "secure": true, "httpOnly": false, "sameSite": "None", "expires": expires},
		{"name": "fixture_partitioned", "value": "synthetic-partition-a", "url": "https://embedded.example.test/", "path": "/", "secure": true, "httpOnly": true, "sameSite": "None", "expires": expires, "partitionKey": map[string]any{"topLevelSite": "https://example.test", "hasCrossSiteAncestor": true}},
		{"name": "fixture_partitioned", "value": "synthetic-partition-b", "url": "https://embedded.example.test/", "path": "/", "secure": true, "httpOnly": true, "sameSite": "None", "expires": expires, "partitionKey": map[string]any{"topLevelSite": "https://other.test", "hasCrossSiteAncestor": true}},
	}
	if _, err := cdpBrowserCallResult(sourcePort, "Storage.setCookies", map[string]any{"cookies": fixtures}); err != nil {
		t.Fatal("来源浏览器无法写入虚构 Cookie", err)
	}
	session, err := capturePortableSession(sourcePort, "Default")
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Cookies) != len(fixtures) {
		t.Fatalf("来源 Cookie 条目数错误: %d", len(session.Cookies))
	}
	closeSource()
	zipPath := filepath.Join(t.TempDir(), "portable.zip")
	if _, err := source.writeProfilePackageWithSessions(zipPath, []browser.Profile{profile}, map[string]*portableSession{"source": session}); err != nil {
		t.Fatal(err)
	}
	target, _ := newProfilePackageImportTestApp(t, nil, nil)
	target.db = newProfilePackageDatabase(t, target.appRoot)
	result, err := target.importProfilePackageFromPath(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	id := result.ProfileMappings["source"]
	targetDir := target.browserMgr.ResolveUserDataDir(&browser.Profile{ProfileId: id, UserDataDir: id})
	pending, err := readPortableSessionPending(targetDir)
	if err != nil || pending == nil {
		t.Fatalf("导入后缺少独立待恢复登录态: %v", err)
	}
	// 强制目的端使用新 Local State。Windows 将重新生成本机加密密钥，
	// 不能依赖复制来的源端 Cookie 密文碰巧仍可解密。
	if err := os.Remove(filepath.Join(targetDir, "Local State")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	targetPort, closeTarget := startPortableTestChrome(t, chrome, targetDir, pending)
	targets, err := cdpBrowserCallResult(targetPort, "Target.getTargets", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range targets["targetInfos"].([]any) {
		info := item.(map[string]any)
		if u, _ := info["url"].(string); u != "" && u != "about:blank" {
			t.Fatal("登录态恢复前不应打开业务网站")
		}
	}
	if err := restorePortableSession(targetPort, targetDir, pending); err != nil {
		t.Fatal(err)
	}
	restored, err := capturePortableSession(targetPort, "Default")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Cookies) != len(session.Cookies) {
		t.Fatalf("迁移后 Cookie 数量错误: %d", len(restored.Cookies))
	}
	actual := map[string]portableCookie{}
	for _, c := range restored.Cookies {
		actual[portableCookieKey(c)] = c
	}
	for _, want := range session.Cookies {
		got, ok := actual[portableCookieKey(want)]
		if !ok || got.Value != want.Value || got.Session != want.Session || got.HTTPOnly != want.HTTPOnly || got.Secure != want.Secure || got.SameSite != want.SameSite {
			t.Fatal("迁移未保留 Cookie 值、作用域、会话类型或安全属性")
		}
	}
	if _, err := os.Stat(filepath.Join(targetDir, portableSessionPendingFile)); !os.IsNotExist(err) {
		t.Fatal("恢复成功后必须清除一次性登录态文件")
	}
	if err := createBrowserStartTarget(targetPort, "about:blank"); err != nil {
		t.Fatal(err)
	}
	closeTarget()
	// 再次启动确认持久 Cookie 已交给目的端浏览器保存，而不是仅驻留在进程内存。
	restartPort, closeRestart := startPortableTestChrome(t, chrome, targetDir, nil)
	defer closeRestart()
	persisted, err := capturePortableSession(restartPort, "Default")
	if err != nil {
		t.Fatal(err)
	}
	persistedByKey := map[string]portableCookie{}
	for _, c := range persisted.Cookies {
		persistedByKey[portableCookieKey(c)] = c
	}
	for _, c := range session.Cookies {
		if c.Session {
			continue
		}
		if got, ok := persistedByKey[portableCookieKey(c)]; !ok || got.Value != c.Value {
			t.Fatal("目的端重启后丢失持久 Cookie")
		}
	}
	t.Log("真实 Chrome 验证通过：独立源/目标目录、ZIP 导入、目标新密钥、会话及持久 Cookie、host-only/HttpOnly/Secure/SameSite/CHIPS、首次无网站导航、单次消费、重启持久化")
}

func startPortableTestChrome(t *testing.T, chrome, dir string, pending *portableSession) (int, func()) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	port, err := nextAvailablePort()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{fmt.Sprintf("--user-data-dir=%s", dir), fmt.Sprintf("--remote-debugging-port=%d", port), "--no-first-run", "--no-default-browser-check", "about:blank"}
	if pending != nil {
		args = portableSessionLaunchArgs(dir, port, "direct://", nil, pending)
	}
	args = append(args, "--headless=new", "--disable-background-networking", "--disable-component-update", "--host-resolver-rules=MAP * ~NOTFOUND")
	args = append(args, "--enable-logging=stderr")
	logPath := filepath.Join(t.TempDir(), "chrome-startup.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.Command(chrome, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	t.Logf("Chrome=%s; temporary profile=%s; CDP=%d", chrome, dir, port)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	closed := false
	closeBrowser := func() {
		if closed {
			return
		}
		closed = true
		_, _ = cdpBrowserCallResult(port, "Browser.close", nil)
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("测试 Chrome 进程未能回收")
			}
		}
	}
	t.Cleanup(closeBrowser)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		body, err := cdpGetEndpointBody(port, "/json/version")
		if err == nil {
			var version cdpBrowserVersion
			if json.Unmarshal(body, &version) == nil && version.WebSocketDebuggerUrl != "" {
				return port, closeBrowser
			}
		}
		select {
		case <-done:
			t.Fatal("测试 Chrome 在 CDP 就绪前退出")
		case <-time.After(100 * time.Millisecond):
		}
	}
	closeBrowser()
	data, _ := os.ReadFile(logPath)
	if len(data) > 8000 {
		data = data[len(data)-8000:]
	}
	t.Fatalf("测试 Chrome CDP 接口超时，启动日志：%s", data)
	return 0, closeBrowser
}
