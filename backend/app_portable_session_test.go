package backend

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ant-chrome/backend/internal/browser"
)

// 使用虚构 Cookie；不读取真实浏览器资料或访问第三方账号。
// 原实现只复制 user-data，会忽略独立登录态，因此本用例在修复前应失败。
func TestPortableSessionImportStagesCookiesBeforeFirstLaunch(t *testing.T) {
	app, _ := newProfilePackageImportTestApp(t, nil, nil)
	zipPath := filepath.Join(t.TempDir(), "portable.zip")
	out, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	entries := map[string]any{
		"manifest.json": ProfilePackageManifest{Format: profilePackageFormat, Version: 1, ProfileCount: 1},
		"profiles.json": []browser.Profile{{ProfileId: "source", ProfileName: "迁移测试", UserDataDir: "source"}},
		"portable-sessions.json": map[string]any{
			"version": 1,
			"profiles": map[string]any{"source": map[string]any{
				"version": 1, "profileDirectory": "Default",
				"cookies": []map[string]any{{"name": "synthetic_session", "value": "fixture-only", "domain": "example.test", "path": "/", "secure": true, "httpOnly": true, "sameSite": "Lax"}},
			}},
		},
	}
	for name, value := range entries {
		if err := writeProfilePackageJSON(zw, name, value); err != nil {
			t.Fatal(err)
		}
	}
	w, err := zw.Create("user-data/source/Default/Preferences")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"session":{"restore_on_startup":1}}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := app.importProfilePackageFromPath(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	id := result.ProfileMappings["source"]
	dir := app.browserMgr.ResolveUserDataDir(&browser.Profile{ProfileId: id, UserDataDir: id})
	data, err := os.ReadFile(filepath.Join(dir, ".ant-portable-session.json"))
	if err != nil {
		t.Fatalf("跨电脑导入必须暂存独立 Cookie 登录态，在首次网页导航前恢复；当前仅还原原电脑加密文件: %v", err)
	}
	var got struct {
		Cookies []map[string]any `json:"cookies"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cookies) != 1 || got.Cookies[0]["value"] != "fixture-only" {
		t.Fatal("Cookie 登录态未完整保留")
	}
}
