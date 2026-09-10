package backend

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ant-chrome/backend/internal/browser"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const portableSessionsPath = "portable-sessions.json"
const portableSessionPendingFile = ".ant-portable-session.json"
const portableSessionMaxBytes = 32 << 20
const portableSessionMaxCookies = 20000

type portableCookiePartitionKey struct {
	TopLevelSite         string `json:"topLevelSite"`
	HasCrossSiteAncestor bool   `json:"hasCrossSiteAncestor"`
}

// 只保留 CDP 支持的 Cookie 字段；不导出操作系统密钥或浏览器密码。
type portableCookie struct {
	Name               string                      `json:"name"`
	Value              string                      `json:"value"`
	Domain             string                      `json:"domain"`
	Path               string                      `json:"path"`
	Expires            *float64                    `json:"expires,omitempty"`
	Session            bool                        `json:"session,omitempty"`
	HTTPOnly           bool                        `json:"httpOnly"`
	Secure             bool                        `json:"secure"`
	SameSite           string                      `json:"sameSite,omitempty"`
	Priority           string                      `json:"priority,omitempty"`
	SourceScheme       string                      `json:"sourceScheme,omitempty"`
	SourcePort         *int                        `json:"sourcePort,omitempty"`
	PartitionKey       *portableCookiePartitionKey `json:"partitionKey,omitempty"`
	PartitionKeyOpaque bool                        `json:"partitionKeyOpaque,omitempty"`
}

type portableSession struct {
	RequireConfirmation bool             `json:"requireConfirmation,omitempty"`
	Version             int              `json:"version"`
	ProfileDirectory    string           `json:"profileDirectory"`
	Cookies             []portableCookie `json:"cookies"`
}

type portableSessionPackage struct {
	Version  int                         `json:"version"`
	Profiles map[string]*portableSession `json:"profiles"`
}

func validatePortableSession(session *portableSession) error {
	if session == nil || session.Version != 1 || session.Cookies == nil {
		return fmt.Errorf("登录态数据格式无效或版本不支持")
	}
	dir := session.ProfileDirectory
	if dir == "" || dir == "." || dir == ".." || strings.ContainsAny(dir, "/\\:\x00") || strings.TrimSpace(dir) != dir {
		return fmt.Errorf("登录态浏览器配置目录无效")
	}
	if len(session.Cookies) > portableSessionMaxCookies {
		return fmt.Errorf("登录态 Cookie 数量超出限制")
	}
	for i, c := range session.Cookies {
		if _, err := c.params(); err != nil {
			return fmt.Errorf("第 %d 条 Cookie 无法迁移：%w", i+1, err)
		}
	}
	return nil
}

func (c portableCookie) params() (map[string]any, error) {
	host := strings.TrimPrefix(c.Domain, ".")
	parsed, err := url.Parse("https://" + host + "/")
	if err != nil || host == "" || parsed.Host != host || parsed.User != nil || strings.ContainsAny(host, "/\\\x00\r\n?#") || !strings.HasPrefix(c.Path, "/") {
		return nil, fmt.Errorf("域名或路径无效")
	}
	if c.PartitionKeyOpaque {
		return nil, fmt.Errorf("不透明分区 Cookie 无法通过浏览器接口迁移")
	}
	if c.PartitionKey != nil {
		u, err := url.Parse(c.PartitionKey.TopLevelSite)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("Cookie 分区信息无效")
		}
	}
	p := map[string]any{"name": c.Name, "value": c.Value, "path": c.Path, "secure": c.Secure, "httpOnly": c.HTTPOnly}
	if strings.HasPrefix(c.Domain, ".") {
		p["domain"] = c.Domain
	} else {
		// 仅通过 URL 设置 host-only Cookie，不能把 __Host- Cookie 扩大成 domain Cookie。
		scheme := "http"
		if c.Secure || c.SourceScheme == "Secure" {
			scheme = "https"
		}
		p["url"] = (&url.URL{Scheme: scheme, Host: host, Path: c.Path}).String()
	}
	if !c.Session && c.Expires != nil && *c.Expires > 0 {
		p["expires"] = *c.Expires
	}
	if c.SameSite != "" {
		p["sameSite"] = c.SameSite
	}
	if c.Priority != "" {
		p["priority"] = c.Priority
	}
	if c.SourceScheme != "" {
		p["sourceScheme"] = c.SourceScheme
	}
	if c.SourcePort != nil {
		p["sourcePort"] = *c.SourcePort
	}
	if c.PartitionKey != nil {
		p["partitionKey"] = c.PartitionKey
	}
	return p, nil
}

func capturePortableSession(debugPort int, profileDirectory string) (*portableSession, error) {
	result, err := cdpBrowserCallResult(debugPort, "Storage.getCookies", nil)
	if err != nil {
		return nil, fmt.Errorf("读取实例登录态失败，请确认来源实例正在运行且调试接口就绪")
	}
	raw, exists := result["cookies"]
	if !exists || raw == nil {
		return nil, fmt.Errorf("浏览器未返回 Cookie 数据，已中止导出")
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > portableSessionMaxBytes {
		return nil, fmt.Errorf("Cookie 数据格式无效或过大")
	}
	session := &portableSession{Version: 1, ProfileDirectory: profileDirectory}
	if err := json.Unmarshal(encoded, &session.Cookies); err != nil {
		return nil, fmt.Errorf("浏览器 Cookie 解析失败")
	}
	if err := validatePortableSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

func readPortableSessionPending(userDataDir string) (*portableSession, error) {
	path := filepath.Join(userDataDir, portableSessionPendingFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > portableSessionMaxBytes {
		return nil, fmt.Errorf("待恢复登录态文件无效或过大")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var session portableSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("待恢复登录态 JSON 无效")
	}
	if err := validatePortableSession(&session); err != nil {
		return nil, err
	}
	return &session, nil
}

func writePortableSessionPending(userDataDir string, session *portableSession) error {
	if err := validatePortableSession(session); err != nil {
		return err
	}
	data, err := json.Marshal(session)
	if err != nil || len(data) > portableSessionMaxBytes {
		return fmt.Errorf("登录态数据过大或无效")
	}
	if err := os.MkdirAll(userDataDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(userDataDir, portableSessionPendingFile)
	// 导入 staging 内文件；拒绝沿符号链接写入其他目录。
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("待恢复登录态路径不是普通文件")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(userDataDir, ".ant-session-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readPortableSessionPackage(files []*zip.File, profiles []browser.Profile) (map[string]*portableSession, error) {
	var found *zip.File
	for _, file := range files {
		if filepath.ToSlash(file.Name) != portableSessionsPath {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("实例包包含重复的登录态文件")
		}
		found = file
	}
	if found == nil {
		return nil, nil
	}
	if found.UncompressedSize64 > portableSessionMaxBytes {
		return nil, fmt.Errorf("实例包登录态数据过大")
	}
	reader, err := found.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, portableSessionMaxBytes+1))
	if err != nil || len(data) > portableSessionMaxBytes {
		return nil, fmt.Errorf("无法读取实例包登录态数据")
	}
	var pkg portableSessionPackage
	if err := json.Unmarshal(data, &pkg); err != nil || pkg.Version != 1 || len(pkg.Profiles) != len(profiles) {
		return nil, fmt.Errorf("实例包登录态表无效或不完整")
	}
	for _, profile := range profiles {
		if err := validatePortableSession(pkg.Profiles[profile.ProfileId]); err != nil {
			return nil, fmt.Errorf("实例登录态表与实例不匹配：%w", err)
		}
	}
	return pkg.Profiles, nil
}

func portableCookieKey(c portableCookie) string {
	key := c.Name + "\x00" + c.Domain + "\x00" + c.Path
	if c.PartitionKey != nil {
		key += fmt.Sprintf("\x00%s\x00%t", c.PartitionKey.TopLevelSite, c.PartitionKey.HasCrossSiteAncestor)
	}
	return key
}

func restorePortableSession(debugPort int, userDataDir string, session *portableSession) error {
	if err := validatePortableSession(session); err != nil {
		return err
	}
	if session.RequireConfirmation {
		return fmt.Errorf("上次导出关闭状态未确认，必须明确确认后才能恢复当时登录态")
	}
	expected := make([]portableCookie, 0, len(session.Cookies))
	params := make([]map[string]any, 0, len(session.Cookies))
	now := float64(time.Now().Unix())
	for _, c := range session.Cookies {
		if !c.Session && c.Expires != nil && *c.Expires > 0 && *c.Expires <= now {
			continue
		}
		p, err := c.params()
		if err != nil {
			return err
		}
		params = append(params, p)
		expected = append(expected, c)
	}
	// 分批写入，但不跳过失败项，也不在部分成功时删除待恢复数据。
	for start := 0; start < len(params); start += 100 {
		end := start + 100
		if end > len(params) {
			end = len(params)
		}
		if _, err := cdpBrowserCallResult(debugPort, "Storage.setCookies", map[string]any{"cookies": params[start:end]}); err != nil {
			return fmt.Errorf("浏览器拒绝恢复 Cookie；登录态已保留，请检查目标内核兼容性后重试")
		}
	}
	restored, err := capturePortableSession(debugPort, session.ProfileDirectory)
	if err != nil {
		return err
	}
	byKey := make(map[string]portableCookie, len(restored.Cookies))
	for _, c := range restored.Cookies {
		byKey[portableCookieKey(c)] = c
	}
	for _, c := range expected {
		got, ok := byKey[portableCookieKey(c)]
		sessionCookie := c.Session || c.Expires == nil || *c.Expires <= 0
		if !ok || got.Value != c.Value || got.HTTPOnly != c.HTTPOnly || got.Secure != c.Secure || got.SameSite != c.SameSite || got.Session != sessionCookie {
			return fmt.Errorf("Cookie 恢复校验不完整；已阻止打开网站，登录态保留供重试")
		}
	}
	// 一次性迁移：成功后不再重放，避免用户退出账号后又被旧 Cookie 登录。
	if err := os.Remove(filepath.Join(userDataDir, portableSessionPendingFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("无法清除已使用的登录态文件：%w", err)
	}
	return nil
}

// Wails 2 的 Windows 原生询问框固定返回 Yes/No，不能依赖自定义按钮文本。
var askPortableSessionRecovery = func(a *App, message string) (bool, error) {
	if a.ctx == nil {
		return false, fmt.Errorf("导出曾中断，需要在应用界面确认是否恢复当时登录态")
	}
	answer, err := wailsruntime.MessageDialog(a.ctx, wailsruntime.MessageDialogOptions{
		Type: wailsruntime.QuestionDialog, Title: "确认中断的登录态迁移", Message: message,
		Buttons: []string{"Yes", "No"}, DefaultButton: "No", CancelButton: "No",
	})
	return strings.EqualFold(answer, "Yes"), err
}

func (a *App) confirmPortableSessionRecovery(profile *browser.Profile, allowLiveExport bool) error {
	dir := a.browserMgr.ResolveUserDataDir(profile)
	pending, err := readPortableSessionPending(dir)
	if err != nil || pending == nil || !pending.RequireConfirmation {
		return err
	}
	live := isBrowserProfileLive(profile, a.browserMgr.BrowserProcesses[profile.ProfileId])
	if detection, ok := detectBrowserRuntimeByActivePort(dir); ok && detection.DebugReady {
		live = true
	}
	if live {
		if allowLiveExport {
			return nil
		} // 重新采集当前状态，不使用旧快照。
		return fmt.Errorf("上次导出尚未确认关闭，请先关闭该实例；当时的快照仍保留且不会自动重放")
	}
	restore, err := askPortableSessionRecovery(a, "实例「"+profile.ProfileName+"」上次导出未确认完成，已保留当时的登录态快照。\n如果此后登录或退出过网站，该快照可能已过时。\n\n是否恢复当时的登录态？\n是：确认恢复并继续。\n否：进入放弃或取消选项。")
	if err != nil {
		return err
	}
	if restore {
		pending.RequireConfirmation = false
		return writePortableSessionPending(dir, pending)
	}
	discard, err := askPortableSessionRecovery(a, "是否明确放弃这份恢复快照，继续使用现有浏览器数据？\n是：删除快照并继续，可能需要重新登录。\n否：取消本次操作，快照保持不变。")
	if err != nil {
		return err
	}
	if !discard {
		return fmt.Errorf("已取消操作，恢复快照仍保留")
	}
	return os.Remove(filepath.Join(dir, portableSessionPendingFile))
}

func (a *App) confirmPortableExportRecovery(ids []string) error {
	a.browserMgr.InitData()
	a.browserMgr.Mutex.Lock()
	defer a.browserMgr.Mutex.Unlock()
	for _, id := range ids {
		profile := a.browserMgr.Profiles[id]
		if profile == nil {
			return fmt.Errorf("导出实例不存在")
		}
		if err := a.confirmPortableSessionRecovery(profile, true); err != nil {
			return err
		}
	}
	return nil
}

func profilePortableDirectory(profile *browser.Profile, userDataDir string) string {
	launchArgs := profile.LaunchArgs
	if profile.Running && len(profile.LastLaunchArgs) > 0 {
		launchArgs = profile.LastLaunchArgs
	}
	for i := len(launchArgs) - 1; i >= 0; i-- {
		arg := launchArgs[i]
		if strings.HasPrefix(arg, "--profile-directory=") {
			return strings.TrimPrefix(arg, "--profile-directory=")
		}
		if arg == "--profile-directory" && i+1 < len(launchArgs) {
			return launchArgs[i+1]
		}
	}
	var state struct {
		Profile struct {
			LastUsed string `json:"last_used"`
		} `json:"profile"`
	}
	if data, err := os.ReadFile(filepath.Join(userDataDir, "Local State")); err == nil && json.Unmarshal(data, &state) == nil && state.Profile.LastUsed != "" {
		return state.Profile.LastUsed
	}
	return "Default"
}

func hasProfileCookieStore(userDataDir string) bool {
	entries, _ := os.ReadDir(userDataDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, rel := range []string{"Cookies", "Network/Cookies"} {
			if _, err := os.Stat(filepath.Join(userDataDir, entry.Name(), filepath.FromSlash(rel))); err == nil {
				return true
			}
		}
	}
	return false
}

// 导出期间阻止应用再次启动选中实例；仅访问用户明确选中的实例。
func (a *App) profilesForPortableExport(ids []string) ([]browser.Profile, error) {
	a.browserMgr.InitData()
	a.browserMgr.Mutex.Lock()
	defer a.browserMgr.Mutex.Unlock()
	profiles := make([]browser.Profile, 0, len(ids))
	for _, id := range ids {
		p := a.browserMgr.Profiles[id]
		if p == nil {
			return nil, fmt.Errorf("导出实例不存在")
		}
		if p.Running && (!p.DebugReady || p.DebugPort <= 0) {
			return nil, fmt.Errorf("实例「%s」调试接口尚未就绪，请稍后导出", p.ProfileName)
		}
		dir := a.browserMgr.ResolveUserDataDir(p)
		pending, err := readPortableSessionPending(dir)
		if err != nil {
			return nil, err
		}
		if !p.Running && pending == nil && hasProfileCookieStore(dir) {
			return nil, fmt.Errorf("实例「%s」包含由来源电脑加密的 Cookie。请在来源电脑启动该实例，确认网站仍登录，再保持运行点击导出；程序会采集登录态并停止实例打包", p.ProfileName)
		}
		profiles = append(profiles, *p)
	}
	return profiles, nil
}

func (a *App) collectPortableSessionsForExport(profiles []browser.Profile) (map[string]*portableSession, error) {
	sessions := make(map[string]*portableSession, len(profiles))
	for i := range profiles {
		p := &profiles[i]
		dir := a.browserMgr.ResolveUserDataDir(p)
		pending, err := readPortableSessionPending(dir)
		if err != nil {
			return nil, err
		}
		if p.Running {
			pending, err = capturePortableSession(p.DebugPort, profilePortableDirectory(p, dir))
			if err != nil {
				return nil, fmt.Errorf("实例「%s」：%w", p.ProfileName, err)
			}
		}
		if pending == nil {
			pending = &portableSession{Version: 1, ProfileDirectory: profilePortableDirectory(p, dir), Cookies: []portableCookie{}}
		}
		if err := validatePortableSession(pending); err != nil {
			return nil, err
		}
		sessions[p.ProfileId] = pending
	}
	encoded, err := json.Marshal(portableSessionPackage{Version: 1, Profiles: sessions})
	if err != nil || len(encoded) > portableSessionMaxBytes {
		return nil, fmt.Errorf("登录态包过大，请减少本次导出的实例数量")
	}
	for _, p := range profiles {
		if !p.Running {
			continue
		}
		dir := a.browserMgr.ResolveUserDataDir(&p)
		// 必须先落盘再关浏览器。磁盘满、后续实例关闭或 ZIP 保存失败都能重试，
		// 来源电脑下次启动也能恢复会话 Cookie，而不是因本次导出丢失登录。
		recovery := *sessions[p.ProfileId]
		recovery.RequireConfirmation = true
		if err := writePortableSessionPending(dir, &recovery); err != nil {
			return nil, fmt.Errorf("无法安全保存来源实例的恢复快照，未关闭该实例：%w", err)
		}
		if err := a.stopPortableExportProfile(p.ProfileId, p.DebugPort); err != nil {
			// 端口仍可连接不代表关闭已取消：保留唯一快照，但禁止未经确认自动重放。
			return nil, fmt.Errorf("%w；恢复快照已保留，再次启动/导出前会要求确认是否使用当时的登录态", err)
		}
		recovery.RequireConfirmation = false
		if err := writePortableSessionPending(dir, &recovery); err != nil {
			return nil, fmt.Errorf("来源实例已停止，快照已保留但需要再次确认：%w", err)
		}
	}
	return sessions, nil
}

func (a *App) stopPortableExportProfile(profileID string, debugPort int) error {
	a.browserMgr.Mutex.Lock()
	defer a.browserMgr.Mutex.Unlock()
	p := a.browserMgr.Profiles[profileID]
	if p == nil || !p.Running || p.DebugPort != debugPort {
		return fmt.Errorf("导出期间实例运行状态改变，请重新导出")
	}
	if !tryCloseBrowserViaCDP(debugPort, 15*time.Second) {
		return fmt.Errorf("实例未能正常停止，已中止打包以避免用户数据不完整")
	}
	if monitor := a.browserProcessMonitors[profileID]; monitor != nil {
		select {
		case <-monitor.Done():
		case <-time.After(15 * time.Second):
			return fmt.Errorf("实例仍在退出并写入用户数据，请稍后重新导出")
		}
	}
	a.markProfileStoppedLocked(profileID, p)
	return nil
}

// 迁移首次启动不恢复旧标签页、不安装扩展，也不接受会提前导航的自定义参数。
// 指纹参数、目标代理保持不变；下次正常启动恢复原有启动行为。
func portableSessionLaunchArgs(userDataDir string, port int, proxy string, fingerprintArgs []string, session *portableSession) []string {
	safeFingerprintArgs := []string{}
	for _, arg := range fingerprintArgs {
		// 指纹配置同样来自导入数据，不能借此夹带 URL、扩展或自动会话恢复开关。
		for _, prefix := range []string{"--fingerprint=", "--fingerprint-", "--fingerprinting-", "--lang=", "--accept-lang=", "--timezone=", "--user-agent=", "--window-size=", "--disable-spoofing=", "--disable-non-proxied-udp", "--disable-gpu-fingerprint", "--force-webrtc-ip-handling-policy=", "--webrtc-ip-handling-policy=", "--force-color-profile="} {
			if strings.HasPrefix(arg, prefix) {
				safeFingerprintArgs = append(safeFingerprintArgs, arg)
				break
			}
		}
	}
	args := buildBrowserLaunchArgs(userDataDir, port, proxy, safeFingerprintArgs, nil, nil, nil, false)
	return append(args, "--no-startup-window", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-background-networking", "--profile-directory="+session.ProfileDirectory)
}
