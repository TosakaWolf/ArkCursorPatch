//go:build windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const (
	regSZ       = 1
	regExpandSZ = 2

	errorNoMoreItems = 259
	errorMoreData    = 234

	driveRemovable                  = 2
	driveFixed                      = 3
	stdOutputHandle                 = ^uint32(10)
	enableVirtualTerminalProcessing = 0x0004
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procGetLogicalDrives         = kernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW            = kernel32.NewProc("GetDriveTypeW")
	procGetStdHandle             = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode           = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode           = kernel32.NewProc("SetConsoleMode")
	procSetConsoleCP             = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOutputCP       = kernel32.NewProc("SetConsoleOutputCP")
	procGetUserDefaultUILanguage = kernel32.NewProc("GetUserDefaultUILanguage")
	procRegOpenKeyExW            = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumKeyExW            = advapi32.NewProc("RegEnumKeyExW")
	procRegQueryValueExW         = advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey              = advapi32.NewProc("RegCloseKey")
)

type appState struct {
	ManualGameRoot   string
	ResolvedGameRoot string
	LastResult       string
}

type uiLanguage uint8

const (
	languageEnglish uiLanguage = iota
	languageChinese
)

var currentLanguage = languageEnglish

func main() {
	configureConsoleEncoding()
	currentLanguage = detectUILanguage()
	if relaunched, err := ensureElevated(); err != nil {
		fmt.Fprintln(os.Stderr, tr("无法自动请求管理员权限：", "Could not request administrator privileges: ")+err.Error())
	} else if relaunched {
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, tr("错误：", "Error:"), err)
		os.Exit(1)
	}
}

func run() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf(tr("无法确定程序位置: %w", "Could not determine the executable location: %w"), err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf(tr("无法规范化程序位置: %w", "Could not normalize the executable location: %w"), err)
	}
	packageRoot := filepath.Dir(exePath)
	return runMenu(bufio.NewReader(os.Stdin), packageRoot, enableConsoleRefresh())
}

func runMenu(reader *bufio.Reader, packageRoot string, canClear bool) error {
	state := appState{}
	if err := refreshAppState(&state, packageRoot); err != nil {
		state.LastResult = tr("自动检查失败：", "Automatic check failed: ") + err.Error()
	} else {
		state.LastResult = tr("已就绪。请先启动游戏，再应用系统指针。", "Ready. Start the game before applying the system cursor.")
	}

	for {
		clearScreen(canClear)
		renderDashboard(state)
		choice, err := readLine(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf(tr("读取菜单输入失败: %w", "Failed to read menu input: %w"), err)
		}

		switch choice {
		case "1":
			if err := refreshAppState(&state, packageRoot); err != nil {
				state.LastResult = tr("无法应用：", "Could not apply: ") + err.Error()
				continue
			}
			targetExe := filepath.Join(state.ResolvedGameRoot, "Arknights.exe")
			active, err := applyCursorOnce(targetExe)
			if err != nil {
				state.LastResult = tr("应用失败：", "Apply failed: ") + err.Error()
				continue
			}
			clearScreen(canClear)
			fmt.Println(tr("系统指针已应用到当前游戏进程，ArkCursorPatch 已退出。", "The system cursor was applied to the running game. ArkCursorPatch has exited."))
			if !active {
				fmt.Println(tr("切换到游戏窗口后生效；重启游戏即可还原。", "It takes effect when the game enters the foreground. Restart the game to restore the original cursor."))
			} else {
				fmt.Println(tr("重启游戏即可还原。", "Restart the game to restore the original cursor."))
			}
			return nil
		case "2":
			if err := refreshAppState(&state, packageRoot); err != nil {
				state.LastResult = tr("无法恢复：", "Could not restore: ") + err.Error()
			} else {
				targetExe := filepath.Join(state.ResolvedGameRoot, "Arknights.exe")
				restored, err := restoreCursorOnce(targetExe)
				switch {
				case err != nil:
					state.LastResult = tr("恢复失败：", "Restore failed: ") + err.Error()
				case restored:
					state.LastResult = tr("已恢复当前游戏的原版指针。", "The original cursor was restored in the running game.")
				default:
					state.LastResult = tr("当前游戏未检测到本工具的运行时补丁。", "No ArkCursorPatch runtime patch was detected in the running game.")
				}
			}
		case "3":
			if err := refreshAppState(&state, packageRoot); err != nil {
				state.LastResult = tr("检查失败：", "Check failed: ") + err.Error()
			} else {
				state.LastResult = tr("检查完成，游戏目录有效。", "Check complete. The game directory is valid.")
			}
		case "4":
			if err := promptGameRoot(&state, reader, packageRoot, canClear); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				state.LastResult = tr("目录设置失败：", "Game directory setup failed: ") + err.Error()
			}
		case "5":
			if err := showInfoPage(reader, canClear, printAbout); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				return err
			}
		case "6":
			if err := showInfoPage(reader, canClear, func() { printTechnicalInfo(state) }); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				return err
			}
		case "0":
			clearScreen(canClear)
			fmt.Println(tr("ArkCursorPatch 已退出。", "ArkCursorPatch exited."))
			return nil
		default:
			state.LastResult = tr("无效选项，请输入 0 至 6。", "Invalid option. Enter a number from 0 to 6.")
		}
	}
}

func renderDashboard(state appState) {
	mode := tr("自动定位", "Automatic")
	if state.ManualGameRoot != "" {
		mode = tr("手动设置", "Manual")
	}
	gameRoot := state.ResolvedGameRoot
	if gameRoot == "" {
		gameRoot = tr("尚未找到", "Not found")
	}
	status := tr("尚未找到", "Not found")
	if state.ResolvedGameRoot != "" {
		status = tr("游戏目录有效", "Game directory is valid")
	}
	lastResult := state.LastResult
	if lastResult == "" {
		lastResult = tr("无", "None")
	}

	fmt.Println("========================================")
	fmt.Println(tr(" ArkCursorPatch  明日方舟鼠标替换", " ArkCursorPatch  Arknights Cursor Patch"))
	fmt.Println("========================================")
	fmt.Printf(tr("定位方式：%s\n", "Location mode: %s\n"), mode)
	fmt.Printf(tr("游戏目录：%s\n", "Game directory: %s\n"), gameRoot)
	fmt.Printf(tr("当前状态：%s\n", "Current state: %s\n"), status)
	fmt.Printf(tr("上次结果：%s\n", "Last result: %s\n"), lastResult)
	fmt.Println("----------------------------------------")
	fmt.Println(tr("1. 应用系统指针并退出", "1. Apply system cursor and exit"))
	fmt.Println(tr("2. 恢复当前游戏指针", "2. Restore the current game cursor"))
	fmt.Println(tr("3. 重新检查状态", "3. Check status"))
	fmt.Println(tr("4. 设置游戏目录", "4. Set game directory"))
	fmt.Println(tr("5. 查看使用说明", "5. Help"))
	fmt.Println(tr("6. 查看技术信息", "6. Technical information"))
	fmt.Println(tr("0. 退出", "0. Exit"))
	fmt.Print(tr("请选择：", "Select: "))
}

func refreshAppState(state *appState, packageRoot string) error {
	gameRoot, err := resolveGameRoot(state.ManualGameRoot, packageRoot)
	if err != nil {
		state.ResolvedGameRoot = ""
		return err
	}
	state.ResolvedGameRoot = gameRoot
	return nil
}

func promptGameRoot(state *appState, reader *bufio.Reader, packageRoot string, canClear bool) error {
	clearScreen(canClear)
	fmt.Println("========================================")
	fmt.Println(tr(" 设置游戏目录", " Set game directory"))
	fmt.Println("========================================")
	fmt.Println(tr("输入游戏根目录，例如 E:\\Hypergryph Launcher\\games\\Arknights。", "Enter the game root, for example E:\\Hypergryph Launcher\\games\\Arknights."))
	fmt.Print(tr("直接回车可恢复自动定位：", "Press Enter to return to automatic detection: "))
	input, err := readLine(reader)
	if err != nil {
		return err
	}
	input = strings.TrimSpace(strings.Trim(input, "\"'"))
	if input == "" {
		state.ManualGameRoot = ""
		if err := refreshAppState(state, packageRoot); err != nil {
			state.LastResult = tr("已恢复自动定位，但检查失败：", "Automatic detection restored, but the check failed: ") + err.Error()
			return nil
		}
		state.LastResult = tr("已恢复自动定位。", "Automatic detection restored.")
		return nil
	}
	root, err := resolveGameRoot(input, packageRoot)
	if err != nil {
		return err
	}
	state.ManualGameRoot = root
	if err := refreshAppState(state, packageRoot); err != nil {
		return err
	}
	state.LastResult = tr("游戏目录设置成功。", "Game directory set successfully.")
	return nil
}

func showInfoPage(reader *bufio.Reader, canClear bool, render func()) error {
	clearScreen(canClear)
	render()
	_, err := readLine(reader)
	return err
}

func printAbout() {
	fmt.Println("========================================")
	fmt.Println(tr(" 使用说明", " Help"))
	fmt.Println("========================================")
	if currentLanguage == languageChinese {
		fmt.Println("让《明日方舟》PC 版使用 Windows 系统指针，不修改游戏文件。")
		fmt.Println()
		fmt.Println("先启动游戏，再选择“应用系统指针并退出”。")
		fmt.Println()
		fmt.Println("补丁仅保留在当前游戏进程中；可用恢复选项或重启游戏还原。")
		fmt.Println("本工具仅供交流与学习，使用者自行承担相关风险。")
		return
	}
	fmt.Println("Uses the Windows system cursor in Arknights PC without modifying game files.")
	fmt.Println()
	fmt.Println("Start the game, then select Apply system cursor and exit.")
	fmt.Println()
	fmt.Println("The patch remains only in the running game process. Use Restore or restart the game to remove it.")
	fmt.Println("For communication and learning only. Use at your own risk.")
}

func printTechnicalInfo(state appState) {
	fmt.Println("========================================")
	fmt.Println(tr(" 技术信息", " Technical information"))
	fmt.Println("========================================")
	fmt.Println(tr("工作方式：一次修改当前游戏进程的指针逻辑，工具退出后继续使用系统箭头", "Method: Patches the running game's cursor logic once; the system arrow remains after the tool exits"))
	fmt.Println(tr("修改范围：仅当前游戏进程内存；不修改游戏文件、不注入 DLL", "Scope: Running game process memory only; no game-file changes or DLL injection"))
	fmt.Println(tr("版本识别：使用多段代码特征与原始字节共同校验，结果不唯一时拒绝修改", "Version check: Uses multiple code signatures and original-byte checks; ambiguous matches are rejected"))
	fmt.Println(tr("自动定位：优先读取启动器记录，再检查常见目录和安装注册信息", "Auto detection: Reads launcher records first, then checks common paths and installation registry data"))
	if state.ResolvedGameRoot == "" {
		fmt.Println(tr("游戏目录：尚未找到", "Game directory: Not found"))
	} else {
		fmt.Printf(tr("游戏目录：%s\n", "Game directory: %s\n"), state.ResolvedGameRoot)
		fmt.Printf(tr("目标程序：%s\n", "Target executable: %s\n"), filepath.Join(state.ResolvedGameRoot, "Arknights.exe"))
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && len(line) > 0 && errors.Is(err, io.EOF) {
		return line, nil
	}
	return line, err
}

func detectUILanguage() uiLanguage {
	if err := procGetUserDefaultUILanguage.Find(); err != nil {
		return languageEnglish
	}
	langID, _, _ := procGetUserDefaultUILanguage.Call()
	if langID&0x3ff == 0x04 {
		return languageChinese
	}
	return languageEnglish
}

func tr(chinese, english string) string {
	if currentLanguage == languageChinese {
		return chinese
	}
	return english
}

func configureConsoleEncoding() {
	if procSetConsoleCP.Find() == nil {
		procSetConsoleCP.Call(65001)
	}
	if procSetConsoleOutputCP.Find() == nil {
		procSetConsoleOutputCP.Call(65001)
	}
}

func enableConsoleRefresh() bool {
	if procGetStdHandle.Find() != nil || procGetConsoleMode.Find() != nil || procSetConsoleMode.Find() != nil {
		return false
	}
	handle, _, _ := procGetStdHandle.Call(uintptr(stdOutputHandle))
	if handle == 0 || handle == ^uintptr(0) {
		return false
	}
	var mode uint32
	result, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if result == 0 {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	result, _, _ = procSetConsoleMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
	return result != 0
}

func clearScreen(enabled bool) {
	if enabled {
		fmt.Print("\x1b[2J\x1b[H")
	}
}

func resolveGameRoot(explicitRoot, packageRoot string) (string, error) {
	if strings.TrimSpace(explicitRoot) != "" {
		full, err := filepath.Abs(strings.TrimSpace(explicitRoot))
		if err != nil {
			return "", fmt.Errorf(tr("游戏目录无效: %w", "Invalid game directory: %w"), err)
		}
		if !isArknightsGameRoot(full) {
			return "", fmt.Errorf(tr("手动指定的游戏目录无效：%s", "The selected game directory is invalid: %s"), full)
		}
		return full, nil
	}

	candidates := make(map[string]string)
	addCandidate := func(path string) string {
		path = strings.TrimSpace(strings.Trim(path, "\""))
		if path == "" {
			return ""
		}
		full, err := filepath.Abs(path)
		if err != nil {
			return ""
		}
		full = filepath.Clean(full)
		key := strings.ToLower(full)
		if _, exists := candidates[key]; !exists {
			candidates[key] = full
		}
		return key
	}
	addGameDirectories := func(parent string) {
		entries, err := os.ReadDir(parent)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() {
				addCandidate(filepath.Join(parent, entry.Name()))
			}
		}
	}

	// The launcher log records the configured path and is the most reliable
	// source when the user chose a custom directory name or location.
	preferredKey := ""
	for _, path := range launcherInstallPaths() {
		key := addCandidate(path)
		if key != "" && isArknightsGameRoot(candidates[key]) {
			preferredKey = key
			break
		}
	}

	// Check ancestors of the current directory and executable directory.
	seeds := []string{packageRoot}
	if cwd, err := os.Getwd(); err == nil {
		seeds = append(seeds, cwd)
	}
	for _, seed := range seeds {
		cursor, err := filepath.Abs(seed)
		if err != nil {
			continue
		}
		for {
			if isArknightsGameRoot(cursor) {
				addCandidate(cursor)
			}
			parent := filepath.Dir(cursor)
			if parent == cursor {
				break
			}
			cursor = parent
		}
	}

	// Check known official/common layouts on fixed and removable local drives.
	relativeRoots := []string{
		`Hypergryph Launcher\games\Arknights`,
		`Hypergryph Launcher\games\Arknights Game`,
		`Program Files\Hypergryph Launcher\games\Arknights`,
		`Program Files\Hypergryph Launcher\games\Arknights Game`,
		`Program Files (x86)\Hypergryph Launcher\games\Arknights`,
		`Program Files (x86)\Hypergryph Launcher\games\Arknights Game`,
		`Games\Hypergryph Launcher\games\Arknights`,
		`Games\Hypergryph Launcher\games\Arknights Game`,
		`Games\Arknights`,
		`Games\Arknights Game`,
	}
	for _, drive := range localDriveRoots() {
		for _, rel := range relativeRoots {
			addCandidate(filepath.Join(drive, rel))
		}
		for _, rel := range []string{
			`Hypergryph Launcher\games`,
			`Program Files\Hypergryph Launcher\games`,
			`Program Files (x86)\Hypergryph Launcher\games`,
			`Games\Hypergryph Launcher\games`,
		} {
			addGameDirectories(filepath.Join(drive, rel))
		}
	}

	// Check launcher/uninstaller registration. Values are read through the Win32
	// registry API, so paths containing non-ASCII characters are preserved.
	registryLocations := uninstallLocations()
	for _, location := range registryLocations {
		addCandidate(location)
		addCandidate(filepath.Join(location, `games\Arknights`))
		addCandidate(filepath.Join(location, `games\Arknights Game`))
		addGameDirectories(filepath.Join(location, "games"))
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	found := make([]string, 0)
	for _, key := range keys {
		root := candidates[key]
		if !isArknightsGameRoot(root) {
			continue
		}
		found = append(found, root)
	}

	if len(found) == 0 {
		return "", errors.New(tr("未能自动找到《明日方舟》PC 版；请返回菜单选择“设置游戏目录”", "Arknights PC was not found automatically. Choose Set game directory from the menu."))
	}
	if preferredKey != "" {
		preferredRoot := candidates[preferredKey]
		for _, root := range found {
			if strings.EqualFold(root, preferredRoot) {
				return root, nil
			}
		}
	}
	if len(found) == 1 {
		return found[0], nil
	}
	return "", fmt.Errorf(tr("找到 %d 个安装；请返回菜单选择“设置游戏目录”", "%d installations were found. Choose Set game directory from the menu."), len(found))
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func isArknightsGameRoot(root string) bool {
	return isRegularFile(filepath.Join(root, "Arknights.exe")) &&
		isRegularFile(filepath.Join(root, "game_files"))
}

func launcherInstallPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	launcherRoot := filepath.Join(home, "AppData", "LocalLow", "Hypergryph")
	entries, err := os.ReadDir(launcherRoot)
	if err != nil {
		return nil
	}

	type launcherLog struct {
		path    string
		modTime int64
	}
	logs := make([]launcherLog, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(launcherRoot, entry.Name(), "logs", "games.log")
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() {
			logs = append(logs, launcherLog{path: path, modTime: info.ModTime().UnixNano()})
		}
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].modTime > logs[j].modTime })

	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, log := range logs {
		data, err := os.ReadFile(log.path)
		if err != nil {
			continue
		}
		lines := bytes.Split(data, []byte{'\n'})
		for lineIndex := len(lines) - 1; lineIndex >= 0; lineIndex-- {
			line := string(lines[lineIndex])
			for _, marker := range []string{"strGameInstallPath:", "strGameInstallDir:"} {
				for searchFrom := 0; searchFrom < len(line); {
					markerIndex := strings.Index(line[searchFrom:], marker)
					if markerIndex < 0 {
						break
					}
					valueStart := searchFrom + markerIndex + len(marker)
					valueEnd := len(line)
					if comma := strings.IndexByte(line[valueStart:], ','); comma >= 0 {
						valueEnd = valueStart + comma
					}
					value := strings.TrimSpace(strings.Trim(line[valueStart:valueEnd], "\"\r"))
					if value != "" {
						value = filepath.Clean(filepath.FromSlash(value))
						key := strings.ToLower(value)
						if !seen[key] {
							seen[key] = true
							result = append(result, value)
						}
					}
					searchFrom = valueStart
				}
			}
		}
	}
	return result
}

func localDriveRoots() []string {
	mask, _, _ := procGetLogicalDrives.Call()
	result := make([]string, 0)
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+i)
		ptr, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		driveType, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(ptr)))
		if driveType == driveFixed || driveType == driveRemovable {
			result = append(result, root)
		}
	}
	return result
}

func uninstallLocations() []string {
	type rootQuery struct {
		root syscall.Handle
		path string
	}
	queries := []rootQuery{
		{syscall.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{syscall.HKEY_LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{syscall.HKEY_LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	seen := make(map[string]string)
	for _, query := range queries {
		entries, err := enumerateRegistrySubkeys(query.root, query.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			h, err := openRegistryKey(query.root, query.path+`\`+entry)
			if err != nil {
				continue
			}
			displayName, _, _ := registryString(h, "DisplayName")
			if !looksLikeArknights(displayName) {
				procRegCloseKey.Call(uintptr(h))
				continue
			}
			installLocation, _, _ := registryString(h, "InstallLocation")
			displayIcon, _, _ := registryString(h, "DisplayIcon")
			procRegCloseKey.Call(uintptr(h))

			for _, location := range []string{installLocation, iconDirectory(displayIcon)} {
				location = filepath.Clean(expandPercentEnvironment(strings.TrimSpace(location)))
				if location == "." || location == "" {
					continue
				}
				key := strings.ToLower(location)
				if _, exists := seen[key]; !exists {
					seen[key] = location
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func looksLikeArknights(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "hypergryph") ||
		strings.Contains(lower, "arknights") ||
		strings.Contains(name, "明日方舟") ||
		strings.Contains(name, "鹰角")
}

func iconDirectory(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var path string
	if strings.HasPrefix(value, "\"") {
		if end := strings.Index(value[1:], "\""); end >= 0 {
			path = value[1 : end+1]
		}
	}
	if path == "" {
		path = strings.SplitN(value, ",", 2)[0]
		path = strings.Trim(strings.TrimSpace(path), "\"")
	}
	if path == "" {
		return ""
	}
	return filepath.Dir(path)
}

func expandPercentEnvironment(value string) string {
	for searchFrom := 0; searchFrom < len(value); {
		startRel := strings.IndexByte(value[searchFrom:], '%')
		if startRel < 0 {
			break
		}
		start := searchFrom + startRel
		rest := value[start+1:]
		endRel := strings.IndexByte(rest, '%')
		if endRel < 0 {
			break
		}
		end := start + 1 + endRel
		name := value[start+1 : end]
		if replacement, ok := os.LookupEnv(name); ok {
			value = value[:start] + replacement + value[end+1:]
			searchFrom = start + len(replacement)
		} else {
			searchFrom = end + 1
		}
	}
	return value
}

func openRegistryKey(root syscall.Handle, path string) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var result syscall.Handle
	r1, _, _ := procRegOpenKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		syscall.KEY_READ,
		uintptr(unsafe.Pointer(&result)),
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return result, nil
}

func enumerateRegistrySubkeys(root syscall.Handle, path string) ([]string, error) {
	h, err := openRegistryKey(root, path)
	if err != nil {
		return nil, err
	}
	defer procRegCloseKey.Call(uintptr(h))

	result := make([]string, 0)
	for index := uint32(0); ; index++ {
		capacity := uint32(256)
		for {
			buf := make([]uint16, capacity)
			length := capacity
			r1, _, _ := procRegEnumKeyExW.Call(
				uintptr(h),
				uintptr(index),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(&length)),
				0, 0, 0, 0,
			)
			if r1 == errorNoMoreItems {
				return result, nil
			}
			if r1 == errorMoreData {
				capacity *= 2
				if capacity > 32768 {
					return result, errors.New(tr("注册表子项名称异常过长", "Registry subkey name is unexpectedly long"))
				}
				continue
			}
			if r1 != 0 {
				return result, syscall.Errno(r1)
			}
			result = append(result, syscall.UTF16ToString(buf[:length]))
			break
		}
	}
}

func registryString(h syscall.Handle, name string) (string, bool, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", false, err
	}
	var valueType uint32
	var byteCount uint32
	r1, _, _ := procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&valueType)),
		0,
		uintptr(unsafe.Pointer(&byteCount)),
	)
	if r1 != 0 {
		return "", false, syscall.Errno(r1)
	}
	if valueType != regSZ && valueType != regExpandSZ {
		return "", false, nil
	}
	if byteCount == 0 {
		return "", true, nil
	}
	buf := make([]uint16, (byteCount+1)/2)
	actual := byteCount
	r1, _, _ = procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&actual)),
	)
	if r1 != 0 {
		return "", false, syscall.Errno(r1)
	}
	return syscall.UTF16ToString(buf), true, nil
}
