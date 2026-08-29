//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
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
	stateOriginal    = "ORIGINAL_READY"
	statePatched     = "PATCHED"
	stateUnsupported = "UNSUPPORTED_VERSION"

	regSZ       = 1
	regExpandSZ = 2

	errorNoMoreItems = 259
	errorMoreData    = 234

	driveRemovable                  = 2
	driveFixed                      = 3
	stdOutputHandle                 = ^uint32(10)
	enableVirtualTerminalProcessing = 0x0004

	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procGetLogicalDrives         = kernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW            = kernel32.NewProc("GetDriveTypeW")
	procMoveFileExW              = kernel32.NewProc("MoveFileExW")
	procGetStdHandle             = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode           = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode           = kernel32.NewProc("SetConsoleMode")
	procGetUserDefaultUILanguage = kernel32.NewProc("GetUserDefaultUILanguage")
	procRegOpenKeyExW            = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumKeyExW            = advapi32.NewProc("RegEnumKeyExW")
	procRegQueryValueExW         = advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey              = advapi32.NewProc("RegCloseKey")
)

// The patch manifest is compiled into the executable. The resulting EXE is
// sufficient on its own for check/apply/restore operations and does not contain
// a complete game asset.
//
//go:embed patch_manifest.json
var manifestData []byte

type patchRecord struct {
	Tier               string `json:"tier"`
	AbsoluteFileOffset int64  `json:"absolute_file_offset"`
	ExpectedHex        string `json:"expected_hex"`
	ReplacementHex     string `json:"replacement_hex"`
}

type manifest struct {
	PackageName        string        `json:"package_name"`
	GameContentVersion string        `json:"game_content_version"`
	RelativeTarget     string        `json:"relative_target"`
	SourceFileSize     int64         `json:"source_file_size"`
	SourceSHA256       string        `json:"source_sha256"`
	PatchedSHA256      string        `json:"patched_sha256"`
	PatchRecords       []patchRecord `json:"patch_records"`
}

type installation struct {
	GameRoot string
	State    string
}

type appState struct {
	ManualGameRoot   string
	ResolvedGameRoot string
	Target           string
	InstallState     string
	Size             int64
	SHA256           string
	LastResult       string
}

type uiLanguage uint8

const (
	languageEnglish uiLanguage = iota
	languageChinese
)

var currentLanguage = languageEnglish

func main() {
	currentLanguage = detectUILanguage()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, tr("错误：", "Error:"), err)
		os.Exit(1)
	}
}

func run() error {
	var m manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return fmt.Errorf(tr("解析内嵌补丁清单失败: %w", "Failed to parse the embedded patch manifest: %w"), err)
	}
	m.SourceSHA256 = strings.ToLower(m.SourceSHA256)
	m.PatchedSHA256 = strings.ToLower(m.PatchedSHA256)
	if m.PackageName != "ArkCursorPatch" || m.RelativeTarget == "" || m.SourceFileSize <= 0 ||
		len(m.SourceSHA256) != 64 || len(m.PatchedSHA256) != 64 || len(m.PatchRecords) == 0 {
		return errors.New(tr("内嵌补丁清单不完整", "The embedded patch manifest is incomplete"))
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf(tr("无法确定程序位置: %w", "Could not determine the executable location: %w"), err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf(tr("无法规范化程序位置: %w", "Could not normalize the executable location: %w"), err)
	}
	packageRoot := filepath.Dir(exePath)
	return runMenu(bufio.NewReader(os.Stdin), packageRoot, m, enableConsoleRefresh())
}

func runMenu(reader *bufio.Reader, packageRoot string, m manifest, canClear bool) error {
	state := appState{}
	if err := refreshAppState(&state, packageRoot, m); err != nil {
		state.LastResult = tr("自动检查失败：", "Automatic check failed: ") + err.Error()
	} else {
		state.LastResult = tr("自动检查完成：", "Automatic check complete: ") + stateLabel(state.InstallState)
	}

	for {
		clearScreen(canClear)
		renderDashboard(state, m)
		choice, err := readLine(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf(tr("读取菜单输入失败: %w", "Failed to read menu input: %w"), err)
		}

		switch choice {
		case "1":
			if err := refreshAppState(&state, packageRoot, m); err != nil {
				state.LastResult = tr("检查失败：", "Check failed: ") + err.Error()
			} else {
				state.LastResult = tr("检查完成：", "Check complete: ") + stateLabel(state.InstallState)
			}
		case "2":
			if err := performApply(&state, packageRoot, m, reader, canClear); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				state.LastResult = tr("应用失败：", "Apply failed: ") + err.Error()
			}
		case "3":
			if err := performRestore(&state, packageRoot, m, reader, canClear); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				state.LastResult = tr("恢复失败：", "Restore failed: ") + err.Error()
			}
		case "4":
			if err := promptGameRoot(&state, reader, packageRoot, m, canClear); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				state.LastResult = tr("目录设置失败：", "Game directory setup failed: ") + err.Error()
			}
		case "5":
			if err := showInfoPage(reader, canClear, func() { printAbout(m) }); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				return err
			}
		case "6":
			if err := showInfoPage(reader, canClear, func() { printTechnicalInfo(state, packageRoot, m) }); errors.Is(err, io.EOF) {
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

func renderDashboard(state appState, m manifest) {
	mode := tr("自动定位", "Automatic")
	if state.ManualGameRoot != "" {
		mode = tr("手动设置", "Manual")
	}
	gameRoot := state.ResolvedGameRoot
	if gameRoot == "" {
		gameRoot = tr("尚未找到", "Not found")
	}
	status := tr("尚未检查", "Not checked")
	if state.InstallState != "" {
		status = stateLabel(state.InstallState)
	}
	lastResult := state.LastResult
	if lastResult == "" {
		lastResult = tr("无", "None")
	}

	fmt.Println("========================================")
	fmt.Println(tr(" ArkCursorPatch  明日方舟鼠标替换", " ArkCursorPatch  Arknights Cursor Patch"))
	fmt.Println("========================================")
	fmt.Printf(tr("支持版本：%s\n", "Supported version: %s\n"), m.GameContentVersion)
	fmt.Printf(tr("定位方式：%s\n", "Location mode: %s\n"), mode)
	fmt.Printf(tr("游戏目录：%s\n", "Game directory: %s\n"), gameRoot)
	fmt.Printf(tr("当前状态：%s\n", "Current state: %s\n"), status)
	fmt.Printf(tr("上次结果：%s\n", "Last result: %s\n"), lastResult)
	fmt.Println("----------------------------------------")
	fmt.Println(tr("1. 重新检查状态", "1. Check status"))
	fmt.Println(tr("2. 应用鼠标替换", "2. Apply cursor replacement"))
	fmt.Println(tr("3. 恢复原版", "3. Restore original"))
	fmt.Println(tr("4. 设置游戏目录", "4. Set game directory"))
	fmt.Println(tr("5. 查看使用说明", "5. Help"))
	fmt.Println(tr("6. 查看技术信息", "6. Technical information"))
	fmt.Println(tr("0. 退出", "0. Exit"))
	fmt.Print(tr("请选择：", "Select: "))
}

func refreshAppState(state *appState, packageRoot string, m manifest) error {
	gameRoot, err := resolveGameRoot(state.ManualGameRoot, packageRoot, m)
	if err != nil {
		state.ResolvedGameRoot = ""
		state.Target = ""
		state.InstallState = ""
		state.Size = 0
		state.SHA256 = ""
		return err
	}
	target := filepath.Join(gameRoot, m.RelativeTarget)
	installState, size, hash, err := inspectTarget(target, m)
	if err != nil {
		state.ResolvedGameRoot = ""
		state.Target = ""
		state.InstallState = ""
		state.Size = 0
		state.SHA256 = ""
		return err
	}
	state.ResolvedGameRoot = gameRoot
	state.Target = target
	state.InstallState = installState
	state.Size = size
	state.SHA256 = hash
	return nil
}

func performApply(state *appState, packageRoot string, m manifest, reader *bufio.Reader, canClear bool) error {
	if err := refreshAppState(state, packageRoot, m); err != nil {
		return err
	}
	switch state.InstallState {
	case statePatched:
		state.LastResult = tr("鼠标替换已经应用，无需重复操作。", "Cursor replacement is already applied.")
		return nil
	case stateUnsupported:
		state.LastResult = tr("文件版本不受支持，未进行修改。", "This file version is not supported. No changes were made.")
		return nil
	case stateOriginal:
	default:
		return errors.New(tr("当前状态无法应用", "The patch cannot be applied in the current state"))
	}

	clearScreen(canClear)
	printConfirmation(tr("应用鼠标替换", "Apply cursor replacement"), *state)
	confirmed, err := confirm(reader, tr("输入 y 确认，其他输入取消：", "Enter y to confirm; any other input cancels: "))
	if err != nil {
		return err
	}
	if !confirmed {
		state.LastResult = tr("已取消应用，文件没有修改。", "Apply cancelled. No files were changed.")
		return nil
	}

	backupPath := backupPathFor(packageRoot, m)
	if err := applyPatch(state.Target, backupPath, state.InstallState, m); err != nil {
		return err
	}
	if err := refreshAppState(state, packageRoot, m); err != nil {
		state.LastResult = tr("应用完成，但状态刷新失败：", "Apply completed, but the status refresh failed: ") + err.Error()
		return nil
	}
	state.LastResult = tr("应用成功，原版备份已保存。", "Applied successfully. The original backup was saved.")
	return nil
}

func performRestore(state *appState, packageRoot string, m manifest, reader *bufio.Reader, canClear bool) error {
	if err := refreshAppState(state, packageRoot, m); err != nil {
		return err
	}
	switch state.InstallState {
	case stateOriginal:
		state.LastResult = tr("当前已经是原版，无需恢复。", "The file is already original.")
		return nil
	case stateUnsupported:
		state.LastResult = tr("文件版本不受支持，未进行修改。", "This file version is not supported. No changes were made.")
		return nil
	case statePatched:
	default:
		return errors.New(tr("当前状态无法恢复", "The original file cannot be restored in the current state"))
	}

	clearScreen(canClear)
	printConfirmation(tr("恢复原版", "Restore original"), *state)
	confirmed, err := confirm(reader, tr("输入 y 确认，其他输入取消：", "Enter y to confirm; any other input cancels: "))
	if err != nil {
		return err
	}
	if !confirmed {
		state.LastResult = tr("已取消恢复，文件没有修改。", "Restore cancelled. No files were changed.")
		return nil
	}

	if err := restorePatch(state.Target, backupPathFor(packageRoot, m), state.InstallState, m); err != nil {
		return err
	}
	if err := refreshAppState(state, packageRoot, m); err != nil {
		state.LastResult = tr("恢复完成，但状态刷新失败：", "Restore completed, but the status refresh failed: ") + err.Error()
		return nil
	}
	state.LastResult = tr("恢复成功，当前文件已还原为原版。", "Restored successfully. The original file is active.")
	return nil
}

func printConfirmation(action string, state appState) {
	fmt.Println("========================================")
	fmt.Printf(" %s\n", action)
	fmt.Println("========================================")
	fmt.Printf(tr("游戏目录：%s\n", "Game directory: %s\n"), state.ResolvedGameRoot)
	fmt.Printf(tr("当前状态：%s\n", "Current state: %s\n"), stateLabel(state.InstallState))
	fmt.Println(tr("请确认游戏和启动器已经完全退出。", "Make sure the game and launcher are fully closed."))
	fmt.Println()
}

func backupPathFor(packageRoot string, m manifest) string {
	return filepath.Join(packageRoot, "backup", "sharedassets0.assets."+m.SourceSHA256+".bak")
}

func promptGameRoot(state *appState, reader *bufio.Reader, packageRoot string, m manifest, canClear bool) error {
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
		if err := refreshAppState(state, packageRoot, m); err != nil {
			state.LastResult = tr("已恢复自动定位，但检查失败：", "Automatic detection restored, but the check failed: ") + err.Error()
			return nil
		}
		state.LastResult = tr("已恢复自动定位。", "Automatic detection restored.")
		return nil
	}
	root, err := resolveGameRoot(input, packageRoot, m)
	if err != nil {
		return err
	}
	state.ManualGameRoot = root
	if err := refreshAppState(state, packageRoot, m); err != nil {
		return err
	}
	state.LastResult = tr("游戏目录设置成功。", "Game directory set successfully.")
	return nil
}

func showInfoPage(reader *bufio.Reader, canClear bool, render func()) error {
	clearScreen(canClear)
	render()
	fmt.Println()
	fmt.Print(tr("按回车键返回主菜单……", "Press Enter to return to the main menu..."))
	_, err := readLine(reader)
	return err
}

func printAbout(m manifest) {
	fmt.Println("========================================")
	fmt.Println(tr(" 使用说明", " Help"))
	fmt.Println("========================================")
	if currentLanguage == languageChinese {
		fmt.Println("关闭《明日方舟》PC 版的游戏鼠标图片，改用 Windows 系统指针。")
		fmt.Println("支持版本：", m.GameContentVersion)
		fmt.Println()
		fmt.Println("操作前请完全退出游戏和启动器。程序会自动寻找游戏，")
		fmt.Println("修改前自动备份；需要还原时选择“恢复原版”。")
		fmt.Println("版本不匹配时不会修改文件。")
		fmt.Println()
		fmt.Println("本工具仅供交流与学习。使用前请自行备份，并自行承担")
		fmt.Println("修改本地游戏资源可能产生的风险。")
		return
	}
	fmt.Println("Disables the Arknights PC custom cursor and uses the Windows system cursor.")
	fmt.Println("Supported version:", m.GameContentVersion)
	fmt.Println()
	fmt.Println("Close the game and launcher before making changes. The tool finds the game")
	fmt.Println("automatically and creates a backup before applying the patch. Choose")
	fmt.Println("Restore original to revert. Unsupported file versions are not modified.")
	fmt.Println()
	fmt.Println("For communication and learning only. Back up your files first and accept")
	fmt.Println("the risks of modifying local game resources.")
}

func printTechnicalInfo(state appState, packageRoot string, m manifest) {
	fmt.Println("========================================")
	fmt.Println(tr(" 技术信息", " Technical information"))
	fmt.Println("========================================")
	fmt.Printf(tr("支持版本：%s\n", "Supported version: %s\n"), m.GameContentVersion)
	fmt.Printf(tr("补丁记录：%d 条\n", "Patch records: %d\n"), len(m.PatchRecords))
	if state.ResolvedGameRoot == "" {
		fmt.Println(tr("游戏目录：尚未找到", "Game directory: Not found"))
		fmt.Println(tr("文件状态：尚未检查", "File state: Not checked"))
	} else {
		fmt.Printf(tr("游戏目录：%s\n", "Game directory: %s\n"), state.ResolvedGameRoot)
		fmt.Printf(tr("目标文件：%s\n", "Target file: %s\n"), state.Target)
		fmt.Printf(tr("文件状态：%s\n", "File state: %s\n"), stateLabel(state.InstallState))
		fmt.Printf(tr("文件大小：%d 字节\n", "File size: %d bytes\n"), state.Size)
		fmt.Printf(tr("当前 SHA-256：%s\n", "Current SHA-256: %s\n"), strings.ToUpper(state.SHA256))
	}
	fmt.Printf(tr("原版 SHA-256：%s\n", "Original SHA-256: %s\n"), strings.ToUpper(m.SourceSHA256))
	fmt.Printf(tr("补丁 SHA-256：%s\n", "Patched SHA-256: %s\n"), strings.ToUpper(m.PatchedSHA256))
	fmt.Printf(tr("备份位置：%s\n", "Backup path: %s\n"), backupPathFor(packageRoot, m))
}

func confirm(reader *bufio.Reader, prompt string) (bool, error) {
	fmt.Print(prompt)
	answer, err := readLine(reader)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes" || answer == "是", nil
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

func resolveGameRoot(explicitRoot, packageRoot string, m manifest) (string, error) {
	if strings.TrimSpace(explicitRoot) != "" {
		full, err := filepath.Abs(strings.TrimSpace(explicitRoot))
		if err != nil {
			return "", fmt.Errorf(tr("游戏目录无效: %w", "Invalid game directory: %w"), err)
		}
		if !isRegularFile(filepath.Join(full, m.RelativeTarget)) {
			return "", fmt.Errorf(tr("手动指定的游戏目录无效：%s", "The selected game directory is invalid: %s"), full)
		}
		return full, nil
	}

	candidates := make(map[string]string)
	addCandidate := func(path string) {
		path = strings.TrimSpace(strings.Trim(path, "\""))
		if path == "" {
			return
		}
		full, err := filepath.Abs(path)
		if err != nil {
			return
		}
		full = filepath.Clean(full)
		key := strings.ToLower(full)
		if _, exists := candidates[key]; !exists {
			candidates[key] = full
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
			if isRegularFile(filepath.Join(cursor, m.RelativeTarget)) {
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
		`Program Files\Hypergryph Launcher\games\Arknights`,
		`Program Files (x86)\Hypergryph Launcher\games\Arknights`,
		`Games\Hypergryph Launcher\games\Arknights`,
		`Games\Arknights`,
	}
	for _, drive := range localDriveRoots() {
		for _, rel := range relativeRoots {
			addCandidate(filepath.Join(drive, rel))
		}
	}

	// Check launcher/uninstaller registration. Values are read through the Win32
	// registry API, so paths containing non-ASCII characters are preserved.
	registryLocations := uninstallLocations()
	for _, location := range registryLocations {
		addCandidate(location)
		addCandidate(filepath.Join(location, `games\Arknights`))
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	found := make([]installation, 0)
	for _, key := range keys {
		root := candidates[key]
		target := filepath.Join(root, m.RelativeTarget)
		if !isRegularFile(target) {
			continue
		}
		hash, err := hashFile(target)
		if err != nil {
			continue
		}
		found = append(found, installation{
			GameRoot: root,
			State:    stateForHash(hash, m),
		})
	}

	if len(found) == 0 {
		return "", errors.New(tr("未能自动找到《明日方舟》PC 版；请返回菜单选择“设置游戏目录”", "Arknights PC was not found automatically. Choose Set game directory from the menu."))
	}
	supported := make([]installation, 0)
	for _, item := range found {
		if item.State == stateOriginal || item.State == statePatched {
			supported = append(supported, item)
		}
	}
	if len(supported) == 1 {
		return supported[0].GameRoot, nil
	}
	if len(supported) > 1 {
		return "", fmt.Errorf(tr("找到 %d 个受支持的安装；请返回菜单选择“设置游戏目录”", "%d supported installations were found. Choose Set game directory from the menu."), len(supported))
	}
	if len(found) == 1 {
		return found[0].GameRoot, nil
	}
	return "", fmt.Errorf(tr("找到 %d 个不受当前补丁支持的安装；请返回菜单选择“设置游戏目录”", "%d installations were found, but none is supported by this patch. Choose Set game directory from the menu."), len(found))
}

func inspectTarget(target string, m manifest) (string, int64, string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return "", 0, "", fmt.Errorf(tr("读取目标文件失败 %s: %w", "Failed to read target file %s: %w"), target, err)
	}
	if !info.Mode().IsRegular() {
		return "", 0, "", fmt.Errorf(tr("目标不是普通文件：%s", "Target is not a regular file: %s"), target)
	}
	hash, err := hashFile(target)
	if err != nil {
		return "", 0, "", fmt.Errorf(tr("计算目标 SHA-256 失败: %w", "Failed to calculate target SHA-256: %w"), err)
	}
	return stateForHash(hash, m), info.Size(), hash, nil
}

func stateLabel(state string) string {
	switch state {
	case stateOriginal:
		return tr("原版文件，可以应用", "Original file; ready to apply")
	case statePatched:
		return tr("鼠标替换已应用", "Cursor replacement applied")
	case stateUnsupported:
		return tr("文件版本不受支持", "Unsupported file version")
	default:
		return state
	}
}

func applyPatch(target, backupPath, state string, m manifest) error {
	if state == statePatched {
		return nil
	}
	if state != stateOriginal {
		return errors.New(tr("拒绝应用：已安装文件不是当前补丁支持的原版", "Apply refused: the installed file is not a supported original"))
	}
	patchedPayload, err := buildPatchedPayload(target, m)
	if err != nil {
		return fmt.Errorf(tr("根据补丁记录生成目标内容失败，目标未修改: %w", "Failed to build the patched content; the target was not changed: %w"), err)
	}
	if err := ensureBackup(target, backupPath, m.SourceSHA256); err != nil {
		return fmt.Errorf(tr("创建或校验备份失败，目标未修改: %w", "Failed to create or verify the backup; the target was not changed: %w"), err)
	}

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf(tr("读取目标属性失败: %w", "Failed to read target attributes: %w"), err)
	}
	if err := atomicInstallBytes(target, patchedPayload, info.Mode()); err != nil {
		return applyFailureWithRestore(target, backupPath, m, err)
	}
	got, err := hashFile(target)
	if err != nil || got != m.PatchedSHA256 {
		if err == nil {
			err = fmt.Errorf(tr("写入后的 SHA-256 为 %s，预期 %s", "SHA-256 after writing is %s; expected %s"), got, m.PatchedSHA256)
		}
		return applyFailureWithRestore(target, backupPath, m, err)
	}
	return nil
}

func buildPatchedPayload(target string, m manifest) ([]byte, error) {
	original, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	return applyPatchRecords(original, m)
}

func applyPatchRecords(original []byte, m manifest) ([]byte, error) {
	if int64(len(original)) != m.SourceFileSize {
		return nil, fmt.Errorf(tr("原文件大小为 %d，预期 %d", "Original file size is %d; expected %d"), len(original), m.SourceFileSize)
	}
	if got := hashBytes(original); got != m.SourceSHA256 {
		return nil, fmt.Errorf(tr("原文件 SHA-256 为 %s，预期 %s", "Original file SHA-256 is %s; expected %s"), got, m.SourceSHA256)
	}

	patched := bytes.Clone(original)
	for _, record := range m.PatchRecords {
		expected, err := hex.DecodeString(record.ExpectedHex)
		if err != nil {
			return nil, fmt.Errorf(tr("%s 的 expected_hex 无效: %w", "%s has an invalid expected_hex: %w"), record.Tier, err)
		}
		replacement, err := hex.DecodeString(record.ReplacementHex)
		if err != nil {
			return nil, fmt.Errorf(tr("%s 的 replacement_hex 无效: %w", "%s has an invalid replacement_hex: %w"), record.Tier, err)
		}
		if len(expected) == 0 || len(expected) != len(replacement) {
			return nil, fmt.Errorf(tr("%s 的补丁记录长度无效", "%s has an invalid patch record length"), record.Tier)
		}
		if record.AbsoluteFileOffset < 0 || record.AbsoluteFileOffset > int64(len(patched)-len(expected)) {
			return nil, fmt.Errorf(tr("%s 的补丁偏移越界: %d", "%s patch offset is out of range: %d"), record.Tier, record.AbsoluteFileOffset)
		}
		start := int(record.AbsoluteFileOffset)
		end := start + len(expected)
		if !bytes.Equal(patched[start:end], expected) {
			return nil, fmt.Errorf(tr("%s 在偏移 %d 的原字节不匹配", "%s original bytes do not match at offset %d"), record.Tier, record.AbsoluteFileOffset)
		}
		copy(patched[start:end], replacement)
	}
	if got := hashBytes(patched); got != m.PatchedSHA256 {
		return nil, fmt.Errorf(tr("生成内容 SHA-256 为 %s，预期 %s", "Generated content SHA-256 is %s; expected %s"), got, m.PatchedSHA256)
	}
	return patched, nil
}

func applyFailureWithRestore(target, backupPath string, m manifest, cause error) error {
	currentHash, hashErr := hashFile(target)
	if hashErr == nil && currentHash == m.SourceSHA256 {
		return fmt.Errorf(tr("应用失败，目标仍保持原版: %w", "Apply failed; the target remains original: %w"), cause)
	}
	if restoreErr := installVerifiedBackup(target, backupPath, m.SourceSHA256); restoreErr != nil {
		return fmt.Errorf(tr("应用失败，且自动恢复也失败（请保留备份并手动处理）：应用错误: %v；恢复错误: %w", "Apply failed, and automatic recovery also failed. Keep the backup and restore manually. Apply error: %v; restore error: %w"), cause, restoreErr)
	}
	return fmt.Errorf(tr("应用失败，已自动恢复原版: %w", "Apply failed; the original was restored automatically: %w"), cause)
}

func restorePatch(target, backupPath, state string, m manifest) error {
	if state == stateOriginal {
		return nil
	}
	if state != statePatched {
		return errors.New(tr("拒绝恢复：已安装文件既不是受支持的原版，也不是本补丁版本", "Restore refused: the installed file is neither a supported original nor this patch version"))
	}
	if err := installVerifiedBackup(target, backupPath, m.SourceSHA256); err != nil {
		return fmt.Errorf(tr("恢复失败: %w", "Restore failed: %w"), err)
	}
	return nil
}

func ensureBackup(source, backupPath, expectedHash string) error {
	if isRegularFile(backupPath) {
		got, err := hashFile(backupPath)
		if err != nil {
			return err
		}
		if got != expectedHash {
			return fmt.Errorf(tr("已有备份校验失败：%s", "Existing backup verification failed: %s"), backupPath)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(backupPath), ".cursor-backup-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = io.Copy(tmp, in); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	_ = os.Chmod(tmpPath, info.Mode())
	got, err := hashFile(tmpPath)
	if err != nil {
		return err
	}
	if got != expectedHash {
		return fmt.Errorf(tr("临时备份校验失败：得到 %s", "Temporary backup verification failed; got %s"), got)
	}
	if err := os.Rename(tmpPath, backupPath); err != nil {
		if isRegularFile(backupPath) {
			got, hashErr := hashFile(backupPath)
			if hashErr == nil && got == expectedHash {
				return nil
			}
		}
		return err
	}
	return nil
}

func installVerifiedBackup(target, backupPath, expectedHash string) error {
	if !isRegularFile(backupPath) {
		return fmt.Errorf(tr("找不到经校验的原版备份：%s", "Verified original backup not found: %s"), backupPath)
	}
	got, err := hashFile(backupPath)
	if err != nil {
		return err
	}
	if got != expectedHash {
		return fmt.Errorf(tr("备份 SHA-256 校验失败：得到 %s", "Backup SHA-256 verification failed; got %s"), got)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(target); statErr == nil {
		mode = info.Mode()
	} else if backupInfo, backupErr := os.Stat(backupPath); backupErr == nil {
		mode = backupInfo.Mode()
	}
	if err := atomicInstallBytes(target, data, mode); err != nil {
		return err
	}
	got, err = hashFile(target)
	if err != nil {
		return err
	}
	if got != expectedHash {
		return fmt.Errorf(tr("恢复后的 SHA-256 校验失败：得到 %s", "Restored SHA-256 verification failed; got %s"), got)
	}
	return nil
}

func atomicInstallBytes(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".cursor-patch-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	_ = os.Chmod(tmpPath, mode)
	if err := moveFileReplace(tmpPath, target); err != nil {
		return fmt.Errorf(tr("原子替换目标失败（请确认游戏和启动器已完全退出）: %w", "Atomic target replacement failed. Make sure the game and launcher are fully closed: %w"), err)
	}
	return nil
}

func moveFileReplace(source, target string) error {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	r1, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(targetPtr)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if r1 == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("MoveFileExW failed")
	}
	return nil
}

func stateForHash(hash string, m manifest) string {
	switch strings.ToLower(hash) {
	case m.SourceSHA256:
		return stateOriginal
	case m.PatchedSHA256:
		return statePatched
	default:
		return stateUnsupported
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
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
