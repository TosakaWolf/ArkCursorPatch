//go:build windows

package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	rtProcessVMOperation             = 0x0008
	rtProcessVMRead                  = 0x0010
	rtProcessVMWrite                 = 0x0020
	rtProcessQueryInformation        = 0x0400
	rtProcessQueryLimitedInformation = 0x1000
	rtTH32CSSnapModule               = 0x00000008
	rtTH32CSSnapModule32             = 0x00000010
	rtMemCommit                      = 0x00001000
	rtMemReserve                     = 0x00002000
	rtPageExecuteReadWrite           = 0x40
	rtInvalidHandleValue             = ^uintptr(0)
	rtTokenQuery                     = 0x0008
	rtTokenElevation                 = 20
	rtIDCArrow                       = 32512
	rtCursorShowing                  = 0x00000001
	rtStillActive                    = 259
)

type rtModuleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlobalUsage  uint32
	ProcessUsage uint32
	BaseAddress  uintptr
	BaseSize     uint32
	ModuleHandle uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

type rtCursorInfo struct {
	Size   uint32
	Flags  uint32
	Cursor syscall.Handle
	X      int32
	Y      int32
}

type maskedPattern struct {
	bytes []byte
	mask  []bool
}

type runtimeLayout struct {
	onTickRVA           uint32
	onTickEntry         []byte
	onTickInitFlagRVA   uint32
	switchStateRVA      uint32
	switchPatchRVA      uint32
	switchPatchOriginal []byte
	refreshRVA          uint32
	refreshSequenceRVA  uint32
	refreshOriginalA    []byte
	refreshOriginalB    []byte
	refreshOriginalCall []byte
	setCursorRVA        uint32
}

type runtimePatch struct {
	address  uintptr
	original []byte
	patched  []byte
	applied  bool
}

type processSession struct {
	process      uintptr
	gameAssembly uintptr
	layout       runtimeLayout
	patches      []runtimePatch
	systemCursor uintptr
}

var (
	rtKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	rtUser32                     = syscall.NewLazyDLL("user32.dll")
	rtAdvapi32                   = syscall.NewLazyDLL("advapi32.dll")
	rtShell32                    = syscall.NewLazyDLL("shell32.dll")
	rtProcOpenProcess            = rtKernel32.NewProc("OpenProcess")
	rtProcCloseHandle            = rtKernel32.NewProc("CloseHandle")
	rtProcQueryFullProcessName   = rtKernel32.NewProc("QueryFullProcessImageNameW")
	rtProcCreateSnapshot         = rtKernel32.NewProc("CreateToolhelp32Snapshot")
	rtProcModule32First          = rtKernel32.NewProc("Module32FirstW")
	rtProcModule32Next           = rtKernel32.NewProc("Module32NextW")
	rtProcReadProcessMemory      = rtKernel32.NewProc("ReadProcessMemory")
	rtProcWriteProcessMemory     = rtKernel32.NewProc("WriteProcessMemory")
	rtProcVirtualProtectEx       = rtKernel32.NewProc("VirtualProtectEx")
	rtProcVirtualAllocEx         = rtKernel32.NewProc("VirtualAllocEx")
	rtProcFlushInstructionCache  = rtKernel32.NewProc("FlushInstructionCache")
	rtProcGetExitCodeProcess     = rtKernel32.NewProc("GetExitCodeProcess")
	rtProcGetCurrentProcess      = rtKernel32.NewProc("GetCurrentProcess")
	rtProcEnumWindows            = rtUser32.NewProc("EnumWindows")
	rtProcIsWindowVisible        = rtUser32.NewProc("IsWindowVisible")
	rtProcGetWindowThreadProcess = rtUser32.NewProc("GetWindowThreadProcessId")
	rtProcGetForegroundWindow    = rtUser32.NewProc("GetForegroundWindow")
	rtProcGetCursorInfo          = rtUser32.NewProc("GetCursorInfo")
	rtProcLoadCursorW            = rtUser32.NewProc("LoadCursorW")
	rtProcOpenProcessToken       = rtAdvapi32.NewProc("OpenProcessToken")
	rtProcGetTokenInformation    = rtAdvapi32.NewProc("GetTokenInformation")
	rtProcShellExecuteW          = rtShell32.NewProc("ShellExecuteW")
)

func ensureElevated() (bool, error) {
	elevated, err := isElevated()
	if err != nil || elevated {
		return false, err
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return false, err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return false, err
	}
	directory, err := syscall.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return false, err
	}
	result, _, callErr := rtProcShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0,
		uintptr(unsafe.Pointer(directory)),
		1,
	)
	if result <= 32 {
		if callErr != syscall.Errno(0) {
			return false, callErr
		}
		return false, fmt.Errorf("ShellExecuteW returned %d", result)
	}
	return true, nil
}

func isElevated() (bool, error) {
	process, _, err := rtProcGetCurrentProcess.Call()
	if process == 0 {
		return false, err
	}
	var token uintptr
	ok, _, err := rtProcOpenProcessToken.Call(process, rtTokenQuery, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return false, err
	}
	defer rtProcCloseHandle.Call(token)
	var elevation uint32
	var returned uint32
	ok, _, err = rtProcGetTokenInformation.Call(
		token,
		rtTokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&returned)),
	)
	if ok == 0 {
		return false, err
	}
	return elevation != 0, nil
}

func initializeRuntimePatch() (uintptr, error) {
	for _, proc := range []*syscall.LazyProc{
		rtProcEnumWindows, rtProcIsWindowVisible, rtProcGetWindowThreadProcess,
		rtProcGetForegroundWindow, rtProcGetCursorInfo, rtProcLoadCursorW,
		rtProcOpenProcess, rtProcCloseHandle, rtProcQueryFullProcessName,
		rtProcCreateSnapshot, rtProcModule32First, rtProcModule32Next,
		rtProcReadProcessMemory, rtProcWriteProcessMemory, rtProcVirtualProtectEx,
		rtProcVirtualAllocEx, rtProcFlushInstructionCache, rtProcGetExitCodeProcess,
	} {
		if err := proc.Find(); err != nil {
			return 0, fmt.Errorf(tr("缺少所需的 Windows 接口: %w", "A required Windows API is unavailable: %w"), err)
		}
	}
	arrow, _, callErr := rtProcLoadCursorW.Call(0, rtIDCArrow)
	if arrow == 0 {
		return 0, fmt.Errorf(tr("无法载入 Windows 系统箭头: %v", "Could not load the Windows system arrow: %v"), callErr)
	}
	return arrow, nil
}

func openProcessSession(targetExe string, pid uint32, systemCursor uintptr) (*processSession, error) {
	gameAssemblyPath := filepath.Join(filepath.Dir(targetExe), "GameAssembly.dll")
	layout, err := locateRuntimeLayout(gameAssemblyPath)
	if err != nil {
		return nil, err
	}
	base, _, err := findRuntimeModule(pid, "GameAssembly.dll")
	if err != nil {
		return nil, fmt.Errorf(tr("游戏仍在初始化：%w", "The game is still initializing: %w"), err)
	}
	process, _, openErr := rtProcOpenProcess.Call(
		rtProcessVMOperation|rtProcessVMRead|rtProcessVMWrite|rtProcessQueryInformation,
		0,
		uintptr(pid),
	)
	if process == 0 {
		return nil, fmt.Errorf(tr("无法访问游戏进程，请允许管理员权限：%v", "Could not access the game process; allow administrator privileges: %v"), openErr)
	}
	return &processSession{
		process:      process,
		gameAssembly: base,
		layout:       layout,
		systemCursor: systemCursor,
	}, nil
}

func applyCursorOnce(targetExe string) (bool, error) {
	systemCursor, err := initializeRuntimePatch()
	if err != nil {
		return false, err
	}
	hwnd, pid, err := findTargetWindow(filepath.Clean(targetExe))
	if err != nil {
		return false, err
	}
	if hwnd == 0 {
		return false, errors.New(tr("未找到运行中的游戏窗口，请先启动游戏", "No running game window was found. Start the game first"))
	}
	session, err := openProcessSession(targetExe, pid, systemCursor)
	if err != nil {
		return false, err
	}
	defer session.close()
	if err := session.applyPersistentPatches(); err != nil {
		return false, err
	}
	if err := session.invokeOnTick(true); err != nil {
		return false, errors.Join(err, session.restorePersistentPatches())
	}
	if err := session.verifyPersistentPatches(); err != nil {
		restoreErr := session.restoreCursor()
		return false, errors.Join(err, restoreErr)
	}
	foreground, _, _ := rtProcGetForegroundWindow.Call()
	return foreground == hwnd && session.systemCursorActive(), nil
}

func restoreCursorOnce(targetExe string) (bool, error) {
	systemCursor, err := initializeRuntimePatch()
	if err != nil {
		return false, err
	}
	hwnd, pid, err := findTargetWindow(filepath.Clean(targetExe))
	if err != nil {
		return false, err
	}
	if hwnd == 0 {
		return false, errors.New(tr("未找到运行中的游戏窗口，请先启动游戏", "No running game window was found. Start the game first"))
	}
	session, err := openProcessSession(targetExe, pid, systemCursor)
	if err != nil {
		return false, err
	}
	defer session.close()
	patched, err := session.capturePersistentPatches()
	if err != nil {
		return false, err
	}
	if !patched {
		return false, nil
	}
	if err := session.restoreCursor(); err != nil {
		return false, err
	}
	return true, nil
}

func (session *processSession) restoreCursor() error {
	if !session.alive() {
		return nil
	}
	if err := session.restorePersistentPatches(); err != nil {
		return fmt.Errorf(tr("恢复游戏运行时代码失败：%w", "Failed to restore the game's runtime code: %w"), err)
	}
	if err := session.invokeOnTick(false); err != nil {
		return fmt.Errorf(tr("恢复游戏指针显示失败；重启游戏即可完全还原：%w", "Failed to restore the game cursor display; restarting the game will fully restore it: %w"), err)
	}
	return nil
}

func (session *processSession) preparePersistentPatches() error {
	callAddress := session.gameAssembly + uintptr(session.layout.refreshSequenceRVA) + 30
	setCursorAddress := session.gameAssembly + uintptr(session.layout.setCursorRVA)
	relative := int64(setCursorAddress) - int64(callAddress+5)
	if relative < math.MinInt32 || relative > math.MaxInt32 {
		return errors.New(tr("系统指针调用超出可补丁范围", "The system cursor call is outside the patchable range"))
	}
	patchedCall := []byte{0xe8, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(patchedCall[1:], uint32(int32(relative)))
	session.patches = []runtimePatch{
		{
			address:  session.gameAssembly + uintptr(session.layout.switchPatchRVA),
			original: cloneBytes(session.layout.switchPatchOriginal),
			patched:  []byte{0x31, 0xdb, 0x90},
		},
		{
			address:  session.gameAssembly + uintptr(session.layout.refreshSequenceRVA),
			original: cloneBytes(session.layout.refreshOriginalA),
			patched:  []byte{0x31, 0xc9, 0x90},
		},
		{
			address:  session.gameAssembly + uintptr(session.layout.refreshSequenceRVA) + 20,
			original: cloneBytes(session.layout.refreshOriginalB),
			patched:  []byte{0x45, 0x31, 0xc0, 0x90, 0x90},
		},
		{
			address:  callAddress,
			original: cloneBytes(session.layout.refreshOriginalCall),
			patched:  patchedCall,
		},
	}
	return nil
}

func (session *processSession) applyPersistentPatches() error {
	if err := session.preparePersistentPatches(); err != nil {
		return err
	}
	for index := range session.patches {
		patch := &session.patches[index]
		current, err := readRuntimeBytes(session.process, patch.address, len(patch.original))
		if err != nil {
			_ = session.restorePersistentPatches()
			return err
		}
		switch {
		case bytes.Equal(current, patch.patched):
			patch.applied = true
		case bytes.Equal(current, patch.original):
			if err := writeRuntimeMemory(session.process, patch.address, patch.patched, true); err != nil {
				_ = session.restorePersistentPatches()
				return err
			}
			patch.applied = true
		default:
			_ = session.restorePersistentPatches()
			return fmt.Errorf(tr("游戏运行时代码与已识别版本不一致：%#x (%s)", "The game runtime code differs from the recognized version: %#x (%s)"), patch.address-session.gameAssembly, hex.EncodeToString(current))
		}
	}
	return nil
}

func (session *processSession) capturePersistentPatches() (bool, error) {
	if err := session.preparePersistentPatches(); err != nil {
		return false, err
	}
	patched := false
	for index := range session.patches {
		patch := &session.patches[index]
		current, err := readRuntimeBytes(session.process, patch.address, len(patch.original))
		if err != nil {
			return false, err
		}
		switch {
		case bytes.Equal(current, patch.patched):
			patch.applied = true
			patched = true
		case bytes.Equal(current, patch.original):
			patch.applied = false
		default:
			return false, fmt.Errorf(tr("游戏运行时代码与已识别版本不一致：%#x (%s)", "The game runtime code differs from the recognized version: %#x (%s)"), patch.address-session.gameAssembly, hex.EncodeToString(current))
		}
	}
	return patched, nil
}

func (session *processSession) restorePersistentPatches() error {
	var restoreErr error
	for index := len(session.patches) - 1; index >= 0; index-- {
		patch := &session.patches[index]
		if !patch.applied {
			continue
		}
		current, err := readRuntimeBytes(session.process, patch.address, len(patch.patched))
		if err != nil {
			restoreErr = errors.Join(restoreErr, err)
			continue
		}
		if bytes.Equal(current, patch.original) {
			patch.applied = false
			continue
		}
		if !bytes.Equal(current, patch.patched) {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("unexpected bytes at %#x: %s", patch.address-session.gameAssembly, hex.EncodeToString(current)))
			continue
		}
		if err := writeRuntimeMemory(session.process, patch.address, patch.original, true); err != nil {
			restoreErr = errors.Join(restoreErr, err)
			continue
		}
		patch.applied = false
	}
	return restoreErr
}

func (session *processSession) verifyPersistentPatches() error {
	for _, patch := range session.patches {
		current, err := readRuntimeBytes(session.process, patch.address, len(patch.patched))
		if err != nil {
			return err
		}
		if !bytes.Equal(current, patch.patched) {
			return fmt.Errorf(tr("运行时补丁被覆盖：%#x", "A runtime patch was overwritten: %#x"), patch.address-session.gameAssembly)
		}
	}
	return nil
}

func (session *processSession) systemCursorActive() bool {
	var info rtCursorInfo
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, _ := rtProcGetCursorInfo.Call(uintptr(unsafe.Pointer(&info)))
	return ok != 0 && info.Flags&rtCursorShowing != 0 && uintptr(info.Cursor) == session.systemCursor
}

func (session *processSession) invokeOnTick(systemMode bool) (returnErr error) {
	entry := session.gameAssembly + uintptr(session.layout.onTickRVA)
	current, err := readRuntimeBytes(session.process, entry, len(session.layout.onTickEntry))
	if err != nil {
		return err
	}
	if !bytes.Equal(current, session.layout.onTickEntry) {
		return fmt.Errorf(tr("无法安全进入鼠标管理主线程：%s", "Could not safely enter the mouse manager's main thread: %s"), hex.EncodeToString(current))
	}
	cave, _, allocErr := rtProcVirtualAllocEx.Call(session.process, 0, 4096, rtMemCommit|rtMemReserve, rtPageExecuteReadWrite)
	if cave == 0 {
		return fmt.Errorf("VirtualAllocEx: %w", allocErr)
	}
	state := cave + 0x300
	trampoline := buildOnTickTrampoline(
		systemMode,
		session.gameAssembly+uintptr(session.layout.switchStateRVA),
		session.gameAssembly+uintptr(session.layout.setCursorRVA),
		session.gameAssembly+uintptr(session.layout.refreshRVA),
		session.gameAssembly+uintptr(session.layout.onTickInitFlagRVA),
		entry,
		entry+uintptr(len(session.layout.onTickEntry)),
		state,
		session.layout.onTickEntry,
	)
	if err := writeRuntimeMemory(session.process, cave, trampoline, false); err != nil {
		return err
	}
	hook := make([]byte, len(session.layout.onTickEntry))
	hook[0], hook[1] = 0x48, 0xb8
	binary.LittleEndian.PutUint64(hook[2:10], uint64(cave))
	hook[10], hook[11] = 0xff, 0xe0
	for index := 12; index < len(hook); index++ {
		hook[index] = 0x90
	}
	var oldProtect uint32
	ok, _, protectErr := rtProcVirtualProtectEx.Call(session.process, entry, uintptr(len(hook)), rtPageExecuteReadWrite, uintptr(unsafe.Pointer(&oldProtect)))
	if ok == 0 {
		return fmt.Errorf("VirtualProtectEx: %w", protectErr)
	}
	protectionRestored := false
	hookInstalled := false
	defer func() {
		if hookInstalled {
			if err := writeRuntimeMemory(session.process, entry, session.layout.onTickEntry, false); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("critical OnTick restore failure: %w", err))
			}
		}
		if !protectionRestored {
			var ignored uint32
			if restored, _, restoreErr := rtProcVirtualProtectEx.Call(session.process, entry, uintptr(len(hook)), uintptr(oldProtect), uintptr(unsafe.Pointer(&ignored))); restored == 0 {
				returnErr = errors.Join(returnErr, fmt.Errorf("VirtualProtectEx restore: %w", restoreErr))
			}
		}
	}()
	hookInstalled = true
	if err := writeRuntimeMemory(session.process, entry, hook, false); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	executed := false
	for time.Now().Before(deadline) {
		stateBytes, readErr := readRuntimeBytes(session.process, state, 8)
		if readErr != nil {
			return readErr
		}
		if binary.LittleEndian.Uint32(stateBytes[0:4]) != 0 && binary.LittleEndian.Uint32(stateBytes[4:8]) == 0 {
			executed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rtProcFlushInstructionCache.Call(session.process, entry, uintptr(len(session.layout.onTickEntry)))
	verified, verifyErr := readRuntimeBytes(session.process, entry, len(session.layout.onTickEntry))
	if verifyErr != nil {
		return verifyErr
	}
	if !bytes.Equal(verified, session.layout.onTickEntry) {
		if restoreErr := writeRuntimeMemory(session.process, entry, session.layout.onTickEntry, false); restoreErr != nil {
			return fmt.Errorf("critical OnTick restore failure: %w", restoreErr)
		}
		hookInstalled = false
		return errors.New(tr("鼠标管理主线程未及时响应", "The mouse manager's main thread did not respond in time"))
	}
	hookInstalled = false
	var ignored uint32
	ok, _, protectErr = rtProcVirtualProtectEx.Call(session.process, entry, uintptr(len(hook)), uintptr(oldProtect), uintptr(unsafe.Pointer(&ignored)))
	if ok == 0 {
		return fmt.Errorf("VirtualProtectEx restore: %w", protectErr)
	}
	protectionRestored = true
	if !executed {
		return errors.New(tr("等待游戏鼠标管理器超时", "Timed out waiting for the game's mouse manager"))
	}
	return nil
}

func buildOnTickTrampoline(systemMode bool, switchState, setCursor, refresh, initFlag, entry, resume, state uintptr, original []byte) []byte {
	code := []byte{
		0x48, 0x83, 0xec, 0x38,
		0x48, 0x89, 0x4c, 0x24, 0x30,
		0x48, 0x89, 0x54, 0x24, 0x28,
		0x48, 0xb8,
	}
	code = binary.LittleEndian.AppendUint64(code, uint64(state))
	code = append(code,
		0x83, 0x38, 0x00,
		0x0f, 0x85,
	)
	skipRel := len(code)
	code = append(code, 0, 0, 0, 0)
	code = append(code,
		0xff, 0x00,
		0xc7, 0x40, 0x04, 0x01, 0, 0, 0,
		0x48, 0x8b, 0x4c, 0x24, 0x30,
	)
	if systemMode {
		code = append(code, 0x31, 0xd2)
	} else {
		code = append(code, 0xba, 0x01, 0, 0, 0)
	}
	code = append(code, 0x45, 0x31, 0xc0, 0x48, 0xb8)
	code = binary.LittleEndian.AppendUint64(code, uint64(switchState))
	code = append(code, 0xff, 0xd0)
	if systemMode {
		code = append(code, 0x31, 0xc9, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, uint64(setCursor))
		code = append(code, 0xff, 0xd0)
	} else {
		code = append(code, 0x31, 0xc9, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, uint64(refresh))
		code = append(code, 0xff, 0xd0)
	}
	code = append(code, 0x48, 0xb8)
	code = binary.LittleEndian.AppendUint64(code, uint64(entry))
	code = append(code, 0x48, 0xba)
	code = binary.LittleEndian.AppendUint64(code, binary.LittleEndian.Uint64(original[0:8]))
	code = append(code, 0x48, 0x89, 0x10, 0x48, 0xba)
	code = binary.LittleEndian.AppendUint64(code, binary.LittleEndian.Uint64(original[8:16]))
	code = append(code,
		0x48, 0x89, 0x50, 0x08,
		0x48, 0xb8,
	)
	code = binary.LittleEndian.AppendUint64(code, uint64(state))
	code = append(code, 0xc7, 0x40, 0x04, 0, 0, 0, 0)
	skip := len(code)
	binary.LittleEndian.PutUint32(code[skipRel:skipRel+4], uint32(int32(skip-(skipRel+4))))
	code = append(code,
		0x48, 0x8b, 0x4c, 0x24, 0x30,
		0x48, 0x8b, 0x54, 0x24, 0x28,
		0x48, 0x83, 0xc4, 0x38,
		0x40, 0x53,
		0x48, 0x83, 0xec, 0x50,
		0x48, 0xb8,
	)
	code = binary.LittleEndian.AppendUint64(code, uint64(initFlag))
	code = append(code, 0x80, 0x38, 0x00, 0x48, 0x8b, 0xd9, 0x48, 0xb8)
	code = binary.LittleEndian.AppendUint64(code, uint64(resume))
	code = append(code, 0xff, 0xe0)
	return code
}

func locateRuntimeLayout(path string) (runtimeLayout, error) {
	file, err := pe.Open(path)
	if err != nil {
		return runtimeLayout{}, err
	}
	defer file.Close()
	var section *pe.Section
	for _, candidate := range file.Sections {
		if strings.EqualFold(strings.TrimRight(candidate.Name, "\x00"), "il2cpp") {
			section = candidate
			break
		}
	}
	if section == nil {
		return runtimeLayout{}, errors.New(tr("GameAssembly.dll 缺少 IL2CPP 代码段", "GameAssembly.dll has no IL2CPP code section"))
	}
	data, err := section.Data()
	if err != nil {
		return runtimeLayout{}, err
	}
	baseRVA := section.VirtualAddress
	onTickMatches := findMaskedOffsets(data, mustPattern("40 53 48 83 EC 50 80 3D ?? ?? ?? ?? 00 48 8B D9 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 48 8B 05 ?? ?? ?? ?? 48 8B 88 B8 00 00 00 48 8B 49 40"))
	switchMatches := findMaskedOffsets(data, mustPattern("48 89 5C 24 08 57 48 83 EC 20 80 3D ?? ?? ?? ?? 00 0F B6 DA 48 8B F9 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 48 8B 05 ?? ?? ?? ?? 4C 8B 80 B8 00 00 00 49 8B 88 80 00 00 00"))
	onTickOffset := -1
	switchOffset := -1
	for _, onTickCandidate := range onTickMatches {
		for _, switchCandidate := range switchMatches {
			if onTickCandidate < switchCandidate && switchCandidate-onTickCandidate < 0x3000 {
				if onTickOffset >= 0 {
					return runtimeLayout{}, errors.New(tr("无法唯一识别 PCMouseMgr 鼠标管理逻辑", "Could not uniquely identify the PCMouseMgr cursor logic"))
				}
				onTickOffset = onTickCandidate
				switchOffset = switchCandidate
			}
		}
	}
	if onTickOffset < 0 {
		return runtimeLayout{}, errors.New(tr("当前游戏版本中未识别到 PCMouseMgr 鼠标管理逻辑", "The PCMouseMgr cursor logic was not recognized in the current game version"))
	}
	refreshOffset, err := findUniqueMasked(data, mustPattern("48 83 EC 78 80 3D ?? ?? ?? ?? 00 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 33 C9 E8 ?? ?? ?? ?? 84 C0"), "PCCursorHelper.RefreshCursor")
	if err != nil {
		return runtimeLayout{}, err
	}
	refreshSequenceOffset, err := findUniqueMasked(data, mustPattern("48 8B CE 66 0F 6E C8 0F 5B C9 0F 14 F1 41 0F 28 C8 0F 14 CF 66 49 0F 7E F0 66 48 0F 7E CA E8 ?? ?? ?? ?? 0F 28 74 24 60"), "PCCursorHelper cursor call")
	if err != nil {
		return runtimeLayout{}, err
	}
	setCursorMatches := findMaskedOffsets(data, mustPattern("48 89 5C 24 08 57 48 83 EC 30 48 8B 05 ?? ?? ?? ?? 41 8B D8 48 89 54 24 20 48 8B F9 48 85 C0 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 44 8B C3 48 8D 54 24 20 48 8B CF FF D0 48 8B 5C 24 40 48 83 C4 30 5F C3"))
	withSizeCallRVA := baseRVA + uint32(refreshSequenceOffset) + 30
	withSizeDisplacement := int32(binary.LittleEndian.Uint32(data[refreshSequenceOffset+31 : refreshSequenceOffset+35]))
	withSizeRVA64 := int64(withSizeCallRVA) + 5 + int64(withSizeDisplacement)
	setCursorOffset := -1
	for _, candidate := range setCursorMatches {
		candidateRVA := int64(baseRVA) + int64(candidate)
		if candidateRVA > withSizeRVA64 && candidateRVA-withSizeRVA64 < 0x400 {
			if setCursorOffset >= 0 {
				return runtimeLayout{}, errors.New(tr("无法唯一识别 UnityEngine.Cursor.SetCursor", "Could not uniquely identify UnityEngine.Cursor.SetCursor"))
			}
			setCursorOffset = candidate
		}
	}
	if setCursorOffset < 0 {
		return runtimeLayout{}, errors.New(tr("当前游戏版本中未识别到 UnityEngine.Cursor.SetCursor", "UnityEngine.Cursor.SetCursor was not recognized in the current game version"))
	}
	onTickRVA := baseRVA + uint32(onTickOffset)
	onTickEntry := cloneBytes(data[onTickOffset : onTickOffset+16])
	displacement := int32(binary.LittleEndian.Uint32(onTickEntry[8:12]))
	initFlag64 := int64(onTickRVA) + 13 + int64(displacement)
	if initFlag64 < 0 || initFlag64 > math.MaxUint32 {
		return runtimeLayout{}, errors.New("invalid PCMouseMgr.OnTick initialization flag")
	}
	sequenceRVA := baseRVA + uint32(refreshSequenceOffset)
	return runtimeLayout{
		onTickRVA:           onTickRVA,
		onTickEntry:         onTickEntry,
		onTickInitFlagRVA:   uint32(initFlag64),
		switchStateRVA:      baseRVA + uint32(switchOffset),
		switchPatchRVA:      baseRVA + uint32(switchOffset) + 17,
		switchPatchOriginal: cloneBytes(data[switchOffset+17 : switchOffset+20]),
		refreshRVA:          baseRVA + uint32(refreshOffset),
		refreshSequenceRVA:  sequenceRVA,
		refreshOriginalA:    cloneBytes(data[refreshSequenceOffset : refreshSequenceOffset+3]),
		refreshOriginalB:    cloneBytes(data[refreshSequenceOffset+20 : refreshSequenceOffset+25]),
		refreshOriginalCall: cloneBytes(data[refreshSequenceOffset+30 : refreshSequenceOffset+35]),
		setCursorRVA:        baseRVA + uint32(setCursorOffset),
	}, nil
}

func mustPattern(value string) maskedPattern {
	fields := strings.Fields(value)
	pattern := maskedPattern{bytes: make([]byte, len(fields)), mask: make([]bool, len(fields))}
	for index, field := range fields {
		if field == "??" {
			continue
		}
		decoded, err := hex.DecodeString(field)
		if err != nil || len(decoded) != 1 {
			panic("invalid byte pattern: " + field)
		}
		pattern.bytes[index] = decoded[0]
		pattern.mask[index] = true
	}
	return pattern
}

func findUniqueMasked(data []byte, pattern maskedPattern, name string) (int, error) {
	matches := findMaskedOffsets(data, pattern)
	if len(matches) > 1 {
		return 0, fmt.Errorf(tr("无法唯一识别 %s", "Could not uniquely identify %s"), name)
	}
	if len(matches) == 0 {
		return 0, fmt.Errorf(tr("当前游戏版本中未识别到 %s", "%s was not recognized in the current game version"), name)
	}
	return matches[0], nil
}

func findMaskedOffsets(data []byte, pattern maskedPattern) []int {
	result := make([]int, 0, 1)
	for offset := 0; offset+len(pattern.bytes) <= len(data); offset++ {
		match := true
		for index := range pattern.bytes {
			if pattern.mask[index] && data[offset+index] != pattern.bytes[index] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		result = append(result, offset)
	}
	return result
}

func findTargetWindow(targetExe string) (uintptr, uint32, error) {
	var foundHWND uintptr
	var foundPID uint32
	callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		visible, _, _ := rtProcIsWindowVisible.Call(hwnd)
		if visible == 0 {
			return 1
		}
		var pid uint32
		rtProcGetWindowThreadProcess.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != 0 && strings.EqualFold(runtimeProcessPath(pid), targetExe) {
			foundHWND, foundPID = hwnd, pid
			return 0
		}
		return 1
	})
	result, _, callErr := rtProcEnumWindows.Call(callback, 0)
	if result == 0 && foundHWND == 0 && callErr != syscall.Errno(0) {
		return 0, 0, callErr
	}
	return foundHWND, foundPID, nil
}

func runtimeProcessPath(pid uint32) string {
	process, _, _ := rtProcOpenProcess.Call(rtProcessQueryLimitedInformation, 0, uintptr(pid))
	if process == 0 {
		return ""
	}
	defer rtProcCloseHandle.Call(process)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	ok, _, _ := rtProcQueryFullProcessName.Call(process, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 {
		return ""
	}
	return filepath.Clean(syscall.UTF16ToString(buffer[:size]))
}

func findRuntimeModule(pid uint32, name string) (uintptr, uint32, error) {
	snapshot, _, snapErr := rtProcCreateSnapshot.Call(rtTH32CSSnapModule|rtTH32CSSnapModule32, uintptr(pid))
	if snapshot == rtInvalidHandleValue {
		return 0, 0, snapErr
	}
	defer rtProcCloseHandle.Call(snapshot)
	entry := rtModuleEntry32{Size: uint32(unsafe.Sizeof(rtModuleEntry32{}))}
	ok, _, firstErr := rtProcModule32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ok == 0 {
		return 0, 0, firstErr
	}
	for {
		if strings.EqualFold(syscall.UTF16ToString(entry.Module[:]), name) {
			return entry.BaseAddress, entry.BaseSize, nil
		}
		entry.Size = uint32(unsafe.Sizeof(rtModuleEntry32{}))
		ok, _, _ = rtProcModule32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ok == 0 {
			break
		}
	}
	return 0, 0, fmt.Errorf("module not found: %s", name)
}

func (session *processSession) alive() bool {
	if session.process == 0 {
		return false
	}
	var exitCode uint32
	ok, _, _ := rtProcGetExitCodeProcess.Call(session.process, uintptr(unsafe.Pointer(&exitCode)))
	return ok != 0 && exitCode == rtStillActive
}

func (session *processSession) close() {
	if session.process != 0 {
		rtProcCloseHandle.Call(session.process)
		session.process = 0
	}
}

func readRuntimeBytes(process, address uintptr, size int) ([]byte, error) {
	buffer := make([]byte, size)
	var read uintptr
	ok, _, callErr := rtProcReadProcessMemory.Call(process, address, uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&read)))
	if ok == 0 || read != uintptr(size) {
		return nil, fmt.Errorf("ReadProcessMemory %#x read=%d: %w", address, read, callErr)
	}
	return buffer, nil
}

func writeRuntimeMemory(process, address uintptr, data []byte, protect bool) error {
	var oldProtect uint32
	if protect {
		ok, _, callErr := rtProcVirtualProtectEx.Call(process, address, uintptr(len(data)), rtPageExecuteReadWrite, uintptr(unsafe.Pointer(&oldProtect)))
		if ok == 0 {
			return fmt.Errorf("VirtualProtectEx %#x: %w", address, callErr)
		}
	}
	var written uintptr
	ok, _, callErr := rtProcWriteProcessMemory.Call(process, address, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written)))
	var resultErr error
	if ok == 0 || written != uintptr(len(data)) {
		resultErr = fmt.Errorf("WriteProcessMemory %#x wrote=%d: %w", address, written, callErr)
	}
	if protect {
		var ignored uint32
		if restored, _, restoreErr := rtProcVirtualProtectEx.Call(process, address, uintptr(len(data)), uintptr(oldProtect), uintptr(unsafe.Pointer(&ignored))); restored == 0 {
			resultErr = errors.Join(resultErr, fmt.Errorf("VirtualProtectEx restore %#x: %w", address, restoreErr))
		}
	}
	if flushed, _, flushErr := rtProcFlushInstructionCache.Call(process, address, uintptr(len(data))); flushed == 0 {
		resultErr = errors.Join(resultErr, fmt.Errorf("FlushInstructionCache %#x: %w", address, flushErr))
	}
	return resultErr
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
