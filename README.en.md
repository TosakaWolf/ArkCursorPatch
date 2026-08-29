[简体中文](README.md)

# Arknights Cursor Patch

Uses the Windows system cursor in Arknights PC without modifying game files.

## Use

1. Run `ArkCursorPatch.exe`.
2. Select **Start system cursor mode** and keep the tool running.
3. Launch the game normally. It also works when the game is already running.

If automatic detection fails, set the game directory in the tool.

## Safety

- The tool requests administrator privileges, disables the game's drawn cursor at runtime, and selects the Windows system arrow.
- It does not modify game files or inject a DLL. Changes exist only in the running game process and are restored when the mode stops; restarting the game also clears them.
- After a game update, the tool refuses to modify anything unless it can identify every target uniquely.

## Notice

> This tool is provided only for communication and learning. Assess and accept the risks of modifying a game process before use.
