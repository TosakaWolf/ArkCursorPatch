[简体中文](README.md)

# Arknights Cursor Patch

Uses the Windows system cursor in Arknights PC without modifying game files.

## Use

1. Start Arknights.
2. Run `ArkCursorPatch.exe` and select **Apply system cursor and exit**.
3. The tool exits after applying. The running game continues to use the system cursor.

If automatic detection fails, set the game directory in the tool.

To remove it immediately, run the tool again and select **Restore the current game cursor**. Restarting the game also restores it.

## Safety

- The tool requests administrator privileges, patches the running game's cursor logic once, and selects the Windows system arrow.
- It does not modify game files or inject a DLL. The patch exists only in the running game process and disappears completely when the game restarts.
- After a game update, the tool refuses to modify anything unless it can identify every target uniquely.

## Notice

> This tool is provided only for communication and learning. Assess and accept the risks of modifying a game process before use.
