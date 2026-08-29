[简体中文](README.md)

# Arknights Cursor Patch

Disables the custom cursor image in Arknights PC and uses the current Windows system cursor. Tutorial click and drag indicators are not affected.

## Use

1. Fully close the game and Hypergryph Launcher.
2. Run `ArkCursorPatch.exe`.
3. Confirm the game directory and status shown on the dashboard, then select **Apply cursor replacement**.
4. Select **Restore original** to revert the change.

The tool finds the game automatically. If detection fails, set the game directory from the dashboard.

## Safety and recovery

- Content version `76.0.0` uses exact verification. Other versions use cursor-configuration detection; changes are allowed only when the match is unique and structurally complete.
- Back up `Arknights_Data\sharedassets0.assets` under the game root; the tool also saves it to `backup` before applying changes.
- The written file is verified, and automatic recovery is attempted if writing fails.
- The tool does not include complete game assets and does not start the game or launcher.

## Notice

> This tool is provided only for communication and learning. Back up your files first and accept the risks of modifying local game resources.
