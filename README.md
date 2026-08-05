# Python-System-Utility-Toolkit
A Python-based application that provides system administration tools such as website blocking via the hosts file, silent software installation, and automation scripts for system configuration. The project is designed to simplify common system configuration and management tasks through a single, easy-to-use interface.

## Quick Start (new workstation)

Open an **elevated** (Run as administrator) Command Prompt on the target PC and paste one line:

```cmd
curl -o "%TEMP%\bootstrap.bat" https://raw.githubusercontent.com/eazyboytt/Python-System-Utility-Toolkit/main/bootstrap.bat && call "%TEMP%\bootstrap.bat"
```

This will:
1. Install Git automatically via `winget` if it isn't already present
2. Clone (or update) this repo to `%USERPROFILE%\Python-System-Utility-Toolkit`
3. Install Python automatically via `winget` if it isn't already present
4. Launch `master_gui.py`

No pre-existing dev tools required on the target PC — Windows 10 1809+/Windows 11 ship `curl` and
`winget` by default.

If you already have the repo cloned locally, just run `install_and_run.bat` from inside it.

## Installer storage with GitHub Releases

Previously, **Install Software** only searched for seven hard-coded files in an `installers` folder on a detected USB flash drive. The toolkit now downloads those assets from the GitHub Release tag configured in `installers.json`, caches them under `%LOCALAPPDATA%\SystemUtilityToolkit\installers`, and verifies every file against the release's `SHA256SUMS` asset before running it. A missing or invalid checksum stops installation.

### Publish the installer bundle

1. Install and sign in to the [GitHub CLI](https://cli.github.com/): `gh auth login`.
2. Put the seven files below in a folder outside the repository. Keep these exact names:
   `obs.exe`, `anydesk.exe`, `teamlogger.msi`, `zoom.exe`, `teams.exe`, `winrar.exe`, and `jabra.exe`.
3. From the repository root, run:

   ```powershell
   .\scripts\publish_installers.ps1 -Tag installers-v1 -AssetDirectory C:\path\to\installer-assets
   ```

4. Open the draft release on GitHub, confirm that you have permission to redistribute each vendor installer, and publish it. The **Validate installer release** workflow checks filenames and hashes after publication.
5. If you use a different tag or fork, update `release_tag` or `repository` in `installers.json`. Rebuild `dist\master_gui.exe` after catalog changes because PyInstaller embeds that file.

Do not commit third-party installer binaries to this repository. GitHub's file limit and each vendor's redistribution terms still apply. For a private repository, this implementation needs authentication support; its direct release downloads are intended for a public repository.
