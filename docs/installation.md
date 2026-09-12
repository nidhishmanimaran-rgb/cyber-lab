# Installation

## Requirements

- Windows 10/11 PC
- Python 3.11 or later on `PATH`
- Android Studio only when building or installing the Android app
- A trusted private LAN for phone access

## Install

From the project root, run:

```powershell
.\scripts\setup.ps1
```

The script creates `.venv`, installs `requirements.txt`, creates `.env` only when it does not already exist, generates a cryptographically secure local API token for that new file, initializes the SQLite schema additively, and runs an integrity check. Existing `.env` files and existing lab data are not overwritten.

Keep `.env` private. It is ignored by Git and contains the backend token.

## Start and verify

```powershell
.\scripts\start.ps1
.\scripts\health.ps1
```

Open `http://127.0.0.1:8001/` on the PC. For trusted-LAN use, follow [Windows setup](windows-setup.md).
