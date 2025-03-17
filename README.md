# vrcageverify

VrcAgeVerify is a Python application that monitors VRChat group join requests and automatically accepts those from users who are 18+ verified. It features a Tkinter GUI with 2FA support and minimizes to the system tray.

## Features
- Monitors VRChat group join requests at a configurable interval.
- Automatically accepts requests if the user's profile shows:
  - `"ageVerificationStatus": "18+"`
  - `"ageVerified": true`
- Supports two-factor authentication (2FA).
- Provides a GUI for entering credentials, group ID, and polling interval.
- Minimizes to the system tray.
- Logs accepted requests with timestamps to `accepted_log.txt`.

## Requirements
- Python 3.6+
- Tkinter (bundled with Python)
- requests
- pystray
- Pillow
- Cryptography

## Usage

### Install dependencies:
```bash
pip install requests pystray pillow
```

### Run the application:
```bash
python VrcAgeVerify.py
```

## Packaging
To package the application as a standalone executable with PyInstaller, run:
```bash
pyinstaller --onefile --windowed --icon=vrchat_monitor_icon.ico --add-data "vrchat_monitor_icon.ico;." VrcAgeVerify.py
