# VRChat Group Request 18+ Verifier

VrcAgeVerify is a Python application that monitors VRChat group join requests and automatically accepts those from users who are 18+ verified. It features a Tkinter GUI with 2FA support, and a styled logging display that highlights timestamps.

## Features
- Monitors VRChat group join requests at a configurable interval.
- Automatically accepts requests if the user's profile shows:
  - `"ageVerificationStatus": "18+"`
  - `"ageVerified": true`
- Supports two-factor authentication (2FA).
- Provides a GUI for entering credentials, group ID, and polling interval.
- Minimizes to the system tray.
- Displays logs in the GUI with a green, bold timestamp for each entry.
- Logs accepted requests with timestamps to `accepted_log.txt`.
- Optionally forwards formatted log messages to a Discord webhook.

## Requirements
- Python 3.6+
- Tkinter (bundled with Python)
- requests
- pystray
- Pillow
- Keyring

## Usage

### Install dependencies:
```bash
pip install requests pystray pillow keyring
```

### Run the application:
```bash
python VrcAgeVerify.py
```

## Packaging
To package the application as a standalone executable with PyInstaller, run:
```bash
pyinstaller --onefile --windowed --icon=vrchat_monitor_icon.ico --add-data "vrchat_monitor_icon.ico;." VrcAgeVerify.py
```

## Notes
- The GUI log displays each message prepended with a green, bold timestamp.
- Certain log messages (such as accepted join requests or 2FA statuses) are formatted and sent to a Discord webhook.
- Credentials and session cookies are stored securely using Keyring.
