#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, PhotoImage
import threading
import requests
import time
import json
import os
import sys
import pystray
from PIL import Image
import datetime
from cryptography.fernet import Fernet

# Constants for the API and defaults.
API_BASE_URL = "https://api.vrchat.cloud/api/1"
DEFAULT_GROUP_ID = "grp_7aa61881-550f-431e-a180-f99c77436124"
DEFAULT_POLL_INTERVAL = 60
USER_AGENT = "VRChatAutoJoinScript/1.0, contact: snoogle35@gmail.com"

# File names for encrypted data.
CREDENTIALS_FILE = "saved_credentials.enc"
SESSION_COOKIE_FILE = "vrchat_session.enc"
KEY_FILE = "secret.key"

def load_key():
    """Load the encryption key from KEY_FILE or generate one if not found."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

# Load the encryption key and create the cipher.
ENCRYPTION_KEY = load_key()
CIPHER = Fernet(ENCRYPTION_KEY)

class VRChatMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VRChat Auto Join Monitor")
        self.credentials_file = CREDENTIALS_FILE
        self.session_cookie_file = SESSION_COOKIE_FILE
        self.accepted_log_file = "accepted_log.txt"
        self.stop_event = threading.Event()
        self.monitor_thread = None
        self.tray_icon = None  # For pystray
        self.create_widgets()
        self.load_saved_credentials()
        icon_path = self.get_resource_path("vrchat_monitor_icon.ico")
        try:
            self.root.iconbitmap(icon_path)
        except Exception as e:
            self.log(f"Error setting window icon: {e}")

    def get_resource_path(self, relative_path):
        """Get absolute path to resource, works for dev and for PyInstaller."""
        base_path = os.path.abspath(".")
        if hasattr(sys, "_MEIPASS"):
            base_path = sys._MEIPASS
        return os.path.join(base_path, relative_path)

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.W)

        ttk.Label(frame, text="Group ID:").grid(row=2, column=0, sticky=tk.W)
        self.group_entry = ttk.Entry(frame, width=30)
        self.group_entry.insert(0, DEFAULT_GROUP_ID)
        self.group_entry.grid(row=2, column=1, sticky=tk.W)

        ttk.Label(frame, text="Polling Interval (sec):").grid(row=3, column=0, sticky=tk.W)
        self.interval_entry = ttk.Entry(frame, width=30)
        self.interval_entry.insert(0, str(DEFAULT_POLL_INTERVAL))
        self.interval_entry.grid(row=3, column=1, sticky=tk.W)

        self.save_credentials_var = tk.BooleanVar()
        self.save_credentials_check = ttk.Checkbutton(frame, text="Save Credentials", variable=self.save_credentials_var)
        self.save_credentials_check.grid(row=4, column=0, sticky=tk.W)

        self.auto_deny_var = tk.BooleanVar()
        self.auto_deny_check = ttk.Checkbutton(frame, text="Auto Deny Unverified", variable=self.auto_deny_var)
        self.auto_deny_check.grid(row=4, column=1, sticky=tk.W)

        self.start_button = ttk.Button(frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=5, column=0, pady=10)

        self.stop_button = ttk.Button(frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=5, column=1, pady=10)

        self.minimize_button = ttk.Button(frame, text="Minimize to Tray", command=self.minimize_to_tray)
        self.minimize_button.grid(row=6, column=0, pady=10)

        # New Discord Webhook URL field
        ttk.Label(frame, text="Discord Webhook URL:").grid(row=7, column=0, sticky=tk.W)
        self.webhook_entry = ttk.Entry(frame, width=60)
        self.webhook_entry.grid(row=7, column=1, sticky=tk.W)

        self.text_log = tk.Text(self.root, height=15, width=80)
        self.text_log.grid(row=8, column=0, padx=10, pady=10, columnspan=2)

    def log(self, message):
        self.root.after(0, lambda: self.text_log.insert(tk.END, message + "\n"))
        self.root.after(0, lambda: self.text_log.see(tk.END))
        print(message)
        # If a Discord webhook URL is provided, send the log message.
        webhook_url = self.webhook_entry.get().strip()
        if webhook_url:
            threading.Thread(target=self.send_discord_log, args=(webhook_url, message), daemon=True).start()

    def send_discord_log(self, webhook, message):
        try:
            payload = {"content": message}
            response = requests.post(webhook, json=payload)
            if response.status_code not in (200, 204):
                self.root.after(0, lambda: self.text_log.insert(tk.END, f"Failed to send discord log: HTTP {response.status_code}\n"))
        except Exception as e:
            self.root.after(0, lambda: self.text_log.insert(tk.END, f"Exception sending discord log: {e}\n"))

    def log_to_file(self, message):
        try:
            with open(self.accepted_log_file, "a") as f:
                f.write(message + "\n")
        except Exception as e:
            self.log(f"Error writing to log file: {e}")

    def load_saved_credentials(self):
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = CIPHER.decrypt(encrypted_data)
                creds = json.loads(decrypted_data.decode("utf-8"))
                self.username_entry.insert(0, creds.get("username", ""))
                self.password_entry.insert(0, creds.get("password", ""))
                group = creds.get("group", DEFAULT_GROUP_ID)
                self.group_entry.delete(0, tk.END)
                self.group_entry.insert(0, group)
                webhook = creds.get("webhook", "")
                self.webhook_entry.delete(0, tk.END)
                self.webhook_entry.insert(0, webhook)
                self.log("Loaded saved credentials (encrypted).")
            except Exception as e:
                self.log(f"Failed to load saved credentials: {e}")

    def save_credentials(self):
        creds = {
            "username": self.username_entry.get(),
            "password": self.password_entry.get(),
            "group": self.group_entry.get(),
            "webhook": self.webhook_entry.get()
        }
        try:
            data = json.dumps(creds).encode("utf-8")
            encrypted_data = CIPHER.encrypt(data)
            with open(self.credentials_file, "wb") as f:
                f.write(encrypted_data)
            self.log("Credentials, group ID, and webhook URL saved (encrypted).")
        except Exception as e:
            self.log(f"Failed to save credentials: {e}")

    def load_session_cookies(self, session):
        if os.path.exists(self.session_cookie_file):
            try:
                with open(self.session_cookie_file, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = CIPHER.decrypt(encrypted_data)
                cookies_dict = json.loads(decrypted_data.decode("utf-8"))
                session.cookies.update(cookies_dict)
                self.log("Session cookies loaded (encrypted).")
            except Exception as e:
                self.log(f"Failed to load session cookies: {e}")

    def save_session_cookies(self, session):
        cookies_dict = session.cookies.get_dict()
        try:
            data = json.dumps(cookies_dict).encode("utf-8")
            encrypted_data = CIPHER.encrypt(data)
            with open(self.session_cookie_file, "wb") as f:
                f.write(encrypted_data)
            self.log("Session cookies saved (encrypted).")
        except Exception as e:
            self.log(f"Failed to save session cookies: {e}")

    def authenticate(self, session, username, password):
        url = f"{API_BASE_URL}/auth/user"
        try:
            response = session.get(url, auth=(username, password))
            if response.status_code == 200:
                self.log(f"Successfully authenticated as {username}.")
                return True
            else:
                self.log(f"Authentication failed. Status: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            self.log(f"Exception during authentication: {e}")
            return False

    def get_2fa_code(self):
        result = {}
        event = threading.Event()
        def ask():
            result["code"] = simpledialog.askstring("Two-Factor Authentication", "Enter your 2FA code:")
            event.set()
        self.root.after(0, ask)
        event.wait()
        return result.get("code")

    def verify_two_factor_auth(self, session, username, password):
        self.log("Two-factor authentication is required.")
        code = self.get_2fa_code()
        if not code:
            self.log("No 2FA code provided.")
            return False
        url = f"{API_BASE_URL}/auth/twofactorauth/totp/verify"
        payload = {"code": code}
        try:
            response = session.post(url, json=payload, auth=(username, password))
            if response.status_code == 200:
                self.log("Two-factor authentication successful.")
                return True
            else:
                self.log(f"2FA failed. Status: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            self.log(f"Exception during 2FA: {e}")
            return False

    def get_group_join_requests(self, session, group_id):
        url = f"{API_BASE_URL}/groups/{group_id}/requests"
        try:
            response = session.get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                try:
                    error_json = response.json()
                    msg = error_json.get("error", {}).get("message", "")
                    if "Requires Two-Factor Authentication" in msg:
                        return "2FA_REQUIRED"
                    if "Missing Credentials" in msg:
                        return "MISSING_CREDENTIALS"
                except Exception:
                    pass
                self.log(f"Failed to fetch join requests for group {group_id}. Status: {response.status_code}, Response: {response.text}")
                return None
            else:
                self.log(f"Failed to fetch join requests for group {group_id}. Status: {response.status_code}, Response: {response.text}")
                return None
        except Exception as e:
            self.log(f"Exception while fetching join requests: {e}")
            return None

    def fetch_user_profile(self, session, user_id):
        url = f"{API_BASE_URL}/users/{user_id}"
        try:
            response = session.get(url)
            if response.status_code == 200:
                return response.json()
            else:
                self.log(f"Failed to fetch user profile for {user_id}. Status: {response.status_code}, Response: {response.text}")
                return None
        except Exception as e:
            self.log(f"Exception while fetching user profile for {user_id}: {e}")
            return None

    def accept_join_request(self, session, group_id, user_id):
        url = f"{API_BASE_URL}/groups/{group_id}/requests/{user_id}"
        payload = {"action": "accept"}
        try:
            response = session.put(url, json=payload)
            if response.status_code in (200, 204):
                self.log(f"Successfully accepted join request for user {user_id}.")
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_to_file(f"{timestamp}: Accepted join request for user {user_id}.")
            else:
                self.log(f"Failed to accept join request for user {user_id}. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log(f"Exception while accepting join request for user {user_id}: {e}")

    def deny_join_request(self, session, group_id, user_id):
        url = f"{API_BASE_URL}/groups/{group_id}/requests/{user_id}"
        payload = {"action": "reject"}
        try:
            response = session.put(url, json=payload)
            if response.status_code in (200, 204):
                self.log(f"Automatically denied join request for user {user_id}.")
            else:
                self.log(f"Failed to deny join request for user {user_id}. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log(f"Exception while denying join request for user {user_id}: {e}")

    def is_user_verified(self, user):
        return user.get("ageVerificationStatus") == "18+" and user.get("ageVerified") is True

    def monitor_loop(self):
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        self.load_session_cookies(session)

        self.log("Performing auth check...")
        auth_check_url = f"{API_BASE_URL}/auth/user"
        try:
            auth_check_response = session.get(auth_check_url)
        except Exception as e:
            self.log(f"Error during auth check: {e}")
            return

        if auth_check_response.status_code != 200:
            self.log("Session cookies invalid. Attempting to authenticate...")
            username = self.username_entry.get()
            password = self.password_entry.get()
            if not self.authenticate(session, username, password):
                self.log("Authentication failed.")
                return
            join_requests = self.get_group_join_requests(session, self.group_entry.get())
            if join_requests == "2FA_REQUIRED":
                if not self.verify_two_factor_auth(session, username, password):
                    self.log("2FA failed.")
                    return
                join_requests = self.get_group_join_requests(session, self.group_entry.get())
            if join_requests == "MISSING_CREDENTIALS":
                self.log("Missing Credentials detected. Reauthenticating...")
                if not self.authenticate(session, username, password):
                    self.log("Reauthentication failed.")
                    return
                self.save_session_cookies(session)
                join_requests = self.get_group_join_requests(session, self.group_entry.get())
            self.save_session_cookies(session)
        else:
            self.log("Loaded valid session cookies (encrypted).")

        group_id = self.group_entry.get()
        try:
            poll_interval = int(self.interval_entry.get())
        except:
            poll_interval = DEFAULT_POLL_INTERVAL

        self.log(f"Monitoring join requests for group {group_id} every {poll_interval} seconds...")

        while not self.stop_event.is_set():
            join_requests = self.get_group_join_requests(session, group_id)
            if join_requests == "2FA_REQUIRED":
                if not self.verify_two_factor_auth(session, self.username_entry.get(), self.password_entry.get()):
                    self.log("2FA failed. Exiting monitoring loop.")
                    break
                join_requests = self.get_group_join_requests(session, group_id)
            if join_requests == "MISSING_CREDENTIALS":
                self.log("Missing Credentials detected during monitoring. Reauthenticating...")
                if not self.authenticate(session, self.username_entry.get(), self.password_entry.get()):
                    self.log("Reauthentication failed. Exiting monitoring loop.")
                    break
                self.save_session_cookies(session)
                join_requests = self.get_group_join_requests(session, group_id)
            if join_requests is not None and isinstance(join_requests, list):
                if join_requests:
                    self.log(f"Found {len(join_requests)} join request(s).")
                    for req in join_requests:
                        partial_user = req.get("user", {})
                        user_id = partial_user.get("id", "Unknown")
                        display_name = partial_user.get("displayName", "Unknown")
                        full_user = self.fetch_user_profile(session, user_id)
                        if not full_user:
                            self.log(f"Could not fetch full profile for user {display_name} ({user_id}). Skipping.")
                            continue
                        if self.is_user_verified(full_user):
                            self.log(f"User {display_name} ({user_id}) is 18+ verified. Accepting join request...")
                            self.accept_join_request(session, group_id, user_id)
                        else:
                            self.log(f"User {display_name} ({user_id}) is NOT 18+ verified.")
                            if self.auto_deny_var.get():
                                self.log("Auto Deny is enabled. Denying join request...")
                                self.deny_join_request(session, group_id, user_id)
                            else:
                                self.log("Skipping join request (Auto Deny not enabled).")
            else:
                self.log("Error fetching join requests; will try again on next cycle.")
            time.sleep(poll_interval)
        self.log("Monitoring stopped.")

    def start_monitoring(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_event.clear()
        if self.save_credentials_var.get():
            self.save_credentials()
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.stop_event.set()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("Stop signal sent.")

    def minimize_to_tray(self):
        self.log("Minimizing to system tray...")
        self.root.withdraw()
        image_path = self.get_resource_path("vrchat_monitor_icon.ico")
        try:
            image = Image.open(image_path)
        except Exception as e:
            self.log(f"Error loading tray icon image: {e}")
            return
        menu = pystray.Menu(
            pystray.MenuItem("Restore", self.restore_window),
            pystray.MenuItem("Exit", self.exit_app)
        )
        self.tray_icon = pystray.Icon("VRChatMonitor", image, "VRChat Auto Join Monitor", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def restore_window(self, icon, item):
        self.log("Restoring window from tray...")
        icon.stop()
        self.root.after(0, self.root.deiconify)

    def exit_app(self, icon, item):
        self.log("Exiting application from tray...")
        icon.stop()
        self.root.after(0, self.root.destroy)

if __name__ == "__main__":
    root = tk.Tk()
    app = VRChatMonitorApp(root)
    root.mainloop()
