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
import datetime  # For timestamps

# Constants for the API and defaults.
API_BASE_URL = "https://api.vrchat.cloud/api/1"
DEFAULT_GROUP_ID = "grp_7aa61881-550f-431e-a180-f99c77436124"
DEFAULT_POLL_INTERVAL = 60
USER_AGENT = "VRChatAutoJoinScript/1.0, contact: snoogle35@gmail.com"

class VRChatMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VRChat Auto Join Monitor")
        self.credentials_file = "saved_credentials.json"
        self.session_cookie_file = "vrchat_session.json"
        self.accepted_log_file = "accepted_log.txt"
        self.stop_event = threading.Event()
        self.monitor_thread = None
        self.tray_icon = None  # Will hold our pystray icon
        self.create_widgets()
        self.load_saved_credentials()
        # Set window icon. When bundled, adjust using __file__ and sys._MEIPASS.
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
        self.save_credentials_check.grid(row=4, column=1, sticky=tk.W)

        self.start_button = ttk.Button(frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=5, column=0, pady=10)

        self.stop_button = ttk.Button(frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=5, column=1, pady=10)

        self.minimize_button = ttk.Button(frame, text="Minimize to Tray", command=self.minimize_to_tray)
        self.minimize_button.grid(row=6, column=0, pady=10)

        self.text_log = tk.Text(self.root, height=15, width=80)
        self.text_log.grid(row=1, column=0, padx=10, pady=10)

    def log(self, message):
        # Thread-safe logging to the text widget.
        self.root.after(0, lambda: self.text_log.insert(tk.END, message + "\n"))
        self.root.after(0, lambda: self.text_log.see(tk.END))
        print(message)

    def log_to_file(self, message):
        """Append a log entry to the accepted log file with a timestamp."""
        try:
            with open(self.accepted_log_file, "a") as f:
                f.write(message + "\n")
        except Exception as e:
            self.log(f"Error writing to log file: {e}")

    def load_saved_credentials(self):
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, "r") as f:
                    creds = json.load(f)
                self.username_entry.insert(0, creds.get("username", ""))
                self.password_entry.insert(0, creds.get("password", ""))
                self.log("Loaded saved credentials.")
            except Exception as e:
                self.log(f"Failed to load saved credentials: {e}")

    def save_credentials(self):
        creds = {"username": self.username_entry.get(), "password": self.password_entry.get()}
        try:
            with open(self.credentials_file, "w") as f:
                json.dump(creds, f)
            self.log("Credentials saved.")
        except Exception as e:
            self.log(f"Failed to save credentials: {e}")

    def load_session_cookies(self, session):
        if os.path.exists(self.session_cookie_file):
            try:
                with open(self.session_cookie_file, "r") as f:
                    cookies_dict = json.load(f)
                session.cookies.update(cookies_dict)
                self.log("Session cookies loaded.")
            except Exception as e:
                self.log(f"Failed to load session cookies: {e}")

    def save_session_cookies(self, session):
        cookies_dict = session.cookies.get_dict()
        try:
            with open(self.session_cookie_file, "w") as f:
                json.dump(cookies_dict, f)
            self.log("Session cookies saved.")
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
        """Prompt for a 2FA code on the main thread and wait for the response."""
        result = {}
        event = threading.Event()
        def ask():
            result["code"] = simpledialog.askstring("Two-Factor Authentication", "Enter your 2FA code:")
            event.set()
        self.root.after(0, ask)
        event.wait()  # Block until the dialog is answered.
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
                    if "Requires Two-Factor Authentication" in error_json.get("error", {}).get("message", ""):
                        return "2FA_REQUIRED"
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
                # Write acceptance event to log file with a timestamp.
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_to_file(f"{timestamp}: Accepted join request for user {user_id}.")
            else:
                self.log(f"Failed to accept join request for user {user_id}. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log(f"Exception while accepting join request for user {user_id}: {e}")

    def is_user_verified(self, user):
        return user.get("ageVerificationStatus") == "18+" and user.get("ageVerified") is True

    def monitor_loop(self):
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        self.load_session_cookies(session)

        auth_check_url = f"{API_BASE_URL}/auth/user"
        try:
            auth_check_response = session.get(auth_check_url)
        except Exception as e:
            self.log(f"Error during auth check: {e}")
            return

        if auth_check_response.status_code != 200:
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
            self.save_session_cookies(session)
        else:
            self.log("Loaded valid session cookies.")

        group_id = self.group_entry.get()
        try:
            poll_interval = int(self.interval_entry.get())
        except:
            poll_interval = DEFAULT_POLL_INTERVAL

        self.log(f"Monitoring join requests for group {group_id} every {poll_interval} seconds...")

        while not self.stop_event.is_set():
            self.log("----- Starting new monitoring cycle -----")
            join_requests = self.get_group_join_requests(session, group_id)
            if join_requests == "2FA_REQUIRED":
                if not self.verify_two_factor_auth(session, self.username_entry.get(), self.password_entry.get()):
                    self.log("2FA failed. Exiting monitoring loop.")
                    break
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
                            self.log(f"User {display_name} ({user_id}) is NOT 18+ verified. Skipping join request.")
                else:
                    self.log("No join requests found at this time.")
            else:
                self.log("Error fetching join requests; will try again on next cycle.")
            self.log("----- Monitoring cycle complete; sleeping -----")
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
        # Hide the main window
        self.root.withdraw()
        # Create tray icon using the ICO file.
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
        # Run the tray icon in a separate thread
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
