import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
import hashlib
import os
import json
import base64

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Management Application")
        self.root.geometry("400x600")
        self.root.resizable(False, False)

        self.accounts_file = "accounts.json"
        self.users = self.load_accounts()
        self.current_user = None
        self.locked = True
        self.encryption_key = None
        self.is_dark_mode = False

        if not os.path.exists("key.key"):
            with open("key.key", "wb") as key_file:
                key_file.write(Fernet.generate_key())

        with open("key.key", "rb") as key_file:
            self.key = key_file.read()

        self.style = ttk.Style()
        self.set_theme(self.is_dark_mode)

        self.show_user_selection_screen()

    def set_theme(self, dark_mode):
        if dark_mode:
            self.root.configure(bg="#000000")
            self.style.theme_use("clam")
            self.style.configure("TLabel", background="#000000", foreground="#FFFFFF")
            self.style.configure("TButton", background="#333333", foreground="#FFFFFF")
            self.style.configure("TEntry", fieldbackground="#333333", foreground="#FFFFFF")
            self.style.map("TButton", background=[("active", "#444444")])
        else:
            self.root.configure(bg="#FFFFFF")
            self.style.theme_use("clam")
            self.style.configure("TLabel", background="#FFFFFF", foreground="#000000")
            self.style.configure("TButton", background="#DDDDDD", foreground="#000000")
            self.style.configure("TEntry", fieldbackground="#FFFFFF", foreground="#000000")
            self.style.map("TButton", background=[("active", "#CCCCCC")])

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.set_theme(self.is_dark_mode)

    def load_accounts(self):
        if os.path.exists(self.accounts_file):
            with open(self.accounts_file, "r") as file:
                return json.load(file)
        return {}

    def save_accounts(self):
        with open(self.accounts_file, "w") as file:
            json.dump(self.users, file, indent=4)

    def encrypt_password(self, plaintext_password):
        cipher_suite = Fernet(self.encryption_key)
        encrypted_password = cipher_suite.encrypt(plaintext_password.encode())
        return encrypted_password.decode()

    def decrypt_password(self, encrypted_password):
        cipher_suite = Fernet(self.encryption_key)
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
        return decrypted_password.decode()

    def show_user_selection_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.user_label = ttk.Label(self.root, text="Select User or Create Account", font=("Arial", 14, "bold"))
        self.user_label.pack(pady=(20, 10))

        self.user_listbox = tk.Listbox(self.root, height=5, selectmode=tk.SINGLE)
        self.user_listbox.pack(pady=10)
        for username in self.users:
            self.user_listbox.insert(tk.END, username)

        self.select_button = ttk.Button(self.root, text="Select User", command=self.select_user)
        self.select_button.pack(pady=5)

        self.create_button = ttk.Button(self.root, text="Create New Account", command=self.create_account)
        self.create_button.pack(pady=5)

        self.forgot_password_button = ttk.Button(self.root, text="Forgot Password", command=self.reset_password)
        self.forgot_password_button.pack(pady=5)

        self.theme_button = ttk.Button(self.root, text="Toggle Dark/Light Mode", command=self.toggle_theme)
        self.theme_button.pack(pady=10)

    def select_user(self):
        selected_user = self.user_listbox.get(tk.ACTIVE)
        if selected_user:
            self.current_user = selected_user
            self.show_login_screen()
        else:
            messagebox.showwarning("Warning", "Please select a user.")

    def create_account(self):
        if len(self.users) >= 3:
            messagebox.showerror("Error", "Maximum number of accounts reached.")
            return

        username = simpledialog.askstring("New Account", "Enter a username:")
        if not username or username in self.users:
            messagebox.showerror("Error", "Invalid or duplicate username.")
            return

        password = simpledialog.askstring("New Account", "Enter a master password:", show="*")
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        pin = simpledialog.askstring("New Account", "Enter a PIN code (4 digits):", show="*")
        if not pin or len(pin) != 4 or not pin.isdigit():
            messagebox.showerror("Error", "Invalid PIN.")
            return

        recovery_password = simpledialog.askstring("New Account", "Set a recovery password:", show="*")
        if not recovery_password:
            messagebox.showerror("Error", "Recovery password cannot be empty.")
            return

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        recovery_password_hash = hashlib.sha256(recovery_password.encode()).hexdigest()

        self.users[username] = {
            "password_hash": password_hash,
            "pin_hash": pin_hash,
            "recovery_password_hash": recovery_password_hash,
            "data": {}
        }
        self.save_accounts()
        messagebox.showinfo("Success", f"Account for {username} created successfully.")
        self.show_user_selection_screen()

    def reset_password(self):
        username = simpledialog.askstring("Reset Password", "Enter your username:")
        if username not in self.users:
            messagebox.showerror("Error", "Username not found.")
            return

        recovery_password = simpledialog.askstring("Reset Password", "Enter your recovery password:", show="*")
        recovery_password_hash = hashlib.sha256(recovery_password.encode()).hexdigest()

        if recovery_password_hash == self.users[username]["recovery_password_hash"]:
            choice = messagebox.askquestion("Reset Options", "Would you like to reset your PIN? Click 'Yes' for PIN or 'No' for Master Password.")
            if choice == 'yes':
                new_pin = simpledialog.askstring("Reset PIN", "Enter a new PIN code (4 digits):", show="*")
                if not new_pin or len(new_pin) != 4 or not new_pin.isdigit():
                    messagebox.showerror("Error", "Invalid PIN.")
                    return
                new_pin_hash = hashlib.sha256(new_pin.encode()).hexdigest()
                self.users[username]["pin_hash"] = new_pin_hash
                self.save_accounts()
                messagebox.showinfo("Success", "PIN reset successfully.")
            else:
                new_password = simpledialog.askstring("Reset Password", "Enter a new master password:", show="*")
                if not new_password:
                    messagebox.showerror("Error", "Password cannot be empty.")
                    return
                new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                self.users[username]["password_hash"] = new_password_hash
                self.save_accounts()
                messagebox.showinfo("Success", "Master password reset successfully.")
        else:
            messagebox.showerror("Error", "Invalid recovery password.")

    def show_login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.login_label = ttk.Label(self.root, text=f"Login - {self.current_user}", font=("Arial", 14, "bold"))
        self.login_label.pack(pady=(20, 10))

        self.password_label = ttk.Label(self.root, text="Master Password:")
        self.password_label.pack(pady=5)

        self.password_frame = ttk.Frame(self.root)
        self.password_frame.pack(pady=5)

        self.password_entry = ttk.Entry(self.password_frame, show="*", width=25)
        self.password_entry.grid(row=0, column=0, padx=5)

        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_checkbutton = ttk.Checkbutton(
            self.password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_checkbutton.grid(row=0, column=1)

        self.login_button = ttk.Button(self.root, text="Login", command=self.check_master_password)
        self.login_button.pack(pady=10)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def check_master_password(self):
        password = self.password_entry.get()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        if password_hash == self.users[self.current_user]["password_hash"]:
            self.encryption_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            messagebox.showinfo("Login Successful", "Welcome!")
            self.show_pin_screen()
        else:
            messagebox.showwarning("Login Failed", "Invalid master password.")

    def show_pin_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.pin_label = ttk.Label(self.root, text="Enter PIN Code:", font=("Arial", 12, "bold"))
        self.pin_label.pack(pady=(20, 10))

        self.pin_entry = ttk.Entry(self.root, show="*", width=25)
        self.pin_entry.pack(pady=5)

        self.pin_button = ttk.Button(self.root, text="Verify PIN", command=self.check_pin)
        self.pin_button.pack(pady=10)

    def check_pin(self):
        pin = self.pin_entry.get()
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()

        if pin_hash == self.users[self.current_user]["pin_hash"]:
            self.locked = False
            messagebox.showinfo("Success", "PIN Verified!")
            self.show_main_screen()
        else:
            messagebox.showwarning("Error", "Invalid PIN.")

    def show_main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.data_label = ttk.Label(self.root, text=f"Account - {self.current_user}", font=("Arial", 14, "bold"))
        self.data_label.pack(pady=(20, 10))

        self.add_button = ttk.Button(self.root, text="Add Password", command=self.add_password)
        self.add_button.pack(pady=5)

        self.view_button = ttk.Button(self.root, text="View Passwords", command=self.view_passwords)
        self.view_button.pack(pady=5)

        self.delete_button = ttk.Button(self.root, text="Delete Password", command=self.delete_password)
        self.delete_button.pack(pady=5)

        self.change_username_button = ttk.Button(self.root, text="Change Username", command=self.change_username)
        self.change_username_button.pack(pady=5)

        self.change_password_button = ttk.Button(self.root, text="Change Master Password", command=self.change_password)
        self.change_password_button.pack(pady=5)

        self.logout_button = ttk.Button(self.root, text="Logout", command=self.show_user_selection_screen)
        self.logout_button.pack(pady=10)

    def add_password(self):
        site = simpledialog.askstring("Add Password", "Enter site name:")
        if not site:
            messagebox.showwarning("Warning", "Site name cannot be empty.")
            return

        password = simpledialog.askstring("Add Password", "Enter the password:", show="*")
        if not password:
            messagebox.showwarning("Warning", "Password cannot be empty.")
            return

        encrypted_password = self.encrypt_password(password)

        self.users[self.current_user]["data"][site] = encrypted_password
        self.save_accounts()
        messagebox.showinfo("Success", f"Password added for {site}.")

    def view_passwords(self):
        passwords = self.users[self.current_user]["data"]
        if not passwords:
            messagebox.showinfo("Passwords", "No passwords stored.")
            return

        password_list = "\n".join(
            f"{site}: {self.decrypt_password(encrypted_password)}"
            for site, encrypted_password in passwords.items()
        )
        messagebox.showinfo("Stored Passwords", password_list)

    def delete_password(self):
        site = simpledialog.askstring("Delete Password", "Enter site name to delete:")
        if site in self.users[self.current_user]["data"]:
            del self.users[self.current_user]["data"][site]
            self.save_accounts()
            messagebox.showinfo("Success", f"Password for {site} deleted.")
        else:
            messagebox.showerror("Error", "Site not found.")

    def change_username(self):
        new_username = simpledialog.askstring("Change Username", "Enter a new username:")
        if new_username and new_username not in self.users:
            self.users[new_username] = self.users.pop(self.current_user)
            self.current_user = new_username
            self.save_accounts()
            messagebox.showinfo("Success", "Username changed successfully.")
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Invalid or duplicate username.")

    def change_password(self):
        new_password = simpledialog.askstring("Change Password", "Enter a new master password:", show="*")
        if new_password:
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            self.users[self.current_user]["password_hash"] = new_password_hash
            self.save_accounts()
            messagebox.showinfo("Success", "Master password changed successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
