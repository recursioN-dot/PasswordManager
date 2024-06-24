import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from tkinter import simpledialog, messagebox
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from random import choice
import string

# Constants
PASSWORD_FILE = "passwords.json"
ENCRYPTION_KEY_FILE = "key.key"
USER_PREFERENCES_FILE = "preferences.json"

# Encryption and Decryption

def generate_key():
    # Generate a new encryption key.
    return Fernet.generate_key()

def load_key():
    # Load the encryption key from the file, or generate a new one if it doesn't exist.
    if not os.path.exists(ENCRYPTION_KEY_FILE):
        key = generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

def encrypt_message(message, key):
    # Encrypt a message using the provided key.
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    # Decrypt an encrypted message using the provided key.
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Password Generation

def generate_password(length=12):
    # Generate a random password with the given length.
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(choice(characters) for i in range(length))
    return password

# User Preferences

def load_preferences(key):
    # Load user preferences from the encrypted file.
    if os.path.exists(USER_PREFERENCES_FILE):
        with open(USER_PREFERENCES_FILE, "rb") as file:
            encrypted_data = file.read()
            data = decrypt_message(encrypted_data, key)
            return json.loads(data)
    return {}

def save_preferences(preferences, key):
    # Save user preferences to the encrypted file.
    data = json.dumps(preferences)
    encrypted_data = encrypt_message(data, key)
    with open(USER_PREFERENCES_FILE, "wb") as file:
        file.write(encrypted_data)

# Password Manager Class

class PasswordManager:
    def __init__(self):
        self.key = load_key()
        self.passwords = self.load_passwords()

    def load_passwords(self):
        # Load passwords from the encrypted file.
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "rb") as file:
                encrypted_data = file.read()
                data = decrypt_message(encrypted_data, self.key)
                return json.loads(data)
        return {}

    def save_passwords(self):
        # Save passwords to the encrypted file.
        data = json.dumps(self.passwords)
        encrypted_data = encrypt_message(data, self.key)
        with open(PASSWORD_FILE, "wb") as file:
            file.write(encrypted_data)

    def add_password(self, account, username, password):
        # Add a new password entry.
        self.passwords[account] = {"username": username, "password": password}
        self.save_passwords()

    def get_password(self, account):
        # Retrieve a password entry by account name.
        return self.passwords.get(account, None)

# GUI

class PasswordManagerGUI:
    def __init__(self, root, password_manager):
        self.root = root
        self.password_manager = password_manager

        self.root.title("Password Manager")
        self.preferences = load_preferences(self.password_manager.key)
        self.current_theme = self.preferences.get("theme", "light")
        ctk.set_appearance_mode(self.current_theme)
        
        self.show_login_window()

    def show_login_window(self):
        # Display the login window. If the application password is not set, prompt the user to create one.
        self.root.withdraw()  # Hide the root window
        self.login_window = ctk.CTkToplevel(self.root)
        self.login_window.title("Login")

        if "app_password" not in self.preferences:
            self.create_password_window()
        else:
            ctk.CTkLabel(self.login_window, text="Enter application password:", anchor="w").grid(row=1, column=0, padx=20, pady=10)
            self.app_password_entry = ctk.CTkEntry(self.login_window, show='*')
            self.app_password_entry.grid(row=1, column=1, padx=20, pady=10)

            self.login_button = ctk.CTkButton(self.login_window, text="Login", command=self.check_password)
            self.login_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.theme_switch = None
        if "app_password" in self.preferences:
            self.theme_switch = ctk.CTkSwitch(self.login_window, text="Dark Mode", command=self.toggle_theme)
            self.theme_switch.grid(row=0, column=1, sticky="e", padx=20, pady=10)
            self.theme_switch.configure(font=("Helvetica", 10))
            if self.current_theme == "dark":
                self.theme_switch.select()
        
    def create_password_window(self):
        # Prompt the user to create a new application password on the first launch.
        self.login_window.withdraw()  # Hide the login window
        self.create_password_window = ctk.CTkToplevel(self.root)
        self.create_password_window.title("Create Application Password")

        ctk.CTkLabel(self.create_password_window, text="Create application password:", anchor="w").grid(row=0, column=0, padx=20, pady=10)
        self.new_password_entry = ctk.CTkEntry(self.create_password_window, show='*')
        self.new_password_entry.grid(row=0, column=1, padx=20, pady=10)

        self.save_new_password_button = ctk.CTkButton(self.create_password_window, text="Save Password", command=self.save_new_password)
        self.save_new_password_button.grid(row=1, column=0, columnspan=2, pady=10)

    def save_new_password(self):
        # Save the new application password entered by the user.
        new_password = self.new_password_entry.get()
        if new_password:
            self.preferences["app_password"] = encrypt_message(new_password, self.password_manager.key).decode()
            save_preferences(self.preferences, self.password_manager.key)
            self.create_password_window.destroy()
            self.login_window.destroy()
            self.root.deiconify()  # Show the root window
            self.show_main_window()
        else:
            messagebox.showerror("Error", "Password cannot be empty!")

    def toggle_theme(self):
        # Toggle between light and dark themes.
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        ctk.set_appearance_mode(self.current_theme)
        self.preferences["theme"] = self.current_theme
        save_preferences(self.preferences, self.password_manager.key)

    def check_password(self):
        # Verify the entered application password.
        app_password = self.app_password_entry.get()
        encrypted_app_password = self.preferences["app_password"]
        if app_password != decrypt_message(encrypted_app_password.encode(), self.password_manager.key):
            messagebox.showerror("Error", "Incorrect application password!")
            self.root.quit()
        else:
            self.login_window.destroy()
            self.root.deiconify()  # Show the root window
            self.show_main_window()

    def show_main_window(self):
        # Display the main window of the password manager application.
        self.root.title("Password Manager")
        
        ctk.CTkLabel(self.root, text="Account").grid(row=1, column=0, pady=10)
        ctk.CTkLabel(self.root, text="Username").grid(row=2, column=0, pady=10)
        ctk.CTkLabel(self.root, text="Password").grid(row=3, column=0, pady=10)

        self.account_entry = ctk.CTkEntry(self.root)
        self.username_entry = ctk.CTkEntry(self.root)
        self.password_entry = ctk.CTkEntry(self.root)
        self.account_entry.grid(row=1, column=1, padx=10, pady=10)
        self.username_entry.grid(row=2, column=1, padx=10, pady=10)
        self.password_entry.grid(row=3, column=1, padx=10, pady=10)

        self.generate_button = ctk.CTkButton(self.root, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=3, column=2, padx=10, pady=10)

        self.save_button = ctk.CTkButton(self.root, text="Save", command=self.save_password)
        self.save_button.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

        self.retrieve_button = ctk.CTkButton(self.root, text="Retrieve Password", command=self.retrieve_password)
        self.retrieve_button.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

        self.view_button = ctk.CTkButton(self.root, text="View All Passwords", command=self.view_passwords)
        self.view_button.grid(row=6, column=0, columnspan=3, padx=10, pady=10)
        
        self.theme_switch_main = ctk.CTkSwitch(self.root, text="Dark Mode", command=self.toggle_theme)
        self.theme_switch_main.grid(row=0, column=2, sticky="e", padx=20, pady=10)
        self.theme_switch_main.configure(font=("Helvetica", 10))
        if self.current_theme == "dark":
            self.theme_switch_main.select()

    def generate_password(self):
        # Generate a new random password and display it in the password entry field.
        password = generate_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def save_password(self):
        # Save the entered account, username, and password.
        account = self.account_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if account and username and password:
            self.password_manager.add_password(account, username, password)
            messagebox.showinfo("Success", "Password saved successfully!")
        else:
            messagebox.showerror("Error", "Please fill in all fields!")

    def retrieve_password(self):
        # Retrieve and display the password for the entered account.
        account = self.account_entry.get()
        if account:
            password_data = self.password_manager.get_password(account)
            if password_data:
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, password_data["username"])
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, password_data["password"])
            else:
                messagebox.showerror("Error", "No password found for this account!")
        else:
            messagebox.showerror("Error", "Please enter an account!")

    def view_passwords(self):
        # Display all stored passwords in a new window.
        passwords = self.password_manager.passwords
        if passwords:
            view_window = ctk.CTkToplevel(self.root)
            view_window.title("Stored Passwords")
            view_window.transient(self.root)  # Ensure the window is on top of the main application
            view_window.grab_set()  # Make the window modal

            tree = ttk.Treeview(view_window, columns=("Account", "Username", "Password"), show="headings")
            tree.heading("Account", text="Account")
            tree.heading("Username", text="Username")
            tree.heading("Password", text="Password")

            for account, data in passwords.items():
                tree.insert("", "end", values=(account, data["username"], data["password"]))

            tree.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

            view_window.geometry("600x400")
        else:
            messagebox.showinfo("Stored Passwords", "No passwords saved yet!")

if __name__ == "__main__":
    root = ctk.CTk()
    password_manager = PasswordManager()
    gui = PasswordManagerGUI(root, password_manager)
    root.mainloop()
