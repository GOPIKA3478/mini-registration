"""
user_admin_app.py
Tkinter app with:
 - User registration (validations: email, phone, password)
 - User login -> Welcome page
 - Admin login -> Users table
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import hashlib
import binascii
import secrets
import re
import csv

DB_PATH = "app_users.db"


def hash_password(password: str, salt: bytes = None) -> (str, str):
    """Return (salt_hex, hash_hex). Uses PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(16)
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(hash_bytes).decode()

def verify_password(stored_salt_hex: str, stored_hash_hex: str, provided_password: str) -> bool:
    salt = binascii.unhexlify(stored_salt_hex.encode())
    _, computed_hash = hash_password(provided_password, salt)
    return computed_hash == stored_hash_hex


#user tb db
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        city TEXT,
        salt TEXT NOT NULL,
        passhash TEXT NOT NULL,
        #created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt TEXT NOT NULL,
        passhash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()

   
    cur.execute("SELECT COUNT(*) FROM admins")
    count = cur.fetchone()[0]
    if count == 0:
        default_admin_user = "admin"
        default_admin_pass = "admin123"  
        salt, phash = hash_password(default_admin_pass)
        cur.execute("INSERT INTO admins (username, salt, passhash) VALUES (?, ?, ?)",
                    (default_admin_user, salt, phash))
        conn.commit()
    conn.close()



#db
def register_user(name, email, phone, city, password):
    salt, phash = hash_password(password)
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, email, phone, city, salt, passhash) VALUES (?, ?, ?, ?, ?, ?)",
                    (name, email, phone, city, salt, phash))
        conn.commit()
        conn.close()
        return True, "Registration successful."
    except sqlite3.IntegrityError as e:
        return False, f"Error: {str(e)}"

def user_login(email, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT salt, passhash, name FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, "User not found.", None
    salt, phash, name = row
    if verify_password(salt, phash, password):
        return True, f"Welcome, {name}!", name
    else:
        return False, "Incorrect password.", None

def admin_login(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT salt, passhash FROM admins WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, "Admin not found."
    salt, phash = row
    if verify_password(salt, phash, password):
        return True, "Admin login successful."
    else:
        return False, "Incorrect admin password."

def fetch_all_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, phone, city, created_at FROM users ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows




class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("User/Admin App")
        self.geometry("520x420")
        self.resizable(False, False)

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=10)

       
        self.frames = {}
        for F in (MainMenu, UserRegisterFrame, UserLoginFrame, AdminLoginFrame, UserWelcomeFrame):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("MainMenu")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

class MainMenu(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        header = ttk.Label(self, text="Welcome — Choose an option", font=("TkDefaultFont", 14, "bold"))
        header.pack(pady=12)

        btn_user_register = ttk.Button(self, text="User: Register", width=25,
                                       command=lambda: controller.show_frame("UserRegisterFrame"))
        btn_user_register.pack(pady=6)
        btn_user_login = ttk.Button(self, text="User: Login", width=25,
                                    command=lambda: controller.show_frame("UserLoginFrame"))
        btn_user_login.pack(pady=6)
        btn_admin_login = ttk.Button(self, text="Admin: Login", width=25,
                                     command=lambda: controller.show_frame("AdminLoginFrame"))
        btn_admin_login.pack(pady=6)

        info = ttk.Label(self, text="Default Admin: username='admin' password='admin123'\n(please change in production)",
                         font=("TkDefaultFont", 8))
        info.pack(pady=12)

class UserRegisterFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="User Registration", font=("TkDefaultFont", 12, "bold")).pack(pady=8)

        form = ttk.Frame(self)
        form.pack(pady=6)

        ttk.Label(form, text="Name:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.e_name = ttk.Entry(form, width=30)
        self.e_name.grid(row=0, column=1, pady=4)

        ttk.Label(form, text="Email:").grid(row=1, column=0, sticky="e", padx=6, pady=4)
        self.e_email = ttk.Entry(form, width=30)
        self.e_email.grid(row=1, column=1, pady=4)

        ttk.Label(form, text="Phone:").grid(row=2, column=0, sticky="e", padx=6, pady=4)
        self.e_phone = ttk.Entry(form, width=30)
        self.e_phone.grid(row=2, column=1, pady=4)

        ttk.Label(form, text="City:").grid(row=3, column=0, sticky="e", padx=6, pady=4)
        self.e_city = ttk.Entry(form, width=30)
        self.e_city.grid(row=3, column=1, pady=4)

        ttk.Label(form, text="Password:").grid(row=4, column=0, sticky="e", padx=6, pady=4)
        self.e_password = ttk.Entry(form, show="*", width=30)
        self.e_password.grid(row=4, column=1, pady=4)

        ttk.Label(form, text="Confirm Password:").grid(row=5, column=0, sticky="e", padx=6, pady=4)
        self.e_confirm = ttk.Entry(form, show="*", width=30)
        self.e_confirm.grid(row=5, column=1, pady=4)

        ttk.Button(self, text="Register", command=self.do_register).pack(pady=8)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame("MainMenu")).pack()

    def do_register(self):
        name = self.e_name.get().strip()
        email = self.e_email.get().strip().lower()
        phone = self.e_phone.get().strip()
        city = self.e_city.get().strip()
        pw = self.e_password.get()
        pw2 = self.e_confirm.get()

        if not (name and email and pw and phone and city):
            messagebox.showwarning("Missing", "All fields are required.")
            return

        if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
            messagebox.showwarning("Invalid", "Please enter a valid email address.")
            return

        if not re.fullmatch(r"\d{10}", phone):
            messagebox.showwarning("Invalid", "Phone number must be 10 digits.")
            return

        if pw != pw2:
            messagebox.showwarning("Mismatch", "Passwords do not match.")
            return
        if len(pw) < 6:
            messagebox.showwarning("Weak", "Password should be at least 6 characters.")
            return

        ok, msg = register_user(name, email, phone, city, pw)
        if ok:
            messagebox.showinfo("Success", msg)
            self.e_name.delete(0, tk.END)
            self.e_email.delete(0, tk.END)
            self.e_phone.delete(0, tk.END)
            self.e_city.delete(0, tk.END)
            self.e_password.delete(0, tk.END)
            self.e_confirm.delete(0, tk.END)
        else:
            messagebox.showerror("Error", msg)

class UserLoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="User Login", font=("TkDefaultFont", 12, "bold")).pack(pady=8)

        frm = ttk.Frame(self)
        frm.pack(pady=6)
        ttk.Label(frm, text="Email:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.e_email = ttk.Entry(frm, width=30)
        self.e_email.grid(row=0, column=1, pady=4)
        ttk.Label(frm, text="Password:").grid(row=1, column=0, sticky="e", padx=6, pady=4)
        self.e_pw = ttk.Entry(frm, show="*", width=30)
        self.e_pw.grid(row=1, column=1, pady=4)

        ttk.Button(self, text="Login", command=self.do_login).pack(pady=8)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame("MainMenu")).pack()

    def do_login(self):
        email = self.e_email.get().strip().lower()
        pw = self.e_pw.get()
        ok, msg, name = user_login(email, pw)
        if ok:


            
            self.controller.frames["UserWelcomeFrame"].set_user(name)
            self.controller.show_frame("UserWelcomeFrame")
            self.e_email.delete(0, tk.END)
            self.e_pw.delete(0, tk.END)
        else:
            messagebox.showerror("Failed", msg)

class UserWelcomeFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.label = ttk.Label(self, text="", font=("TkDefaultFont", 14, "bold"))
        self.label.pack(pady=40)

        ttk.Button(self, text="Logout", command=lambda: controller.show_frame("MainMenu")).pack(pady=20)

    def set_user(self, name):
        self.label.config(text=f" Welcome, {name}!")

class AdminLoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Admin Login", font=("TkDefaultFont", 12, "bold")).pack(pady=8)

        frm = ttk.Frame(self)
        frm.pack(pady=6)
        ttk.Label(frm, text="Username:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.e_user = ttk.Entry(frm, width=30)
        self.e_user.grid(row=0, column=1, pady=4)
        ttk.Label(frm, text="Password:").grid(row=1, column=0, sticky="e", padx=6, pady=4)
        self.e_pw = ttk.Entry(frm, show="*", width=30)
        self.e_pw.grid(row=1, column=1, pady=4)

        ttk.Button(self, text="Login", command=self.do_login).pack(pady=8)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame("MainMenu")).pack()

    def do_login(self):
        username = self.e_user.get().strip()
        pw = self.e_pw.get()
        ok, msg = admin_login(username, pw)
        if ok:
            messagebox.showinfo("Admin", msg)
            self.e_user.delete(0, tk.END)
            self.e_pw.delete(0, tk.END)
            AdminTableWindow(self)  
        else:
            messagebox.showerror("Failed", msg)


class AdminTableWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Admin: Users Table")
        self.geometry("780x420")
        self.resizable(True, True)

        ttk.Label(self, text="Registered Users", font=("TkDefaultFont", 12, "bold")).pack(pady=8)

        columns = ("id", "name", "email", "phone", "city", "created_at")
        tree = ttk.Treeview(self, columns=columns, show="headings")
        tree.pack(fill="both", expand=True, padx=8, pady=6)

        for col in columns:
            tree.heading(col, text=col.title())
            if col == "id":
                tree.column(col, width=40, anchor="center")
            elif col == "email":
                tree.column(col, width=220)
            elif col == "name":
                tree.column(col, width=140)
            else:
                tree.column(col, width=120)

        self.tree = tree
        self.refresh()

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=6)
        ttk.Button(btn_frame, text="Refresh", command=self.refresh).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Close", command=self.destroy).pack(side="left", padx=6)

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for row in fetch_all_users():
            self.tree.insert("", tk.END, values=row)

    def export_csv(self):
        rows = [self.tree.item(r)["values"] for r in self.tree.get_children()]
        if not rows:
            messagebox.showinfo("Export", "No data to export.")
            return
        filepath = "users_export.csv"
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id", "name", "email", "phone", "city", "created_at"])
                writer.writerows(rows)
            messagebox.showinfo("Exported", f"Exported {len(rows)} rows to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")


if __name__ == "__main__":
    init_db()
    app = App()
    app.mainloop()
