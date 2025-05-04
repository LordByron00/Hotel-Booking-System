import tkinter as tk
from tkinter import messagebox
import mysql.connector
import bcrypt
import bookingsystem

# Database Setup
try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="hotel_booking",
        port=3306
    )
    c = conn.cursor()
except mysql.connector.Error as e:
    print(f"Error connecting to MySQL: {e}")
    exit()

# Create users table if it doesn't exist
c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        userID INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50),
        last_name VARCHAR(50),
        email VARCHAR(100) UNIQUE,
        contact_number VARCHAR(20),
        password VARCHAR(255),
        role VARCHAR(20) DEFAULT 'customer',
        status VARCHAR(20) DEFAULT 'active'
    )
""")
conn.commit()

c.execute("SELECT * FROM users WHERE email = %s", ("admin@gmail.com",))
if not c.fetchone():
    password = "admin123".encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
    c.execute("INSERT INTO users (first_name, last_name, email, contact_number, password, role) VALUES (%s, %s, %s, %s, %s, %s)",
              ("Admin", "User", "admin@gmail.com", "1234567890", hashed, "admin"))
    conn.commit()
    print("Default admin user created: email=admin@gmail.com, password=admin123")

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

def login():
    email = email_entry.get().strip()
    password = password_entry.get().strip()

    if not email or not password or email == "Enter your email" or password == "Enter your password":
        messagebox.showerror("Error", "Please enter both email and password")
        return

    c.execute("SELECT userID, first_name, last_name, password, role, status FROM users WHERE email=%s", (email,))
    user = c.fetchone()

    if user:
        if user[5] == 'blocked':
            messagebox.showerror("Error", "Your account is blocked. Contact the admin.")
            return
        if check_password(user[3], password):
            root.destroy()
            full_name = f"{user[1]} {user[2]}"
            if user[4] == 'admin':
                bookingsystem.open_admin_system(user[0], full_name)
            else:
                bookingsystem.open_booking_system(user[0], full_name)
        else:
            messagebox.showerror("Login Failed", "Invalid email or password")
    else:
        messagebox.showerror("Login Failed", "Invalid email or password")

def register():
    root.destroy()
    register_window()

def register_window():
    reg_root = tk.Tk()
    reg_root.title("Register - Hotel Booking System")
    reg_root.geometry("500x700")
    reg_root.configure(bg="#f0f2f5")

    canvas = tk.Canvas(reg_root, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    def update_gradient(event):
        canvas.delete("gradient")
        width = event.width
        height = event.height
        for i in range(height):
            color = f"#{int(240 - i*0.05):02x}{int(242 - i*0.05):02x}{int(245 - i*0.05):02x}"
            canvas.create_line(0, i, width, i, fill=color, tags="gradient")

    canvas.bind("<Configure>", update_gradient)

    reg_frame = tk.Frame(reg_root, bg="white", bd=0)
    reg_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)

    tk.Label(reg_frame, text="Create an Account", font=("Helvetica", 20, "bold"), fg="#1c2526", bg="white").pack(pady=20)

    # First Name
    first_name_entry = tk.Entry(reg_frame, font=("Helvetica", 12), width=25, bd=0, bg="#f0f2f5", fg="#333")
    first_name_entry.insert(0, "First Name")
    first_name_entry.config(fg="grey")
    first_name_entry.pack(pady=10, padx=20, ipady=8)
    first_name_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_first_name_focus_in(event):
        if first_name_entry.get() == "First Name":
            first_name_entry.delete(0, tk.END)
            first_name_entry.config(fg="#333")

    def on_first_name_focus_out(event):
        if not first_name_entry.get():
            first_name_entry.insert(0, "First Name")
            first_name_entry.config(fg="grey")

    first_name_entry.bind("<FocusIn>", on_first_name_focus_in)
    first_name_entry.bind("<FocusOut>", on_first_name_focus_out)

    # Last Name
    last_name_entry = tk.Entry(reg_frame, font=("Helvetica", 12), width=25, bd=0, bg="#f0f2f5", fg="#333")
    last_name_entry.insert(0, "Last Name")
    last_name_entry.config(fg="grey")
    last_name_entry.pack(pady=10, padx=20, ipady=8)
    last_name_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_last_name_focus_in(event):
        if last_name_entry.get() == "Last Name":
            last_name_entry.delete(0, tk.END)
            last_name_entry.config(fg="#333")

    def on_last_name_focus_out(event):
        if not last_name_entry.get():
            last_name_entry.insert(0, "Last Name")
            last_name_entry.config(fg="grey")

    last_name_entry.bind("<FocusIn>", on_last_name_focus_in)
    last_name_entry.bind("<FocusOut>", on_last_name_focus_out)

    # Email
    reg_email_entry = tk.Entry(reg_frame, font=("Helvetica", 12), width=25, bd=0, bg="#f0f2f5", fg="#333")
    reg_email_entry.insert(0, "Enter your email")
    reg_email_entry.config(fg="grey")
    reg_email_entry.pack(pady=10, padx=20, ipady=8)
    reg_email_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_email_focus_in(event):
        if reg_email_entry.get() == "Enter your email":
            reg_email_entry.delete(0, tk.END)
            reg_email_entry.config(fg="#333")

    def on_email_focus_out(event):
        if not reg_email_entry.get():
            reg_email_entry.insert(0, "Enter your email")
            reg_email_entry.config(fg="grey")

    reg_email_entry.bind("<FocusIn>", on_email_focus_in)
    reg_email_entry.bind("<FocusOut>", on_email_focus_out)

    # Contact Number
    contact_entry = tk.Entry(reg_frame, font=("Helvetica", 12), width=25, bd=0, bg="#f0f2f5", fg="#333")
    contact_entry.insert(0, "Contact Number")
    contact_entry.config(fg="grey")
    contact_entry.pack(pady=10, padx=20, ipady=8)
    contact_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_contact_focus_in(event):
        if contact_entry.get() == "Contact Number":
            contact_entry.delete(0, tk.END)
            contact_entry.config(fg="#333")

    def on_contact_focus_out(event):
        if not contact_entry.get():
            contact_entry.insert(0, "Contact Number")
            contact_entry.config(fg="grey")

    contact_entry.bind("<FocusIn>", on_contact_focus_in)
    contact_entry.bind("<FocusOut>", on_contact_focus_out)

    # Password
    reg_password_entry = tk.Entry(reg_frame, font=("Helvetica", 12), show="", width=25, bd=0, bg="#f0f2f5", fg="#333")
    reg_password_entry.insert(0, "Enter your password")
    reg_password_entry.config(fg="grey")
    reg_password_entry.pack(pady=10, padx=20, ipady=8)
    reg_password_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_password_focus_in(event):
        if reg_password_entry.get() == "Enter your password":
            reg_password_entry.delete(0, tk.END)
            reg_password_entry.config(fg="#333")
            reg_password_entry.config(show="*")

    def on_password_focus_out(event):
        if not reg_password_entry.get():
            reg_password_entry.insert(0, "Enter your password")
            reg_password_entry.config(fg="grey")
            reg_password_entry.config(show="")

    reg_password_entry.bind("<FocusIn>", on_password_focus_in)
    reg_password_entry.bind("<FocusOut>", on_password_focus_out)

    def on_register_enter(e):
        register_btn.config(bg="#1877f2")

    def on_register_leave(e):
        register_btn.config(bg="#1a77f2")

    register_btn = tk.Button(reg_frame, text="Register", font=("Helvetica", 12, "bold"),
                             bg="#1a77f2", fg="white", bd=0, width=20, height=2,
                             command=lambda: register_user(reg_root, first_name_entry, last_name_entry, reg_email_entry, contact_entry, reg_password_entry))
    register_btn.pack(pady=15)
    register_btn.bind("<Enter>", on_register_enter)
    register_btn.bind("<Leave>", on_register_leave)

    back_btn = tk.Button(reg_frame, text="Back to Login", font=("Helvetica", 10),
                         bg="white", fg="#1a77f2", bd=0,
                         command=lambda: [reg_root.destroy(), main()])
    back_btn.pack(pady=5)

    reg_root.mainloop()

def register_user(reg_root, first_name_entry, last_name_entry, reg_email_entry, contact_entry, reg_password_entry):
    first_name = first_name_entry.get().strip()
    last_name = last_name_entry.get().strip()
    email = reg_email_entry.get().strip()
    contact_number = contact_entry.get().strip()
    password = reg_password_entry.get().strip()
    role = "customer"

    if not all([first_name, last_name, email, contact_number, password]) or \
       first_name == "First Name" or last_name == "Last Name" or \
       email == "Enter your email" or contact_number == "Contact Number" or \
       password == "Enter your password":
        messagebox.showerror("Error", "Please fill in all fields")
        return

    c.execute("SELECT * FROM users WHERE email=%s", (email,))
    if c.fetchone():
        messagebox.showerror("Error", "Email already exists")
        return

    hashed_password = hash_password(password)
    try:
        c.execute("INSERT INTO users (first_name, last_name, email, contact_number, password, role) VALUES (%s, %s, %s, %s, %s, %s)",
                  (first_name, last_name, email, contact_number, hashed_password, role))
        conn.commit()
        messagebox.showinfo("Success", "Account Created Successfully")
        reg_root.destroy()
        main()
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Registration failed: {e}")

def main():
    global root, email_entry, password_entry

    root = tk.Tk()
    root.title("Login - Hotel Booking System")
    root.geometry("500x600")
    root.configure(bg="#f0f2f5")

    canvas = tk.Canvas(root, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    def update_gradient(event):
        canvas.delete("gradient")
        width = event.width
        height = event.height
        for i in range(height):
            color = f"#{int(240 - i*0.05):02x}{int(242 - i*0.05):02x}{int(245 - i*0.05):02x}"
            canvas.create_line(0, i, width, i, fill=color, tags="gradient")

    canvas.bind("<Configure>", update_gradient)

    login_frame = tk.Frame(root, bg="white", bd=0)
    login_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.7)

    tk.Label(login_frame, text="Hotel Booking System", font=("Helvetica", 24, "bold"), fg="#1c2526", bg="white").pack(pady=(30, 20))

    email_entry = tk.Entry(login_frame, font=("Helvetica", 12), width=25, bd=0, bg="#f0f2f5", fg="#333")
    email_entry.insert(0, "Enter your email")
    email_entry.config(fg="grey")
    email_entry.pack(pady=10, padx=20, ipady=8)
    email_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_email_focus_in(event):
        if email_entry.get() == "Enter your email":
            email_entry.delete(0, tk.END)
            email_entry.config(fg="#333")

    def on_email_focus_out(event):
        if not email_entry.get():
            email_entry.insert(0, "Enter your email")
            email_entry.config(fg="grey")

    email_entry.bind("<FocusIn>", on_email_focus_in)
    email_entry.bind("<FocusOut>", on_email_focus_out)

    password_entry = tk.Entry(login_frame, font=("Helvetica", 12), show="", width=25, bd=0, bg="#f0f2f5", fg="#333")
    password_entry.insert(0, "Enter your password")
    password_entry.config(fg="grey")
    password_entry.pack(pady=10, padx=20, ipady=8)
    password_entry.config(relief="flat", highlightthickness=1, highlightbackground="#ddd", highlightcolor="#ddd")

    def on_password_focus_in(event):
        if password_entry.get() == "Enter your password":
            password_entry.delete(0, tk.END)
            password_entry.config(fg="#333")
            password_entry.config(show="*")

    def on_password_focus_out(event):
        if not password_entry.get():
            password_entry.insert(0, "Enter your password")
            password_entry.config(fg="grey")
            password_entry.config(show="")

    password_entry.bind("<FocusIn>", on_password_focus_in)
    password_entry.bind("<FocusOut>", on_password_focus_out)

    def on_login_enter(e):
        login_btn.config(bg="#1877f2")

    def on_login_leave(e):
        login_btn.config(bg="#1a77f2")

    login_btn = tk.Button(login_frame, text="Login", font=("Helvetica", 12, "bold"),
                          bg="#1a77f2", fg="white", bd=0, width=20, height=2,
                          command=login)
    login_btn.pack(pady=20)
    login_btn.bind("<Enter>", on_login_enter)
    login_btn.bind("<Leave>", on_login_leave)

    register_btn = tk.Button(login_frame, text="Don't have an account? Register", font=("Helvetica", 10),
                             bg="white", fg="#1a77f2", bd=0, command=register)
    register_btn.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()