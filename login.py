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
        password="justbayr@1006",  
        database="hotel_booking",
        port=3306
    )
    c = conn.cursor()
except mysql.connector.Error as e:
    print(f"Error connecting to MySQL: {e}")
    exit()

# # Create users table if it doesn't exist
# c.execute("""
#     CREATE TABLE IF NOT EXISTS users (
#         userID INT AUTO_INCREMENT PRIMARY KEY,
#         username VARCHAR(50) UNIQUE,
#         email VARCHAR(100) UNIQUE,
#         password VARCHAR(255),
#         role VARCHAR(20) DEFAULT 'customer'
#     )
# """)
# conn.commit()

# Create default admin user if it doesn't exist
c.execute("SELECT * FROM users WHERE email = %s", ("j.bayron.538021@umindanao.edu.ph",))
if not c.fetchone():
    password = "bayron123".encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
    c.execute("INSERT INTO users (firstName, lastName, email, password, phone, role) VALUES (%s, %s, %s, %s, %s, %s)",
              ("Justine", "Bayron", "j.bayron.538021@umindanao.edu.ph", hashed, "093029230230", "admin"))
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

    c.execute("SELECT userID, firstName, password, role FROM users WHERE email=%s", (email,))
    user = c.fetchone()

    if user:
        print(f"User found: {user}")  
        print(f"Role: {user[3]}")    
        if check_password(user[2], password):
            root.destroy()
            if user[3] == 'admin':
                print("Opening admin system") 
                bookingsystem.open_admin_system(user[0], user[1])
            else:
                print("Opening booking system") 
                bookingsystem.open_booking_system(user[0], user[1])
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
    reg_root.geometry("500x650")
    reg_root.configure(bg="#f4f4f9")

    # Create a canvas for the background gradient
    canvas = tk.Canvas(reg_root, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    def update_gradient(event):
        canvas.delete("gradient")
        width = event.width
        height = event.height
        for i in range(height):
            color = f"#{int(180 - i*0.1):02x}{int(220 - i*0.1):02x}{255:02x}"
            canvas.create_line(0, i, width, i, fill=color, tags="gradient")

    canvas.bind("<Configure>", update_gradient)

    reg_frame = tk.Frame(reg_root, bg="white", bd=2, relief="flat")
    reg_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.7)
    
    reg_frame.config(highlightbackground="#d3d3d3", highlightcolor="#d3d3d3", highlightthickness=1)

    tk.Label(reg_frame, text="Create an Account", font=("Helvetica", 20, "bold"), fg="#2c3e50", bg="white").pack(pady=20)

    username_frame = tk.Frame(reg_frame, bg="white")
    username_frame.pack(pady=10)
    username_canvas = tk.Canvas(username_frame, width=300, height=50, bg="white", highlightthickness=0)
    username_canvas.pack()
    username_canvas.create_oval(5, 5, 295, 45, outline="#d3d3d3", fill="#f8f9fa", tags="oval")
    username_canvas.create_text(30, 25, text="👤", font=("Arial", 16), fill="#666")
    reg_username_entry = tk.Entry(username_frame, font=("Helvetica", 12), width=22, bd=0, bg="#f8f9fa", fg="#333")
    reg_username_entry.place(x=50, y=15, width=230, height=20)
    reg_username_entry.insert(0, "Enter your username")
    reg_username_entry.config(fg="grey")

    def on_username_focus_in(event):
        if reg_username_entry.get() == "Enter your username":
            reg_username_entry.delete(0, tk.END)
            reg_username_entry.config(fg="#333")

    def on_username_focus_out(event):
        if not reg_username_entry.get():
            reg_username_entry.insert(0, "Enter your username")
            reg_username_entry.config(fg="grey")

    reg_username_entry.bind("<FocusIn>", on_username_focus_in)
    reg_username_entry.bind("<FocusOut>", on_username_focus_out)

    email_frame = tk.Frame(reg_frame, bg="white")
    email_frame.pack(pady=10)
    email_canvas = tk.Canvas(email_frame, width=300, height=50, bg="white", highlightthickness=0)
    email_canvas.pack()
    email_canvas.create_oval(5, 5, 295, 45, outline="#d3d3d3", fill="#f8f9fa", tags="oval")
    email_canvas.create_text(30, 25, text="👤", font=("Arial", 16), fill="#666")
    reg_email_entry = tk.Entry(email_frame, font=("Helvetica", 12), width=22, bd=0, bg="#f8f9fa", fg="#333")
    reg_email_entry.place(x=50, y=15, width=230, height=20)
    reg_email_entry.insert(0, "Enter your email")
    reg_email_entry.config(fg="grey")

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

    password_frame = tk.Frame(reg_frame, bg="white")
    password_frame.pack(pady=10)
    password_canvas = tk.Canvas(password_frame, width=300, height=50, bg="white", highlightthickness=0)
    password_canvas.pack()
    password_canvas.create_oval(5, 5, 295, 45, outline="#d3d3d3", fill="#f8f9fa", tags="oval")
    password_canvas.create_text(30, 25, text="🔒", font=("Arial", 16), fill="#666")
    reg_password_entry = tk.Entry(password_frame, font=("Helvetica", 12), show="", width=22, bd=0, bg="#f8f9fa", fg="#333")
    reg_password_entry.place(x=50, y=15, width=230, height=20)
    reg_password_entry.insert(0, "Enter your password")
    reg_password_entry.config(fg="grey")

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
        register_btn.config(bg="#2980b9")

    def on_register_leave(e):
        register_btn.config(bg="#3498db")

    register_btn = tk.Button(reg_frame, text="Register", font=("Helvetica", 12, "bold"), 
                             bg="#3498db", fg="white", bd=0, width=20, height=2,
                             command=lambda: register_user(reg_root, reg_username_entry, reg_lastname_entry, reg_email_entry, reg_password_entry, reg_phone_entry))
    register_btn.pack(pady=15)
    register_btn.bind("<Enter>", on_register_enter)
    register_btn.bind("<Leave>", on_register_leave)

    def on_back_enter(e):
        back_btn.config(fg="#2980b9")

    def on_back_leave(e):
        back_btn.config(fg="#3498db")

    back_btn = tk.Button(reg_frame, text="Back to Login", font=("Helvetica", 10), 
                         bg="white", fg="#3498db", bd=0,
                         command=lambda: [reg_root.destroy(), main()])
    back_btn.pack(pady=5)
    back_btn.bind("<Enter>", on_back_enter)
    back_btn.bind("<Leave>", on_back_leave)

    reg_root.mainloop()

def register_user(reg_root, reg_username_entry, reg_lastname_entry, reg_email_entry, reg_password_entry, reg_phone_entry):
    username = reg_username_entry.get().strip()
    lastname = reg_lastname_entry.get().strip()
    email = reg_email_entry.get().strip()
    password = reg_password_entry.get().strip()
    phone = reg_phone_entry.get().strip()
    role = "customer"
    
    if not all([username, email, password]) or username == "Enter your username" or email == "Enter your email" or password == "Enter your password":
        messagebox.showerror("Error", "Please fill in all fields")
        return
    
    c.execute("SELECT * FROM users WHERE email=%s", (email))
    if c.fetchone():
        messagebox.showerror("Error", "Email already exists")
        return
    
    hashed_password = hash_password(password)
    try:
        c.execute("INSERT INTO users (firstName, lastName, email, password, phone, role) VALUES (%s, %s, %s, %s, %s, %s)", 
                 (username, email, hashed_password, role))
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
    root.configure(bg="#f4f4f9")

    canvas = tk.Canvas(root, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    def update_gradient(event):
        canvas.delete("gradient")
        width = event.width
        height = event.height
        for i in range(height):
            color = f"#{int(180 - i*0.1):02x}{int(220 - i*0.1):02x}{255:02x}"
            canvas.create_line(0, i, width, i, fill=color, tags="gradient")

    canvas.bind("<Configure>", update_gradient)

    login_frame = tk.Frame(root, bg="white", bd=2, relief="flat")
    login_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.7)

    login_frame.config(highlightbackground="#d3d3d3", highlightcolor="#d3d3d3", highlightthickness=1)

    tk.Label(login_frame, text="Hotel Booking System", font=("Helvetica", 24, "bold"), fg="#2c3e50", bg="white").pack(pady=(30, 20))

    email_frame = tk.Frame(login_frame, bg="white")
    email_frame.pack(pady=10)
    email_canvas = tk.Canvas(email_frame, width=300, height=50, bg="white", highlightthickness=0)
    email_canvas.pack()
    email_canvas.create_oval(5, 5, 295, 45, outline="#d3d3d3", fill="#f8f9fa", tags="oval")
    email_canvas.create_text(30, 25, text="👤", font=("Arial", 16), fill="#666")
    email_entry = tk.Entry(email_frame, font=("Helvetica", 12), width=22, bd=0, bg="#f8f9fa", fg="#333")
    email_entry.place(x=50, y=15, width=230, height=20)
    email_entry.insert(0, "Enter your email")
    email_entry.config(fg="grey")

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

    password_frame = tk.Frame(login_frame, bg="white")
    password_frame.pack(pady=10)
    password_canvas = tk.Canvas(password_frame, width=300, height=50, bg="white", highlightthickness=0)
    password_canvas.pack()
    password_canvas.create_oval(5, 5, 295, 45, outline="#d3d3d3", fill="#f8f9fa", tags="oval")
    password_canvas.create_text(30, 25, text="🔒", font=("Arial", 16), fill="#666")
    password_entry = tk.Entry(password_frame, font=("Helvetica", 12), show="", width=22, bd=0, bg="#f8f9fa", fg="#333")
    password_entry.place(x=50, y=15, width=230, height=20)
    password_entry.insert(0, "Enter your password")
    password_entry.config(fg="grey")

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
        login_btn.config(bg="#2980b9")

    def on_login_leave(e):
        login_btn.config(bg="#3498db")

    login_btn = tk.Button(login_frame, text="Login", font=("Helvetica", 12, "bold"), 
                          bg="#3498db", fg="white", bd=0, width=20, height=2, 
                          command=login)
    login_btn.pack(pady=20)
    login_btn.bind("<Enter>", on_login_enter)
    login_btn.bind("<Leave>", on_login_leave)

    def on_register_enter(e):
        register_btn.config(fg="#2980b9")

    def on_register_leave(e):
        register_btn.config(fg="#3498db")

    register_btn = tk.Button(login_frame, text="Don't have an account? Register", font=("Helvetica", 10), 
                             bg="white", fg="#3498db", bd=0, command=register)
    register_btn.pack(pady=5)
    register_btn.bind("<Enter>", on_register_enter)
    register_btn.bind("<Leave>", on_register_leave)

    root.mainloop()

if __name__ == "__main__":
    main()