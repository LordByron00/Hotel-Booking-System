import tkinter as tk
from tkinter import messagebox, ttk
import mysql.connector
from datetime import datetime
import login
import webview
import threading

# Database Connection
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

def initialize_database():
    try:
        c.execute("""
            CREATE TABLE IF NOT EXISTS room_types (
                roomTypeID INT AUTO_INCREMENT PRIMARY KEY,
                typeName VARCHAR(50) UNIQUE,
                basePrice DECIMAL(10,2)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                roomID INT AUTO_INCREMENT PRIMARY KEY,
                roomTypeID INT,
                roomNumber VARCHAR(10),
                FOREIGN KEY (roomTypeID) REFERENCES room_types(roomTypeID)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS bookings (
                bookingID INT AUTO_INCREMENT PRIMARY KEY,
                userID INT,
                roomID INT,
                checkInDate DATE,
                checkOutDate DATE,
                status VARCHAR(20),
                totalAmount DECIMAL(10,2),
                FOREIGN KEY (roomID) REFERENCES rooms(roomID)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transactionID INT AUTO_INCREMENT PRIMARY KEY,
                bookingID INT,
                amount DECIMAL(10,2),
                transactionDate DATETIME,
                paymentMethod VARCHAR(50),
                status VARCHAR(20),
                FOREIGN KEY (bookingID) REFERENCES bookings(bookingID)
            )
        """)
        c.execute("""
            INSERT IGNORE INTO room_types (typeName, basePrice) 
            VALUES ('Single', 1000.00), ('Double', 2000.00), ('Suite', 2700.00)
        """)
        c.execute("""
            INSERT IGNORE INTO rooms (roomTypeID, roomNumber) 
            VALUES (1, '101'), (1, '102'), (2, '201'), (2, '202'), (3, '301'), (3, '302')
        """)
        conn.commit()
    except mysql.connector.Error as e:
        print(f"Error initializing database: {e}")

def check_room_availability(room_type, check_in, check_out, exclude_booking_id=None):
    try:
        query = """
            SELECT r.roomID 
            FROM rooms r
            JOIN room_types rt ON r.roomTypeID = rt.roomTypeID
            WHERE rt.typeName = %s
            AND r.roomID NOT IN (
                SELECT b.roomID 
                FROM bookings b 
                WHERE b.status != 'cancelled'
                AND (%s < b.checkOutDate AND %s > b.checkInDate)
        """
        params = [room_type, check_in, check_out]
        
        if exclude_booking_id:
            query += " AND b.bookingID != %s"
            params.append(exclude_booking_id)
        
        query += ") LIMIT 1"
        c.execute(query, params)
        return c.fetchone()
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Database error: {e}")
        return None

def calculate_total_amount(room_type, check_in, check_out):
    check_in_date = datetime.strptime(check_in, "%Y-%m-%d")
    check_out_date = datetime.strptime(check_out, "%Y-%m-%d")
    days = (check_out_date - check_in_date).days
    
    c.execute("SELECT basePrice FROM room_types WHERE typeName = %s", (room_type,))
    result = c.fetchone()
    if result:
        return days * result[0]
    return 0

# Customer Booking Functions
def add_booking(user_id, full_name):
    room_type = room_type_var.get().strip()
    check_in = check_in_entry.get().strip()
    check_out = check_out_entry.get().strip()
    payment_method = payment_method_var.get().strip()

    if not all([room_type, check_in, check_out, payment_method]):
        messagebox.showerror("Error", "Please fill in all fields")
        return

    try:
        check_in_date = datetime.strptime(check_in, "%Y-%m-%d")
        check_out_date = datetime.strptime(check_out, "%Y-%m-%d")
        
        if check_out_date <= check_in_date:
            messagebox.showerror("Error", "Check-out date must be after check-in date")
            return
        if check_in_date < datetime.now():
            messagebox.showerror("Error", "Check-in date cannot be in the past")
            return
    except ValueError:
        messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
        return

    available_room = check_room_availability(room_type, check_in, check_out)
    if not available_room:
        messagebox.showerror("Error", "No rooms available for selected dates")
        return
    
    room_id = available_room[0]
    total_amount = calculate_total_amount(room_type, check_in, check_out)

    try:
        c.execute("""
            INSERT INTO bookings (userID, roomID, checkInDate, checkOutDate, status, totalAmount) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, room_id, check_in, check_out, 'pending', total_amount))
        conn.commit()
        
        booking_id = c.lastrowid
        c.execute("""
            INSERT INTO transactions (bookingID, amount, transactionDate, paymentMethod, status)
            VALUES (%s, %s, %s, %s, %s)
        """, (booking_id, total_amount, datetime.now(), payment_method, 'pending'))
        conn.commit()
        
        messagebox.showinfo("Success", f"Booking Added Successfully\nTotal Amount: ${total_amount:.2f}\nPayment Method: {payment_method}\nStatus: Pending (Awaiting Admin Approval)")
        show_bookings(user_id)
        clear_entries()
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Booking failed: {e}")

def update_booking(user_id):
    selected = booking_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a booking to update")
        return
    
    booking_id = booking_table.item(selected[0])['values'][0]
    room_type = room_type_var.get().strip()
    check_in = check_in_entry.get().strip()
    check_out = check_out_entry.get().strip()

    if not all([room_type, check_in, check_out]):
        messagebox.showerror("Error", "Please fill in all fields")
        return

    try:
        check_in_date = datetime.strptime(check_in, "%Y-%m-%d")
        check_out_date = datetime.strptime(check_out, "%Y-%m-%d")
        
        if check_out_date <= check_in_date:
            messagebox.showerror("Error", "Check-out date must be after check-in date")
            return
        if check_in_date < datetime.now():
            messagebox.showerror("Error", "Check-in date cannot be in the past")
            return
    except ValueError:
        messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
        return

    available_room = check_room_availability(room_type, check_in, check_out, exclude_booking_id=booking_id)
    if not available_room:
        messagebox.showerror("Error", "No rooms available for selected dates")
        return

    room_id = available_room[0]
    total_amount = calculate_total_amount(room_type, check_in, check_out)

    try:
        c.execute("""
            UPDATE bookings 
            SET roomID = %s, checkInDate = %s, checkOutDate = %s, totalAmount = %s, status = 'pending'
            WHERE bookingID = %s AND userID = %s
        """, (room_id, check_in, check_out, total_amount, booking_id, user_id))
        conn.commit()
        messagebox.showinfo("Success", f"Booking Updated Successfully\nTotal Amount: ${total_amount:.2f}\nStatus: Pending (Awaiting Admin Approval)")
        show_bookings(user_id)
        clear_entries()
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Update failed: {e}")

def cancel_booking(user_id):
    selected = booking_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a booking to cancel")
        return
    
    booking_id = booking_table.item(selected[0])['values'][0]
    c.execute("UPDATE bookings SET status = 'cancelled' WHERE bookingID = %s AND userID = %s", 
             (booking_id, user_id))
    conn.commit()
    messagebox.showinfo("Success", "Booking cancelled successfully")
    show_bookings(user_id)
    clear_entries()

def show_bookings(user_id):
    for item in booking_table.get_children():
        booking_table.delete(item)

    c.execute("""
        SELECT b.bookingID, b.userID, rt.typeName, r.roomNumber, 
               b.checkInDate, b.checkOutDate, b.status, b.totalAmount 
        FROM bookings b 
        JOIN rooms r ON b.roomID = r.roomID 
        JOIN room_types rt ON r.roomTypeID = rt.roomTypeID 
        WHERE b.userID = %s
        ORDER BY b.checkInDate DESC
    """, (user_id,))
    
    for row in c.fetchall():
        booking_table.insert("", "end", values=row)

def clear_entries():
    check_in_entry.delete(0, tk.END)
    check_out_entry.delete(0, tk.END)
    room_type_var.set("Single")
    payment_method_var.set("Credit Card")

def select_booking(event):
    selected = booking_table.selection()
    if selected:
        booking = booking_table.item(selected[0])['values']
        room_type_var.set(booking[2])  
        check_in_entry.delete(0, tk.END)
        check_in_entry.insert(0, booking[4]) 
        check_out_entry.delete(0, tk.END)
        check_out_entry.insert(0, booking[5])  

def auto_refresh_bookings(user_id, booking_root):
    show_bookings(user_id)
    booking_root.after(5000, lambda: auto_refresh_bookings(user_id, booking_root)) 

def open_booking_system(user_id, full_name):
    global name_entry, check_in_entry, check_out_entry, room_type_var, payment_method_var, booking_table

    initialize_database()

    booking_root = tk.Tk()
    booking_root.title(f"Hotel Booking System - Welcome, {full_name}")
    booking_root.state('zoomed')

    input_frame = tk.LabelFrame(booking_root, text="Booking", padx=10, pady=10)
    input_frame.pack(padx=20, pady=10, fill="x")

    tk.Label(input_frame, text="Guest Name:").grid(row=0, column=0, pady=5, padx=10, sticky="w")
    name_entry = tk.Entry(input_frame, width=30)
    name_entry.insert(0, full_name)
    name_entry.config(state='disabled')
    name_entry.grid(row=0, column=1, pady=5, padx=10)

    tk.Label(input_frame, text="Room Type:").grid(row=1, column=0, pady=5, padx=10, sticky="w")
    room_type_var = tk.StringVar(value="Single")
    c.execute("SELECT typeName FROM room_types")
    room_types = [row[0] for row in c.fetchall()]
    room_type_dropdown = ttk.Combobox(input_frame, textvariable=room_type_var, values=room_types)
    room_type_dropdown.grid(row=1, column=1, pady=5, padx=10)

    tk.Label(input_frame, text="Check-in (YYYY-MM-DD):").grid(row=2, column=0, pady=5, padx=10, sticky="w")
    check_in_entry = tk.Entry(input_frame, width=30)
    check_in_entry.grid(row=2, column=1, pady=5, padx=10)

    tk.Label(input_frame, text="Check-out (YYYY-MM-DD):").grid(row=3, column=0, pady=5, padx=10, sticky="w")
    check_out_entry = tk.Entry(input_frame, width=30)
    check_out_entry.grid(row=3, column=1, pady=5, padx=10)

    tk.Label(input_frame, text="Payment Method:").grid(row=4, column=0, pady=5, padx=10, sticky="w")
    payment_method_var = tk.StringVar(value="Credit Card")
    payment_methods = ["Cash", "GCash", "Credit Card"]
    payment_method_dropdown = ttk.Combobox(input_frame, textvariable=payment_method_var, values=payment_methods)
    payment_method_dropdown.grid(row=4, column=1, pady=5, padx=10)

    button_frame = tk.Frame(input_frame)
    button_frame.grid(row=5, column=0, columnspan=2, pady=10)
    tk.Button(button_frame, text="Add Booking", command=lambda: add_booking(user_id, full_name), 
             bg="#4682B4", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Update Booking", command=lambda: update_booking(user_id),
             bg="#32CD32", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Cancel Booking", command=lambda: cancel_booking(user_id),
             bg="#FFA500", fg="white").pack(side=tk.LEFT, padx=5)

    columns = ("ID", "User ID", "Room Type", "Room Number", "Check-in", "Check-out", "Status", "Amount")
    booking_table = ttk.Treeview(booking_root, columns=columns, show="headings", height=15)
    for col in columns:
        booking_table.heading(col, text=col)
        booking_table.column(col, anchor="center", width=120)
    booking_table.pack(fill="both", expand=True, padx=20, pady=10)
    booking_table.bind('<<TreeviewSelect>>', select_booking)

    specs_btn = tk.Button(booking_root, 
                         text="View Room Specifications",
                         font=("Helvetica", 10, "bold"),
                         bg="#4CAF50",
                         fg="white",
                         bd=0,
                         padx=10,
                         pady=5,
                         command=show_room_specs)
    specs_btn.pack(pady=10)

    def logout():
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to log out?"):
            booking_root.destroy()
            login.main() 

    tk.Button(booking_root, text="Logout", command=logout,
             bg="red", fg="white").pack(pady=10)

    show_bookings(user_id)
    auto_refresh_bookings(user_id, booking_root)
    booking_root.mainloop()

# Admin Functions
def show_customers(customer_table):
    for item in customer_table.get_children():
        customer_table.delete(item)

    c.execute("SELECT userID, first_name, last_name, email, contact_number, role, status FROM users")
    for row in c.fetchall():
        customer_table.insert("", "end", values=row)

def update_customer(customer_table, first_name_entry, last_name_entry, email_entry, contact_entry):
    selected = customer_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a customer to update")
        return
    
    user_id = customer_table.item(selected[0])['values'][0]
    first_name = first_name_entry.get().strip()
    last_name = last_name_entry.get().strip()
    email = email_entry.get().strip()
    contact_number = contact_entry.get().strip()

    if not all([first_name, last_name, email, contact_number]):
        messagebox.showerror("Error", "Please fill in all fields")
        return

    try:
        c.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s, contact_number = %s
            WHERE userID = %s
        """, (first_name, last_name, email, contact_number, user_id))
        conn.commit()
        messagebox.showinfo("Success", "Customer updated successfully")
        show_customers(customer_table)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Update failed: {e}")

def delete_customer(customer_table):
    selected = customer_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a customer to delete")
        return
    
    user_id = customer_table.item(selected[0])['values'][0]
    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this customer?"):
        try:
            c.execute("DELETE FROM transactions WHERE bookingID IN (SELECT bookingID FROM bookings WHERE userID = %s)", (user_id,))
            c.execute("DELETE FROM bookings WHERE userID = %s", (user_id,))
            c.execute("DELETE FROM users WHERE userID = %s", (user_id,))
            conn.commit()
            messagebox.showinfo("Success", "Customer deleted successfully")
            show_customers(customer_table)
        except mysql.connector.Error as e:
            messagebox.showerror("Error", f"Delete failed: {e}")

def block_unblock_customer(customer_table, action):
    selected = customer_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a customer to block/unblock")
        return
    
    user_id = customer_table.item(selected[0])['values'][0]
    new_status = 'blocked' if action == 'block' else 'active'
    
    try:
        c.execute("UPDATE users SET status = %s WHERE userID = %s", (new_status, user_id))
        conn.commit()
        messagebox.showinfo("Success", f"Customer {new_status} successfully")
        show_customers(customer_table)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Action failed: {e}")

def show_all_bookings(booking_table):
    for item in booking_table.get_children():
        booking_table.delete(item)

    c.execute("""
        SELECT b.bookingID, CONCAT(u.first_name, ' ', u.last_name), rt.typeName, r.roomNumber, 
               b.checkInDate, b.checkOutDate, b.status, b.totalAmount 
        FROM bookings b 
        JOIN rooms r ON b.roomID = r.roomID 
        JOIN room_types rt ON r.roomTypeID = rt.roomTypeID 
        JOIN users u ON b.userID = u.userID
        ORDER BY b.checkInDate DESC
    """)
    for row in c.fetchall():
        booking_table.insert("", "end", values=row)

def show_reservations(reservation_table):
    for item in reservation_table.get_children():
        reservation_table.delete(item)

    c.execute("""
        SELECT b.bookingID, CONCAT(u.first_name, ' ', u.last_name), rt.typeName, r.roomNumber, 
               b.checkInDate, b.checkOutDate, b.status, b.totalAmount 
        FROM bookings b 
        JOIN rooms r ON b.roomID = r.roomID 
        JOIN room_types rt ON r.roomTypeID = rt.roomTypeID 
        JOIN users u ON b.userID = u.userID
        WHERE b.status = 'confirmed'
        ORDER BY b.checkInDate DESC
    """)
    for row in c.fetchall():
        reservation_table.insert("", "end", values=row)

def show_transactions(transaction_table):
    for item in transaction_table.get_children():
        transaction_table.delete(item)

    c.execute("""
        SELECT t.transactionID, b.bookingID, CONCAT(u.first_name, ' ', u.last_name), t.amount, 
               t.transactionDate, t.paymentMethod, t.status
        FROM transactions t
        JOIN bookings b ON t.bookingID = b.bookingID
        JOIN users u ON b.userID = u.userID
        ORDER BY t.transactionDate DESC
    """)
    for row in c.fetchall():
        transaction_table.insert("", "end", values=row)

def update_booking_status_admin(booking_table, status_var):
    selected = booking_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a booking to update status")
        return
    
    booking_id = booking_table.item(selected[0])['values'][0]
    new_status = status_var.get().strip()

    try:
        c.execute("UPDATE bookings SET status = %s WHERE bookingID = %s", (new_status, booking_id))
        c.execute("UPDATE transactions SET status = %s WHERE bookingID = %s", (new_status, booking_id))
        conn.commit()
        messagebox.showinfo("Success", f"Booking status updated to {new_status}")
        show_all_bookings(booking_table)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Status update failed: {e}")

def delete_booking_admin(booking_table):
    selected = booking_table.selection()
    if not selected:
        messagebox.showerror("Error", "Please select a booking to delete")
        return
    
    booking_id = booking_table.item(selected[0])['values'][0]
    
    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this booking?"):
        try:
            c.execute("DELETE FROM transactions WHERE bookingID = %s", (booking_id,))
            c.execute("DELETE FROM bookings WHERE bookingID = %s", (booking_id,))
            conn.commit()
            messagebox.showinfo("Success", "Booking deleted successfully")
            show_all_bookings(booking_table)
        except mysql.connector.Error as e:
            messagebox.showerror("Error", f"Delete failed: {e}")

def show_room_specs():
    url = "http://127.0.0.1:3000/home/index"
    window = webview.create_window('Room Specifications', 
                                 url,
                                 width=800, 
                                 height=600,
                                 resizable=True,
                                 fullscreen=False,
                                 min_size=(400, 300))
    window.events.loaded += lambda: window.evaluate_js(
        """
        // Disable right-click
        document.addEventListener('contextmenu', event => event.preventDefault());
        
        // Disable keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && 
                (e.key === 'l' || e.key === 'L' || e.key === 'F5')) {
                e.preventDefault();
            }
        });
        """
    )
    webview.start(debug=False)

def open_admin_system(user_id, full_name):
    initialize_database()

    admin_root = tk.Tk()
    admin_root.title(f"Admin Dashboard - Welcome, {full_name}")
    admin_root.state('zoomed')

    # Add this button frame before the notebook
    top_button_frame = tk.Frame(admin_root)
    top_button_frame.pack(fill="x", padx=20, pady=5)

    specs_btn = tk.Button(top_button_frame, 
                         text="View Room Specifications",
                         font=("Helvetica", 10, "bold"),
                         bg="#4CAF50",
                         fg="white",
                         bd=0,
                         padx=10,
                         pady=5,
                         command=show_room_specs)
    specs_btn.pack(side=tk.RIGHT)

    notebook = ttk.Notebook(admin_root)
    notebook.pack(fill="both", expand=True, padx=20, pady=10)

    # Customers Tab
    customers_frame = ttk.Frame(notebook)
    notebook.add(customers_frame, text="Customers")

    customer_form_frame = tk.LabelFrame(customers_frame, text="Update Customer", padx=10, pady=10)
    customer_form_frame.pack(padx=20, pady=10, fill="x")

    tk.Label(customer_form_frame, text="First Name:").grid(row=0, column=0, pady=5, padx=10, sticky="w")
    first_name_entry = tk.Entry(customer_form_frame, width=30)
    first_name_entry.grid(row=0, column=1, pady=5, padx=10)

    tk.Label(customer_form_frame, text="Last Name:").grid(row=1, column=0, pady=5, padx=10, sticky="w")
    last_name_entry = tk.Entry(customer_form_frame, width=30)
    last_name_entry.grid(row=1, column=1, pady=5, padx=10)

    tk.Label(customer_form_frame, text="Email:").grid(row=2, column=0, pady=5, padx=10, sticky="w")
    email_entry = tk.Entry(customer_form_frame, width=30)
    email_entry.grid(row=2, column=1, pady=5, padx=10)

    tk.Label(customer_form_frame, text="Contact Number:").grid(row=3, column=0, pady=5, padx=10, sticky="w")
    contact_entry = tk.Entry(customer_form_frame, width=30)
    contact_entry.grid(row=3, column=1, pady=5, padx=10)

    button_frame = tk.Frame(customer_form_frame)
    button_frame.grid(row=4, column=0, columnspan=2, pady=10)
    tk.Button(button_frame, text="Update Customer", 
             command=lambda: update_customer(customer_table, first_name_entry, last_name_entry, email_entry, contact_entry),
             bg="#32CD32", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Delete Customer", 
             command=lambda: delete_customer(customer_table),
             bg="#FF4444", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Block Customer", 
             command=lambda: block_unblock_customer(customer_table, 'block'),
             bg="#FFA500", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Unblock Customer", 
             command=lambda: block_unblock_customer(customer_table, 'unblock'),
             bg="#4682B4", fg="white").pack(side=tk.LEFT, padx=5)

    customer_columns = ("ID", "First Name", "Last Name", "Email", "Contact Number", "Role", "Status")
    customer_table = ttk.Treeview(customers_frame, columns=customer_columns, show="headings", height=15)
    for col in customer_columns:
        customer_table.heading(col, text=col)
        customer_table.column(col, anchor="center", width=150)
    customer_table.pack(fill="both", expand=True, padx=20, pady=10)

    def select_customer(event):
        selected = customer_table.selection()
        if selected:
            customer = customer_table.item(selected[0])['values']
            first_name_entry.delete(0, tk.END)
            first_name_entry.insert(0, customer[1])
            last_name_entry.delete(0, tk.END)
            last_name_entry.insert(0, customer[2])
            email_entry.delete(0, tk.END)
            email_entry.insert(0, customer[3])
            contact_entry.delete(0, tk.END)
            contact_entry.insert(0, customer[4])

    customer_table.bind('<<TreeviewSelect>>', select_customer)

    # Bookings Tab
    bookings_frame = ttk.Frame(notebook)
    notebook.add(bookings_frame, text="Bookings")

    status_form_frame = tk.LabelFrame(bookings_frame, text="Update Status", padx=10, pady=10)
    status_form_frame.pack(padx=20, pady=10, fill="x")

    tk.Label(status_form_frame, text="Status:").grid(row=0, column=0, pady=5, padx=10, sticky="w")
    status_var = tk.StringVar(value="pending")
    status_options = ["pending", "confirmed", "cancelled"]
    status_dropdown = ttk.Combobox(status_form_frame, textvariable=status_var, values=status_options, state="readonly")
    status_dropdown.grid(row=0, column=1, pady=5, padx=10)

    button_frame = tk.Frame(status_form_frame)
    button_frame.grid(row=1, column=0, columnspan=2, pady=10)
    tk.Button(button_frame, text="Update Status", 
             command=lambda: update_booking_status_admin(booking_table, status_var),
             bg="#32CD32", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Delete Booking", 
             command=lambda: delete_booking_admin(booking_table),
             bg="#FF4444", fg="white").pack(side=tk.LEFT, padx=5)

    booking_columns = ("ID", "Guest", "Room Type", "Room Number", "Check-in", "Check-out", "Status", "Amount")
    booking_table = ttk.Treeview(bookings_frame, columns=booking_columns, show="headings", height=15)
    for col in booking_columns:
        booking_table.heading(col, text=col)
        booking_table.column(col, anchor="center", width=120)
    booking_table.pack(fill="both", expand=True, padx=20, pady=10)

    # Reservations Tab
    reservations_frame = ttk.Frame(notebook)
    notebook.add(reservations_frame, text="Reservations")

    reservation_columns = ("ID", "Guest", "Room Type", "Room Number", "Check-in", "Check-out", "Status", "Amount")
    reservation_table = ttk.Treeview(reservations_frame, columns=reservation_columns, show="headings", height=20)
    for col in reservation_columns:
        reservation_table.heading(col, text=col)
        reservation_table.column(col, anchor="center", width=120)
    reservation_table.pack(fill="both", expand=True, padx=20, pady=10)

    # Transactions Tab
    transactions_frame = ttk.Frame(notebook)
    notebook.add(transactions_frame, text="Transactions")

    transaction_columns = ("ID", "Booking ID", "Guest", "Amount", "Date", "Payment Method", "Status")
    transaction_table = ttk.Treeview(transactions_frame, columns=transaction_columns, show="headings", height=20)
    for col in transaction_columns:
        transaction_table.heading(col, text=col)
        transaction_table.column(col, anchor="center", width=150)
    transaction_table.pack(fill="both", expand=True, padx=20, pady=10)

    specs_btn = tk.Button(transactions_frame, 
                         text="View Room Specifications",
                         font=("Helvetica", 10, "bold"),
                         bg="#4CAF50",
                         fg="white",
                         bd=0,
                         padx=10,
                         pady=5,
                         command=show_room_specs)
    specs_btn.pack(pady=10)

    def logout():
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to log out?"):
            admin_root.destroy()
            login.main()

    tk.Button(admin_root, text="Logout", command=logout,
             bg="red", fg="white").pack(pady=10)

    show_customers(customer_table)
    show_all_bookings(booking_table)
    show_reservations(reservation_table)
    show_transactions(transaction_table)

    admin_root.mainloop()