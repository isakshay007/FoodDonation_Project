from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
import mysql.connector
import os
import re

app = Flask(__name__, static_folder='static')
app.secret_key = "your_secret_key"  # Replace with a secure random key
app.config['SESSION_PERMANENT'] = False  # Ensures session doesn't persist unnecessarily
load_dotenv()

# Database connection setup
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST"),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DATABASE")
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# Clear session on the first request
first_request_handled = False

@app.before_request
def clear_session_on_startup():
    """Clears session data for the first request."""
    global first_request_handled
    if not first_request_handled:
        session.clear()
        first_request_handled = True

# Redirect root URL ("/") to "/home"
@app.route("/")
def root():
    """Redirects root URL to /home."""
    return redirect(url_for("home"))

# Home Page
@app.route("/home")
def home():
    """Renders the home page."""
    if "user" in session and "role" in session:
        # Redirect based on role
        if session["role"] == "Donor":
            return redirect(url_for("donor_menu"))
        elif session["role"] == "Recipient":
            return redirect(url_for("recipient_dashboard"))
    return render_template("home.html")

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles login for Donor, Recipient, and Admin."""
    if request.method == "POST":
        # Get form data
        email = request.form.get("email")
        password = request.form.get("password")

        connection = get_db_connection()
        if not connection:
            flash("Database connection failed. Please try again.", "danger")
            return render_template("login.html")

        try:
            cursor = connection.cursor(dictionary=True)
            # Query to authenticate user based on role
            query = "SELECT * FROM User WHERE email = %s AND password_hash = SHA2(%s, 256)"
            cursor.execute(query, (email, password))
            user = cursor.fetchone()

            if user:
                # Save session data
                session["user_id"] = user["user_id"]
                session["username"] = user["username"]
                session["role"] = user["role"]

                # Update last login timestamp
                cursor.execute("UPDATE User SET last_login = NOW() WHERE user_id = %s", (user["user_id"],))
                connection.commit()

                # Redirect to respective dashboard
                if user["role"] == "Donor":
                    return redirect(url_for("donor_menu"))
                elif user["role"] == "Recipient":
                    return redirect(url_for("recipient_menu"))
                elif user["role"] == "Admin":
                    return redirect(url_for("admin_dashboard"))
            else:
                flash("Invalid email or password. Please try again.", "danger")
        except Exception as e:
            flash(f"Error during login: {e}", "danger")
        finally:
            connection.close()

    return render_template("login.html")

# Register Route
@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles user registration."""
    if request.method == "POST":
        # Extract form data
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        phone = request.form.get("phone")
        role = request.form.get("role")

        # Input validation patterns
        email_regex = r'^[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}$'
        phone_regex = r'^\d{10,15}$'

        # Validate inputs
        if not re.match(email_regex, email):
            flash("Invalid email format. Please try again.", "danger")
            return render_template("register.html")
        if not re.match(phone_regex, phone):
            flash("Invalid phone number. Please enter 10-15 digits.", "danger")
            return render_template("register.html")
        if role not in ["Donor", "Recipient"]:
            flash("Invalid role selected. Please choose a valid option.", "danger")
            return render_template("register.html")

        # Database connection and user insertion
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()

                # Check if the username or email already exists
                check_query = """
                    SELECT * FROM User WHERE username = %s OR email = %s
                """
                cursor.execute(check_query, (username, email))
                if cursor.fetchone():
                    flash("Username or email already exists. Please try again.", "danger")
                    return render_template("register.html")

                # Insert new user into the database
                query = """
                    INSERT INTO User (username, email, password_hash, phone_number, role)
                    VALUES (%s, %s, SHA2(%s, 256), %s, %s)
                """
                cursor.execute(query, (username, email, password, phone, role))
                connection.commit()

                # Registration successful
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for("login"))

            except mysql.connector.Error as err:
                # Handle specific database errors
                if "Duplicate entry" in str(err):
                    flash("Username or email already exists. Please try again.", "danger")
                else:
                    flash(f"Database error: {err}", "danger")
            finally:
                cursor.close()
                connection.close()
        else:
            flash("Database connection failed. Please try again later.", "danger")

    # Render the registration page for GET requests or in case of errors
    return render_template("register.html")


# Admin Menu
@app.route("/admin/dashboard")
def admin_dashboard():
    """Admin dashboard page."""
    if session.get("role") != "Admin":
        flash("Unauthorized access. Please log in as Admin.", "danger")
        return redirect(url_for("login"))

    return render_template("admin_dashboard.html", username=session.get("username"))


# Admin Donation Statistics
@app.route('/admin/view-donation-statistics', methods=['GET'])
def view_donation_statistics():
    """Displays dynamic donation statistics."""
    connection = get_db_connection()
    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT 
            CURDATE() AS stat_date,
            COUNT(*) AS total_donations,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_donations,
            SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending_donations,
            SUM(CASE WHEN status = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled_donations
        FROM Donations
        """
        cursor.execute(query)
        statistics = cursor.fetchone()

        if statistics:
            # Save statistics dynamically to a database if required
            flash("Statistics retrieved successfully!", "success")
        else:
            flash("No donation statistics available.", "info")

        return render_template('admin_donation_statistics.html', statistics=statistics)

    except mysql.connector.Error as err:
        flash(f"Error retrieving statistics: {err}", "danger")
        return render_template('admin_donation_statistics.html', statistics=None)
    finally:
        connection.close() 


@app.route('/admin/view-user-logs', methods=['GET'])
def view_user_logs():
    """Fetch and display user activity logs."""
    connection = get_db_connection()
    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT 
            ua.action_id,
            u.username,
            u.role,
            ua.action_type,
            ua.action_details,
            ua.action_timestamp
        FROM UserActions ua
        JOIN User u ON ua.user_id = u.user_id
        ORDER BY ua.action_timestamp DESC;
        """
        cursor.execute(query)
        logs = cursor.fetchall()

        if logs:
            flash("User activity logs retrieved successfully!", "success")
        else:
            flash("No user activity logs found.", "info")

        return render_template('admin_user_logs.html', logs=logs)

    except mysql.connector.Error as err:
        flash(f"Error retrieving user logs: {err}", "danger")
        return render_template('admin_user_logs.html', logs=None)
    finally:
        connection.close()

@app.route('/admin/delete-user', methods=['GET', 'POST'])
def delete_user():
    """Allows admin to delete a user."""
    # Ensure the current user is an admin
    if session.get("role") != "Admin":
        flash("Unauthorized access. Please log in as Admin.", "danger")
        return redirect(url_for("login"))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for("admin_dashboard"))

    try:
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            # Get the user ID to delete
            user_id_to_delete = request.form.get('user_id')

            # Prevent the admin from deleting themselves
            if user_id_to_delete == str(session.get("user_id")):
                flash("You cannot delete your own account.", "danger")
                return redirect(url_for('delete_user'))

            # Delete user from the database
            delete_query = "DELETE FROM User WHERE user_id = %s"
            cursor.execute(delete_query, (user_id_to_delete,))
            connection.commit()

            # Provide feedback to the admin
            if cursor.rowcount > 0:
                flash(f"User ID {user_id_to_delete} deleted successfully.", "success")
            else:
                flash(f"No matching user found for ID {user_id_to_delete}.", "warning")
            
            return redirect(url_for("delete_user"))

        # Fetch all users (except the admin themselves) to display in the UI
        cursor.execute("SELECT user_id, username, email, role FROM User WHERE user_id != %s", (session["user_id"],))
        users = cursor.fetchall()

    except mysql.connector.Error as err:
        flash(f"Error deleting user: {err}", "danger")
        users = []
    finally:
        connection.close()

    return render_template("admin_delete_user.html", users=users)

@app.route('/admin/delete-activity-logs', methods=['POST'])
def delete_activity_logs():
    """Allows administrators to clear all user activity logs."""
    # Check if the logged-in user is an admin
    if session.get("role") != "Admin":
        flash("Unauthorized access. Please log in as Admin.", "danger")
        return redirect(url_for("login"))

    # Connect to the database
    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for("view_user_logs"))

    try:
        cursor = connection.cursor()

        # Delete all logs from the UserActions table
        delete_query = "DELETE FROM UserActions"
        cursor.execute(delete_query)
        connection.commit()

        if cursor.rowcount > 0:
            flash(f"All activity logs have been cleared successfully.", "success")
        else:
            flash(f"No activity logs found to delete.", "info")

    except mysql.connector.Error as err:
        flash(f"Error clearing activity logs: {err}", "danger")
    finally:
        connection.close()

    # Redirect back to the user logs page
    return redirect(url_for("view_user_logs"))

# Donor Menu
@app.route('/donor', methods=['GET'])
def donor_menu():
    """Donor Menu."""
    if 'user_id' not in session or session.get('role') != 'Donor':
        flash("Unauthorized access. Please log in as a donor.", "danger")
        return redirect(url_for('login'))
    
    donor_name = session.get('username', 'Donor')  # Default to 'Donor' if username is not found
    return render_template('donor_menu.html', donor_name=donor_name)

# Add Donation
@app.route('/donor/add-donation', methods=['GET', 'POST'])
def add_donation():
    """Allows a donor to add a new donation."""
    if 'user_id' not in session or session.get('role') != 'Donor':
        flash("Unauthorized access. Please log in as a donor.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for('donor_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        if request.method == 'POST':
            # Retrieve form data
            donation_date = request.form.get('donation_date')
            delivery_method = request.form.get('delivery_method')
            delivery_location = request.form.get('delivery_location')
            category = request.form.get('category')
            food_item_name = request.form.get('food_item_name')
            origin = request.form.get('origin')
            expiration_date = request.form.get('expiration_date')
            storage_requirements = request.form.get('storage_requirements')

            # Insert into Donations table
            donation_query = """
            INSERT INTO Donations (donation_date, status, delivery_method, delivery_location, recipient_id, donor_id)
            VALUES (%s, 'Pending', %s, %s, NULL, %s)
            """
            cursor.execute(donation_query, (donation_date, delivery_method, delivery_location, session['user_id']))
            connection.commit()
            donation_id = cursor.lastrowid

            # Insert into FoodItems table
            food_item_query = """
            INSERT INTO FoodItems (name, origin, storage_requirements, expiration_date, category_name, donation_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(food_item_query, (food_item_name, origin, storage_requirements, expiration_date, category, donation_id))
            connection.commit()

            flash(f"Donation added successfully!", "success")
            return redirect(url_for('donor_menu'))

        # Fetch categories for dropdown
        cursor.execute("SELECT category_name FROM Categories")
        categories = cursor.fetchall()

    except mysql.connector.Error as err:
        flash(f"Error adding donation: {err}", "danger")
        categories = []
    finally:
        connection.close()

    return render_template('donor_add_donation.html', categories=categories)

# View Donation History
@app.route('/donor/view-donations', methods=['GET'])
def view_donations():
    """Fetch and display the current donations."""
    if 'user_id' not in session or session.get('role') != 'Donor':
        flash("Unauthorized access. Please log in as a donor.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('donor_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT d.donation_id, d.status, d.delivery_method, d.delivery_location,
               f.name AS food_item_name, f.expiration_date, f.category_name
        FROM Donations d
        LEFT JOIN FoodItems f ON d.donation_id = f.donation_id
        WHERE d.donor_id = %s AND d.status = 'Pending'
        """
        cursor.execute(query, (session['user_id'],))
        donations = cursor.fetchall()
        return render_template('donor_view_donations.html', donations=donations)
    except mysql.connector.Error as err:
        flash(f"Error retrieving donations: {err}", "danger")
        return redirect(url_for('donor_menu'))
    finally:
        connection.close()

@app.route('/donor/delete-donation', methods=['POST'])
def delete_donation():
    """Allows donors to delete a pending donation."""
    if 'user_id' not in session or session.get('role') != 'Donor':
        flash("Unauthorized access. Please log in as a donor.", "danger")
        return redirect(url_for('login'))

    donation_id = request.form.get('donation_id')
    connection = get_db_connection()

    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('view_donations'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Check if the donation is pending and belongs to the logged-in donor
        query = """
        SELECT donation_id FROM Donations
        WHERE donation_id = %s AND donor_id = %s AND status = 'Pending'
        """
        cursor.execute(query, (donation_id, session['user_id']))
        donation = cursor.fetchone()

        if donation:
            # Delete the donation
            delete_query = "DELETE FROM Donations WHERE donation_id = %s"
            cursor.execute(delete_query, (donation_id,))
            connection.commit()
            flash(f"Donation ID {donation_id} has been successfully deleted.", "success")
        else:
            flash("Invalid donation ID or the donation is not pending.", "danger")

    except mysql.connector.Error as err:
        flash(f"Error deleting donation: {err}", "danger")
    finally:
        connection.close()

    return redirect(url_for('view_donations'))


# View Donation History
@app.route('/donor/view-donation-history', methods=['GET'])
def view_donation_history():
    """Fetch and display the donation history."""
    if 'user_id' not in session or session.get('role') != 'Donor':
        flash("Unauthorized access. Please log in as a donor.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('donor_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT d.donation_id, d.status, d.delivery_method, d.delivery_location,
               f.name AS food_item_name, f.expiration_date, f.category_name
        FROM Donations d
        LEFT JOIN FoodItems f ON d.donation_id = f.donation_id
        WHERE d.donor_id = %s AND d.status IN ('Completed', 'Cancelled')
        """
        cursor.execute(query, (session['user_id'],))
        history = cursor.fetchall()
        return render_template('donor_view_donation_history.html', history=history)
    except mysql.connector.Error as err:
        flash(f"Error retrieving donation history: {err}", "danger")
        return redirect(url_for('donor_menu'))
    finally:
        connection.close()

# Donor Notification
@app.route('/donor/view-notifications', methods=['GET'])
def view_notifications():
    """Fetch and display notifications for the logged-in donor."""
    if 'user_id' not in session or session.get('role') != 'Donor':
        flash("Unauthorized access. Please log in as a donor.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('donor_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT message, created_at
        FROM Notifications
        WHERE user_id = %s
        ORDER BY created_at DESC
        """
        cursor.execute(query, (session['user_id'],))
        notifications = cursor.fetchall()

        if not notifications:
            flash("No new notifications.", "info")
            notifications = []

        return render_template('donor_notifications.html', notifications=notifications)
    except mysql.connector.Error as err:
        flash(f"Error retrieving notifications: {err}", "danger")
        return redirect(url_for('donor_menu'))
    finally:
        connection.close()

# Donor Feedback
@app.route('/donor/feedback')
def view_donation_feedback():
    user_id = session.get('user_id')  # Get the current logged-in donor's ID
    if not user_id:
        return "User not logged in", 403

    query = """
    SELECT 
        d.donation_id,
        df.feedback, 
        df.rating, 
        df.created_at
    FROM DonationFeedback df
    JOIN Donations d ON df.donation_id = d.donation_id
    WHERE d.donor_id = %s
    ORDER BY df.created_at DESC
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, (user_id,))
        feedbacks = cursor.fetchall()
        conn.close()  # Always close the connection
        return render_template('donor_feedback.html', feedbacks=feedbacks)
    except mysql.connector.Error as err:
        return f"Error retrieving feedback: {err}", 500

# Recipient Menu
@app.route("/recipient/dashboard")
def recipient_menu():
    """Recipient Menu."""
    if "user_id" not in session or session.get("role") != "Recipient":
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for("login"))

    # Establish a database connection
    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for("login"))

    try:
        cursor = connection.cursor(dictionary=True)

        # Check if the recipient already has an organization
        query = "SELECT * FROM Organization WHERE user_id = %s"
        cursor.execute(query, (session["user_id"],))
        organization = cursor.fetchone()
        has_organization = organization is not None

        # Get recipient name
        recipient_name = session.get("username")

        # Pass organization status to the template
        return render_template(
            "recipient_menu.html",
            recipient_name=recipient_name,
            has_organization=has_organization,
        )
    except mysql.connector.Error as err:
        flash(f"Database error: {err.msg}", "danger")
        return redirect(url_for("login"))
    finally:
        cursor.close()
        connection.close()

# Create organization
@app.route('/recipient/create-organization', methods=['GET', 'POST'])
def create_organization():
    """Allows a recipient to create an organization."""
    # Check if the user is logged in and has the correct role
    if 'user_id' not in session or session.get('role') != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    # Establish a database connection
    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Check if the recipient has already created an organization
        check_query = "SELECT * FROM Organization WHERE user_id = %s"
        cursor.execute(check_query, (session['user_id'],))
        existing_organization = cursor.fetchone()

        if existing_organization:
            flash("You have already registered an organization.", "info")
            return redirect(url_for('recipient_menu'))

        if request.method == 'POST':
            # Retrieve form data
            org_name = request.form.get('org_name')
            address = request.form.get('address')
            contact_info = request.form.get('contact_info')
            capacity = request.form.get('capacity')

            # Ensure required fields are not empty
            if not org_name or not address or not contact_info or not capacity:
                flash("All fields are required. Please fill out the form completely.", "warning")
                return render_template('recipient_create_organization.html')

            try:
                # Insert organization details into the database
                insert_query = """
                INSERT INTO Organization (name, address, contact_info, capacity, registration_date, user_id)
                VALUES (%s, %s, %s, %s, CURDATE(), %s)
                """
                cursor.execute(insert_query, (org_name, address, contact_info, capacity, session['user_id']))
                connection.commit()
                flash("Organization created successfully!", "success")
                
                # Redirect to recipient menu to avoid form resubmission
                return redirect(url_for('recipient_menu'))
            except mysql.connector.Error as err:
                flash(f"Error creating organization: {err.msg}", "danger")
    except mysql.connector.Error as err:
        flash(f"Database error: {err.msg}", "danger")
    finally:
        cursor.close()  # Ensure the cursor is closed
        connection.close()  # Ensure the connection is closed

    # Render the organization creation form
    return render_template('recipient_create_organization.html')


# View Available Donations
@app.route('/recipient/view-available-donations', methods=['GET'])
def view_available_donations():
    """Fetch and display available donations for recipients."""
    if 'user_id' not in session or session.get('role') != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT d.donation_id, d.delivery_method, d.delivery_location,
               f.name AS food_item_name, f.expiration_date, f.category_name
        FROM Donations d
        LEFT JOIN FoodItems f ON d.donation_id = f.donation_id
        WHERE d.status = 'Pending' AND d.recipient_id IS NULL
        """
        cursor.execute(query)
        donations = cursor.fetchall()
        return render_template('recipient_view_available_donations.html', donations=donations)
    except mysql.connector.Error as err:
        flash(f"Error retrieving donations: {err}", "danger")
        return redirect(url_for('recipient_menu'))
    finally:
        connection.close()

# Request Donation
@app.route('/recipient/request-donation', methods=['GET', 'POST'])
def request_donation():
    """Allows a recipient to request a donation."""
    if 'user_id' not in session or session.get('role') != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        if request.method == 'POST':
            donation_id = request.form.get('donation_id')

            # Check if the user is associated with an organization
            cursor.execute("SELECT organization_id FROM Organization WHERE user_id = %s", (session['user_id'],))
            organization = cursor.fetchone()

            if not organization:
                flash("You are not associated with any organization. Please contact the administrator.", "danger")
                return redirect(url_for('recipient_menu'))

            organization_id = organization['organization_id']

            # Update the donation
            update_query = """
            UPDATE Donations
            SET recipient_id = %s
            WHERE donation_id = %s
              AND recipient_id IS NULL
              AND status = 'Pending'
            """
            cursor.execute(update_query, (organization_id, donation_id))
            connection.commit()

            if cursor.rowcount > 0:
                flash(f"Donation {donation_id} requested successfully!", "success")
            else:
                flash("Unable to request the donation. It may already be assigned.", "danger")
            return redirect(url_for('recipient_menu'))

        # Fetch available donations for display
        cursor.execute("SELECT donation_id, delivery_method, delivery_location FROM Donations WHERE recipient_id IS NULL AND status = 'Pending'")
        donations = cursor.fetchall()

    except mysql.connector.Error as err:
        flash(f"Error processing the request: {err}", "danger")
        donations = []
    finally:
        connection.close()

    return render_template('recipient_request_donation.html', donations=donations)

# View Request
@app.route('/recipient/view-my-requests', methods=['GET'])
def view_my_requests():
    """Allows a recipient to view their current donation requests."""
    if 'user_id' not in session or session.get('role') != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT d.donation_id, d.status, d.delivery_method, d.delivery_location, f.name AS food_item_name
        FROM Donations d
        LEFT JOIN FoodItems f ON d.donation_id = f.donation_id
        WHERE d.recipient_id = (
            SELECT organization_id FROM Organization WHERE user_id = %s
        ) AND d.status NOT IN ('Completed', 'Cancelled')
        """
        cursor.execute(query, (session['user_id'],))
        requests = cursor.fetchall()
    except mysql.connector.Error as err:
        flash(f"Error retrieving requests: {err}", "danger")
        requests = []
    finally:
        connection.close()

    return render_template('recipient_view_my_requests.html', requests=requests)

# View Request History
@app.route('/recipient/view-request-history', methods=['GET'])
def view_request_history():
    """Allows a recipient to view the history of their donation requests."""
    if 'user_id' not in session or session.get('role') != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT d.donation_id, d.status, d.delivery_method, d.delivery_location, f.name AS food_item_name
        FROM Donations d
        LEFT JOIN FoodItems f ON d.donation_id = f.donation_id
        WHERE d.recipient_id = (
            SELECT organization_id FROM Organization WHERE user_id = %s
        ) AND d.status IN ('Completed', 'Cancelled')
        """
        cursor.execute(query, (session['user_id'],))
        history = cursor.fetchall()
        return render_template('recipient_view_request_history.html', history=history)
    except mysql.connector.Error as err:
        flash(f"Error retrieving request history: {err}", "danger")
        return redirect(url_for('recipient_menu'))
    finally:
        connection.close()

# Update Donation
@app.route('/recipient/update-status', methods=['GET', 'POST'])
def update_status():
    """Allows donors and recipients to update donation status."""
    if 'user_id' not in session:
        flash("Unauthorized access. Please log in.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed. Please try again later.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            donation_id = request.form.get('donation_id')
            new_status = request.form.get('status')

            # Validate the new status
            if new_status not in ["Completed", "Cancelled"]:
                flash("Invalid status. Only 'Completed' or 'Cancelled' are allowed.", "danger")
                return render_template('recipient_update_status.html')

            # Update the donation status
            query = "UPDATE Donations SET status = %s WHERE donation_id = %s"
            cursor.execute(query, (new_status, donation_id))
            connection.commit()

            # Provide feedback to the user
            if cursor.rowcount > 0:
                flash(f"Donation {donation_id} status updated to '{new_status}' successfully!", "success")
            else:
                flash(f"No matching donation found for ID {donation_id}, or you are not authorized to update it.", "warning")

            return redirect(url_for('recipient_menu'))  # Redirect to recipient menu after processing
            
        return render_template('recipient_update_status.html')

    except mysql.connector.Error as err:
        flash(f"Error updating donation status: {err}", "danger")
    finally:
        connection.close()

#Recipient Nofication
@app.route('/recipient/notifications', methods=['GET'])
def view_recipient_notifications():
    """Displays notifications for the recipient."""
    if 'user_id' not in session or session.get('role') != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    connection = get_db_connection()
    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for('recipient_menu'))

    try:
        cursor = connection.cursor(dictionary=True)
        query = """
        SELECT message, created_at
        FROM Notifications
        WHERE organization_id = (
            SELECT organization_id 
            FROM Organization 
            WHERE user_id = %s
        )
        ORDER BY created_at DESC;
        """
        cursor.execute(query, (session['user_id'],))
        notifications = cursor.fetchall()

        return render_template('recipient_notifications.html', notifications=notifications)
    except mysql.connector.Error as err:
        flash(f"Error retrieving notifications: {err}", "danger")
        return redirect(url_for('recipient_menu'))
    finally:
        connection.close()

@app.route('/recipient/add-feedback', methods=['GET', 'POST'])
def add_feedback():
    """Allows recipients to add feedback for completed donations."""
    if 'user_id' not in session or session['role'] != 'Recipient':
        flash("Unauthorized access. Please log in as a recipient.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        donation_id = request.form['donation_id']
        feedback = request.form['feedback']
        rating = request.form['rating']

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Validate Donation
            query = """
            SELECT d.donation_id
            FROM Donations d
            JOIN Organization o ON d.recipient_id = o.organization_id
            WHERE d.donation_id = %s AND d.status = 'Completed' AND o.user_id = %s
            """
            cursor.execute(query, (donation_id, session['user_id']))
            donation = cursor.fetchone()

            if not donation:
                flash("Invalid Donation ID or the donation is not completed. Please try again.", "danger")
                return redirect(url_for('add_feedback'))

            # Insert Feedback
            feedback_query = """
            INSERT INTO DonationFeedback (donation_id, user_id, feedback, rating)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(feedback_query, (donation_id, session['user_id'], feedback, int(rating)))
            conn.commit()

            # Redirect to recipient menu with success message
            flash("Feedback submitted successfully!", "success")
            return redirect(url_for('recipient_menu'))
        
        except mysql.connector.Error as err:
            flash(f"Error submitting feedback: {err}", "danger")
            return redirect(url_for('add_feedback'))
        finally:
            conn.close()

    return render_template('recipient_add_feedback.html')

# Logout
@app.route('/logout', methods=['GET'])
def logout():
    """Logs out the current user."""
    if 'username' in session:
        flash(f"Goodbye, {session['username']}! You have been logged out.", "success")
    else:
        flash("You were not logged in.", "info")

    # Clear all session data
    session.clear()
    
    # Redirect to the login page
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)