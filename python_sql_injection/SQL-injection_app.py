# app.py
import sqlite3
from flask import Flask, render_template, request, g, flash, redirect, url_for # type: ignore

app = Flask(__name__)
# Set a secret key for flashing messages (important for Flask)
app.secret_key = 'your_very_secret_key_here' # Replace with a strong, random key in a real app

DATABASE = 'database.db'

def get_db():
    """Establishes a database connection or returns the existing one."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # This allows access to columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    print("Database initialized.")

@app.route('/')
def index():
    """Renders the main login page."""
    return render_template('login.html')

@app.route('/login_vulnerable', methods=['POST'])
def login_vulnerable():
    """
    Handles login attempts using a SQL query vulnerable to injection.
    DO NOT USE THIS IN PRODUCTION. This is purely for demonstration.
    """
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    cursor = db.cursor()

    # !!! VULNERABLE SQL QUERY !!!
    # User input is directly concatenated into the SQL string.
    # This allows an attacker to inject malicious SQL code.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing vulnerable query: {query}") # For demonstration purposes

    try:
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            flash(f'Welcome, {user["username"]}! You are logged in (via vulnerable path).', 'success')
            return redirect(url_for('dashboard')) # Redirect to a dummy dashboard
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('index'))
    except sqlite3.Error as e:
        flash(f'An error occurred: {e}', 'error')
        print(f"Database error: {e}")
        return redirect(url_for('index'))

@app.route('/login_secure', methods=['POST'])
def login_secure():
    """
    Handles login attempts using a secure, parameterized SQL query.
    This prevents SQL injection.
    """
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    cursor = db.cursor()

    # !!! SECURE SQL QUERY using parameterized query !!!
    # Parameters are passed separately from the SQL string.
    # The database driver handles escaping, preventing injection.
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"Executing secure query with params: {username}, {password}") # For demonstration purposes

    try:
        cursor.execute(query, (username, password)) # Pass parameters as a tuple
        user = cursor.fetchone()

        if user:
            flash(f'Welcome, {user["username"]}! You are logged in securely.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('index'))
    except sqlite3.Error as e:
        flash(f'An error occurred: {e}', 'error')
        print(f"Database error: {e}")
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """A simple dashboard page for logged-in users."""
    return render_template('dashboard.html')

if __name__ == '__main__':
    init_db() # Initialize the database
    app.run(debug=True)
