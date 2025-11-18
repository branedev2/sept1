import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing Query: {query}")
    cursor.execute(query)
    result = cursor.fetchone()

    if result:
        print("Login successful!")

        
    else:
        print("Invalid credentials!")

user = input("Enter username: ")
pwd = input("Enter password: ")
login(user, pwd)
