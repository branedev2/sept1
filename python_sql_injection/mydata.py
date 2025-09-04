import mysql.connector
import HTML

mydatabase = mysql.connector.connect(
    host="localhost",
    user="root",
    password="SQL_wardwird0$",
    database="user"
)

# Login is injectable with SQL Injection
def login_checker_injectable(username, password):
    my_cursor = mydatabase.cursor()
    my_cursor.execute("SELECT * FROM user_authentication_2 WHERE username = '" + username + "' AND password = '" + password + "';")
    my_result = my_cursor.fetchall()
    print("Length of Query result: " + str(len(my_result)))
    if len(my_result) > 0:
        return True
    my_cursor.close()


# Login is safe from SQL Injection
def login_checker_safe_1(username, password):
    my_cursor = mydatabase.cursor()
    my_cursor.execute("SELECT * FROM user_authentication_2")
    my_result = my_cursor.fetchall()
    function = False
    for data in my_result:
        for index in data:
            if index == username:
                pw = data[2]
                if password == pw:
                    function = True
                else:
                    continue
    my_cursor.close()
    return function



def register(username, password):
    my_cursor = mydatabase.cursor()
    registry = "INSERT INTO user_authentication_2 (username, password) VALUES (%s, %s)"
    data = (username, password)
    my_cursor.execute(registry, data)
    mydatabase.commit()
    my_cursor.close()


def list_converter():
    my_cursor = mydatabase.cursor()
    my_cursor.execute('SELECT * FROM user_authentication_2')
    my_table = my_cursor.fetchall()
    table_data = []
    for row in my_table:
        table_data.append(row)
    html_code = HTML.table(table_data, header_row=['User_ID', 'Username', 'Password'])
    my_cursor.close()
    return html_code
