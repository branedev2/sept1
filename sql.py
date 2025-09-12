import sqlite3
import mysql.connector
import psycopg2
from flask import Flask, request, g
import pymysql
from sqlalchemy import create_engine, text
import cx_Oracle
import os
from werkzeug.datastructures import ImmutableMultiDict
from django.http import HttpRequest, HttpResponse
from django.db import connection
import pymongo
from fastapi import FastAPI, Query, Form
from starlette.requests import Request
import subprocess

app = Flask(__name__)
fastapi_app = FastAPI()

# True Positive Examples (Vulnerable/Insecure Code)

@app.route('/bad_case_1')
def bad_case_1():
    # Basic SQL injection vulnerability with string concatenation
    user_id = request.args.get('id')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: python-sql-injection-ide
    cursor.execute(query)  # Vulnerable: user_id is directly concatenated
    results = cursor.fetchall()
    conn.close()
    return str(results)

@app.route('/bad_case_2', methods=['POST'])
def bad_case_2():
    # SQL injection in MySQL with string formatting
    username = request.form['username']
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    # ruleid: python-sql-injection-ide
    cursor.execute(query)  # Vulnerable: username is inserted via string formatting
    results = cursor.fetchall()
    conn.close()
    return str(results)

@app.route('/bad_case_3')
def bad_case_3():
    # SQL injection with multiple parameters and f-strings
    user_id = request.args.get('id')
    status = request.args.get('status')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM orders WHERE user_id = {user_id} AND status = '{status}'"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)  # Vulnerable: both parameters are inserted via f-string
    results = cursor.fetchall()
    conn.close()
    return str(results)

@app.route('/bad_case_4')
def bad_case_4():
    # SQL injection in PostgreSQL with string concatenation in a complex query
    product_id = request.args.get('product_id')
    category = request.args.get('category')
    conn = psycopg2.connect(host="localhost", database="testdb", user="postgres", password="password")
    cursor = conn.cursor()
    query = "SELECT p.name, p.price FROM products p JOIN categories c ON p.category_id = c.id WHERE p.id = " + product_id + " AND c.name = '" + category + "'"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)  # Vulnerable: both parameters are directly concatenated
    results = cursor.fetchall()
    conn.close()
    return str(results)

@app.route('/bad_case_5', methods=['POST'])
def bad_case_5():
    # SQL injection with conditional logic but still vulnerable
    user_input = request.form.get('search', '')
    sort_order = request.form.get('sort', 'asc')

    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    if sort_order.lower() not in ['asc', 'desc']:
        sort_order = 'asc'  # Attempt to sanitize, but still vulnerable

    query = "SELECT * FROM products WHERE name LIKE '%" + user_input + "%' ORDER BY price " + sort_order
    # ruleid: python-sql-injection-ide
    cursor.execute(query)  # Vulnerable: user_input is directly concatenated
    results = cursor.fetchall()
    conn.close()
    return str(results)