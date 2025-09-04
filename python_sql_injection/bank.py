import psycopg2
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import tkinter.messagebox
import os

class Authentication:

    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry('425x185+700+300')

        self.auth = False

        self.root.title('Bank Balance')

        '''Make Window 10X10'''

        rows = 0
        while rows<10:
            self.root.rowconfigure(rows, weight=1)
            self.root.columnconfigure(rows, weight=1)
            rows+=1

        '''Username and Password'''

        self.frame = tk.LabelFrame(self.root, text='Login')
        self.frame.grid(row = 1,column = 1,columnspan=10,rowspan=10)

        tk.Label(self.frame, text = ' Username ').grid(row = 2, column = 1, sticky = W)
        self.username = tk.Entry(self.frame)
        self.username.grid(row = 2,column = 2)

        tk.Label(self.frame, text = ' Password ').grid(row = 5, column = 1, sticky = W)
        self.password = tk.Entry(self.frame ) #, show='*')
        self.password.grid(row = 5, column = 2)

        # Button

        ttk.Button(self.frame, text = 'LOGIN',command = self.login_user).grid(row=7,column=2)

        '''Message Display'''
        self.message = Label(text = '',fg = 'Red')
        self.message.grid(row=9,column=6)

        self.root.mainloop()


    def login_user(self):

        conn = psycopg2.connect("dbname=bankdb user=thaddeushunt")
        cur = conn.cursor()

        passW = self.password.get().strip()
        user = self.username.get().strip()
        query = "SELECT * FROM ACCOUNTS WHERE USERNAME = '"+user+ "' AND PASSWORD = '"+ passW +"' ;"

        try:
            cur.execute(query)
            result = cur.fetchall()
            if result:
                self.message['text'] = ''
                self.frame['text'] = result[0][0] + '\'s Balance'
                for widget in self.frame.winfo_children():
                    widget.destroy()
                tk.Label(self.frame, padx=50, pady= 50, text = 'Balance: $' +
                    str(result[0][2])).grid(row = 2, column = 1, sticky = W)
            else:
                self.message['text'] = 'Username or Password incorrect. Try again!'
        except Exception as error:
            messagebox.showerror('Error', error)

        conn.commit()
        conn.close()



auth = Authentication()
