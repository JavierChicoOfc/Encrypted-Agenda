from full_agenda import Agenda
from typing import Container
from tkinter import ttk
from tkinter import *
from typing import Container

from crypto import Cryptograpy

from cryptography.hazmat.primitives.ciphers.modes import ECB

import sqlite3

import base64

import json

import os
import constants

import datetime

#[------MainLogIn------]
      
class MainLogIn:
    """
    Class that represents the Register & LogIn section with all the funcionalities
    """

    def __init__(self,main_login):
        """
        Constructor method for the MainLogin class
        """
        self.main_login = main_login
        self.main_login.geometry("300x150")
        self.main_login.title("Account Login")
        self.main_login.resizable(False,False)
        
        self.cripto = Cryptograpy()

        self.login_icon_path = os.getcwd() + "\icons\login_icon.ico"
        try: self.main_login.iconbitmap(self.login_icon_path)
        except: pass

        self.salt = None
        
        # Check if an user already exists
        with open("users.json", "r") as users_json:
            users_json = json.load(users_json)

        # If exists, log-in
        if users_json:        

            Label(text="Introduce your user", bg="blue", width="300", height="2", font=("Open Sans", 14)).pack()
            Label(text="").pack()

            Button(text="Login", height="2", width="30", command = self.login).pack()
            Label(text="").pack()
        
        # Else, register
        else:


            self.main_login.geometry("300x200")

            Label(text="Register your user", bg="blue", width="300", height="2", font=("Open Sans", 14)).pack()
            Label(text="").pack()

            Button(text="Register", height="2", width="30", command=self.register).pack()
        
            Button(text="Login", height="2", width="30", command = self.login).pack()
            Label(text="").pack()
           
    
    def register(self):
        """
        Open the register screen to register a new user
        """
        self.register_screen = Toplevel(self.main_login)
        self.register_screen.title("Register")
        self.register_screen.geometry("300x250")
        self.register_screen.resizable(False,False)

        try: self.register_screen.iconbitmap(self.login_icon_path)
        except: pass
        
        self.username = StringVar()
        self.password = StringVar()

        Label(self.register_screen, text="Please enter details below", bg="blue").pack()
        Label(self.register_screen, text="").pack()
        username_lable = Label(self.register_screen, text="Username * ")
        username_lable.pack()
        self.username_entry = Entry(self.register_screen, textvariable=self.username)
        self.username_entry.pack()

        self.password_lable = Label(self.register_screen, text="Password * ")
        self.password_lable.pack()
        self.password_entry = Entry(self.register_screen, textvariable=self.password, show='*')
        self.password_entry.pack()
        Label(self.register_screen, text="").pack()
        Button(self.register_screen, text="Register", width=10, height=1, bg="blue", command = self.register_user).pack()
    
    def login(self):
        """
        Open the log-in screen to access the agenda
        """
        self.login_screen = Toplevel(self.main_login)
        self.login_screen.title("Login")
        self.login_screen.geometry("300x250")
        self.login_screen.resizable(False,False)

        try: self.login_screen.iconbitmap(self.login_icon_path)
        except: pass

        Label(self.login_screen, text="Please enter details below to login").pack()
        Label(self.login_screen, text="").pack()
    
        self.name_verify = StringVar()
        self.password_verify = StringVar()
    
        Label(self.login_screen, text="Nombre * ").pack()
        self.name_login_entry = Entry(self.login_screen, textvariable=self.name_verify)
        self.name_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Label(self.login_screen, text="Password * ").pack()
        self.password_login_entry = Entry(self.login_screen, textvariable=self.password_verify, show= '*')
        self.password_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Button(self.login_screen, text="Login", width=10, height=1, command = self.login_verify).pack()
    
    def register_user(self):
        """
        Auxiliar method of register that write a new file with the new user´s data
        """

        if self.username.get() == "" or self.password.get() == "":
            Label(self.register_screen, text="User or password is invalid", fg="red", font=("Open Sans", 14)).pack()

        else:
            self.salt = base64.b64encode( os.urandom(16) ).decode("ascii")
            username_info = base64.b64encode( self.cripto.hash_scrypt(self.username.get(), self.salt) ).decode("ascii")
            password_info = base64.b64encode( self.cripto.hash_scrypt(self.password.get(), self.salt) ).decode("ascii")

            with open("users.json", "r", encoding="utf-8") as users_file:
                users_data = json.load(users_file)


            users_data = {}
            users_data["user"] = username_info
            users_data["password"] = password_info
            users_data["salt"] = self.salt
            
            with open("users.json", "w", encoding="utf-8") as users_file:
                json.dump(users_data, users_file, indent=4)

            self.username_entry.delete(0, END)
            self.password_entry.delete(0, END)

            Label(self.register_screen, text="Registration Success", fg="green", font=("Open Sans", 14)).pack()
    
    def login_verify(self):
        """
        Auxiliar method of login that verifies the log-in checking the data files
        """
        
        with open("users.json", "r") as file1:
            verify = json.load(file1)
        

        self.introduced_password = self.password_verify.get()
        self.name_login_entry.delete(0, END)
        self.password_login_entry.delete(0, END)

        salt_pbk = os.urandom(16)


        # Get salted user and password from entry in order to compare it with 
        # the stored ones
        self.salt = verify["salt"]
        salted_password = base64.b64encode(self.cripto.hash_scrypt(
                                                        self.introduced_password, 
                                                        self.salt)
                                                             ).decode("ascii")
        salted_user = base64.b64encode(self.cripto.hash_scrypt(
                                                        self.name_verify.get(), 
                                                        self.salt)
                                                             ).decode("ascii")
        if verify["password"] == salted_password: #verify["user"] == salted_user and verify["password"] == salted_password:
            session_key = self.cripto.pbkdf2hmac(self.introduced_password, salt_pbk)
            self.login_sucess(session_key)
        else:
            self.not_recognised()
            
    def login_sucess(self, session_key):
        """
        Open the login success screen
        """
        # Delete Login Screen & MainLogin Screen
        self.login_screen.destroy()
        self.main_login.destroy()

        #Init App

        agenda_screen = Tk()
        Agenda(agenda_screen, session_key, self.introduced_password)
        agenda_screen.mainloop()
       
    
    def not_recognised(self):
        """
        Open the password not recognised screen
        """
        self.password_not_recog_screen = Toplevel(self.login_screen)
        self.password_not_recog_screen.title("User or password not recognised")
        self.password_not_recog_screen.geometry("150x100")
        self.password_not_recog_screen.resizable(False,False)

        try: self.password_not_recog_screen.iconbitmap(self.login_icon_path)
        except: pass
        
        Label(self.password_not_recog_screen, text="Invalid User or Password ").pack()
        Button(self.password_not_recog_screen, text="OK", command=self.delete_password_not_recognised).pack()
    
    def id_not_found(self):
        """
        Open the id not found screen
        """
        self.id_not_found_screen = Toplevel(self.login_screen)
        self.id_not_found_screen.title("Not found")
        self.id_not_found_screen.geometry("150x100")
        self.id_not_found_screen.resizable(False,False)

        try: self.id_not_found_screen.iconbitmap(self.login_icon_path)
        except: pass

        Label(self.id_not_found_screen, text="Invalid ID ", fg="red", font=("Open Sans", 14)).pack()
        Button(self.id_not_found_screen, text="OK", command=self.delete_id_not_found_screen).pack()

    def delete_login_success(self):
        """
        Deletes the login screen
        """
        self.login_success_screen.destroy()
    
    
    def delete_password_not_recognised(self):
        """
        Deletes the password not recognised screen
        """        
        self.password_not_recog_screen.destroy()
    
    
    def delete_id_not_found_screen(self):
        """
        Deletes the user not found screen
        """            
        self.id_not_found_screen.destroy()
   
