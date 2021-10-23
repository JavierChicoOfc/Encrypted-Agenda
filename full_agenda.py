#[------------Imports------------]

from tkinter import ttk
from tkinter import *
import os

from cryptography.hazmat.primitives.ciphers.modes import ECB

from cripto import Criptograpy

import sqlite3

import base64

import json

import constants

import time

#[------------Classes------------]

#[------Agenda------]

class Agenda:
    """
    Class that represents the Agenda with all the funcionalities
    """
    db_name = constants.DB_NAME

    def __init__(self, agenda_screen, session_key):
        """
        Constructor method for Agenda Class
        """
        self.wind = agenda_screen
        self.wind.title('Personal agenda')
        self.wind.resizable(False,False)
        self.session_key = session_key

        self.agenda_icon_path = os.getcwd() + "\icons\lock_agenda.ico"

        #self.wind.iconbitmap(self.agenda_icon_path)

        # Creating a Frame Containter
        
        frame = LabelFrame(self.wind, text = 'Register a new contact')
        frame.grid(row = 0, column = 0, columnspan = 3, pady = 20)

        # Name Input

        Label(frame, text= 'Name:').grid(row = 1,column = 0)
        self.name = Entry(frame)
        self.name.focus
        self.name.grid(row = 1, column = 1)

        # Telephone input

        Label(frame, text= 'Telephone:').grid(row = 2,column = 0)
        self.telephone = Entry(frame)
        self.telephone.grid(row = 2,column = 1)

        # Email input

        Label(frame, text= 'Email:').grid(row = 3,column = 0)
        self.email = Entry(frame)
        self.email.grid(row = 3,column = 1)

        # Description input

        Label(frame, text= 'Description:').grid(row = 4,column = 0)
        self.description = Entry(frame)
        self.description.grid(row = 4,column = 1)

        # Button Add Contact

        ttk.Button(frame, text = 'Save contact', command = self.add_contact).grid(row = 5, columnspan = 2,sticky = W+E)

        # Output messasges

        self.messsage = Label( text= "", fg = "red")
        self.messsage.grid(row = 3, column = 0, columnspan = 2, sticky = W + E)

        # Table

        self.tree = ttk.Treeview(height = 10, columns=("#0","#1","#2"))
        self.tree.grid(row = 6, column = 0, columnspan = 2)
        self.tree.heading("#0", text = "Name", anchor = CENTER)
        self.tree.heading("#1", text = "Telephone", anchor = CENTER)
        self.tree.heading("#2", text = "Email", anchor = CENTER)
        self.tree.heading("#3", text = "Description", anchor = CENTER)

        # Buttons

        ttk.Button(text = "Edit", command = self.edit_contacts).grid(row = 7, column = 0, sticky = W+E)
        ttk.Button(text = "Delete", command = self.delete_contact).grid(row = 7, column = 1, sticky = W+E)
        # Filling the rows
        self.decrypt_on_open()
        #self.encrypt_on_close()

    def validation(self, *params):
        """
        Validation method that verify if the params have len 0
        """
        for i in params:
            if len(i) == 0:
                return False
        return True

    def add_contact(self):
        """
        Add a contact to the database
        """
        if self.validation(self.name.get(), self.telephone.get(), self.email.get(), self.description.get()):
            query = constants.QUERY_INSERT
            parameters = (self.name.get(), self.telephone.get(), self.email.get(), self.description.get())
            self.run_query(query, parameters)
            self.messsage["text"] = "Contact {} added successfully".format(self.name.get())
            self.name.delete(0, END)
            self.telephone.delete(0, END)
            self.email.delete(0, END)
            self.description.delete(0, END)
        else:
            self.messsage["text"] = constants.ERR_MISSING_PARAMS
        self.get_contacts()

    def delete_contact(self):
        """
        Delete a contact form the database
        """
        self.messsage["text"] = ""
        try:
            self.tree.item(self.tree.selection())["text"][0]
        except IndexError as error:
            self.messsage["text"] = constants.ERR_REC_NOT_SELECTED
            return
        self.messsage["text"] = ""
        name = self.tree.item(self.tree.selection())["text"]
        query = constants.QUERY_DELETE
        self.run_query(query, (name,))
        self.messsage["text"] = " Record {} deleted successfully".format(name)
        self.get_contacts()

    def edit_contacts(self):
        """
        Edit a contact from the database, establishing new parameters
        """
        self.messsage["text"] = ""
        try:
            self.tree.item(self.tree.selection())["text"][0]
        except IndexError as error:
            self.messsage["text"] = constants.ERR_REC_NOT_SELECTED
            return
        self.messsage["text"] = ""
        name            = self.tree.item(self.tree.selection())["text"]
        old_telephone   = self.tree.item(self.tree.selection())["values"][0]
        old_email       = self.tree.item(self.tree.selection())["values"][1]
        old_description = self.tree.item(self.tree.selection())["values"][2]

        self.edit_wind = Toplevel()
        self.edit_wind.title = "Edit contact"

        # Old name
        Label(self.edit_wind, text = "Old name: ").grid(row = 0, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = name), state = "readonly").grid(row = 0, column = 2)

        # New name
        Label(self.edit_wind, text = "New name: ").grid(row = 0, column = 3)
        new_name = Entry(self.edit_wind)
        new_name.grid(row = 0, column = 4)

        # Old telephone
        Label(self.edit_wind, text = "Old telephone: ").grid(row= 1, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_telephone), state = "readonly").grid(row = 1, column = 2)

        # Old email
        Label(self.edit_wind, text = "Old email: ").grid(row= 2, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_email), state = "readonly").grid(row = 2, column = 2)

        # Old description
        Label(self.edit_wind, text = "Old description: ").grid(row= 3, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_description), state = "readonly").grid(row = 3, column = 2)

        # New telephone 
        Label(self.edit_wind, text = "New telephone: ").grid(row = 1, column = 3)
        new_telephone = Entry(self.edit_wind)
        new_telephone.grid(row = 1, column = 4)

        # New email
        Label(self.edit_wind, text = "New email: ").grid(row = 2, column = 3)
        new_email = Entry(self.edit_wind)
        new_email.grid(row = 2, column = 4)

        # New description
        Label(self.edit_wind, text = "New description: ").grid(row = 3, column = 3)
        new_description = Entry(self.edit_wind)
        new_description.grid(row = 3, column = 4)

        Button(self.edit_wind, 
               text = "Update", 
               command = lambda: self.edit_records(new_name.get(), 
               					  name, 
               					  new_telephone.get(), 
               					  new_email.get(), 
               					  new_description.get(), 
               					  old_telephone, 
               					  old_email, 
               					  old_description)).grid(row = 4, column = 2,  sticky = W+E)
        

    def edit_records(self, new_name, name, new_telephone, new_email, new_description, old_telephone, old_email, old_description):
        """
        Auxiliar method of edit_contacts that run the query to edit the records of the database
        """
        if self.validation(new_name, new_telephone, new_email, new_description):
            query = constants.QUERY_UPDATE
            parameters = (new_name, new_telephone, new_email, new_description, name, old_telephone, old_email, old_description)
            self.run_query(query, parameters)
            self.edit_wind.destroy()
            self.messsage["text"] = "Contact {} updated successfully".format(name)
        else:
            self.messsage["text"] = constants.ERR_MISSING_PARAMS
            
        self.get_contacts()

    def run_query(self, query, parameters=()):
        """
        Run a specified query (parameter)
        """
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            result = cursor.execute(query, parameters)
            conn.commit()
        return result

    def get_contacts(self):
        """
        Auxiliar method that obtains the contacts from the database
        """
        # Cleaning table
        # store in 'records' the ids of the ttk element self.tree (nothing to do with db)
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)
        
        query = constants.QUERY_GET
        db_rows = self.run_query(query)
        j = self.run_query(query)
        # Filling data
        for row in db_rows:
            self.tree.insert("", 0, text = row[1], values = (row[2], row[3], row[4]))
            

    def decrypt_on_open(self):
        db_rows = self.run_query(constants.QUERY_GET)
        
        param_list = []
        for row in db_rows:
            plain_data = []
            cipher_data = []
            for element in row:            
                cipher_data.append(element)
                if type(element) != int:
                        plain_data.append( 
                              cripto.symetric_decrypter( 
                                                       self.session_key, 
                                                       base64.b64decode(element) 
                                                            ).decode('latin-1')
                                         )
                else:
                        plain_data.append(element)

            parameters = (
                          plain_data[1],
                          plain_data[2],
                          plain_data[3], 
                          plain_data[4],
                          cipher_data[1], 
                          cipher_data[2], 
                          cipher_data[3], 
                          cipher_data[4]
                        )
            param_list.append(parameters)
            
        for i in range(len(param_list)):
            self.run_query(constants.QUERY_UPDATE, param_list[i])
            
        self.get_contacts()
        
    def encrypt_on_close(self):
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)
            
        db_rows = self.run_query(constants.QUERY_GET)
        
        param_list = []
        for row in db_rows:
            plain_data = []
            cipher_data = []
            for element in row:            
                plain_data.append(element)
                cipher_data.append( cripto.symetric_cipher(self.session_key, element) )
                #cipher_data.append( cripto.hmac( self.session_key, cripto.symetric_cipher(self.session_key, element) ) )

            parameters = (
                          base64.b64encode(cipher_data[1]).decode("ascii"), 
                          base64.b64encode(cipher_data[2]).decode("ascii"), 
                          base64.b64encode(cipher_data[3]).decode("ascii"), 
                          base64.b64encode(cipher_data[4]).decode("ascii"), 
                          plain_data[1],
                          plain_data[2],
                          plain_data[3], 
                          plain_data[4]
                        )

            param_list.append(parameters)
        for i in range(len(param_list)):
            self.run_query(constants.QUERY_UPDATE, param_list[i])
        self.get_contacts()


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
        self.main_login.geometry("300x250")
        self.main_login.title("Account Login")
        self.main_login.resizable(False,False)

        self.login_icon_path = os.getcwd() + "\icons\login_icon.ico"
        #self.main_login.iconbitmap(self.login_icon_path)
        
        
        Label(text="Select Your Choice", bg="blue", width="300", height="2", font=("Open Sans", 14)).pack()
        Label(text="").pack()
        Button(text="Login", height="2", width="30", command = self.login).pack()
        Label(text="").pack()
        Button(text="Register", height="2", width="30", command=self.register).pack()
    
    def register(self):
        """
        Open the register screen to register a new user
        """
        self.register_screen = Toplevel(self.main_login)
        self.register_screen.title("Register")
        self.register_screen.geometry("300x250")
        self.register_screen.resizable(False,False)

        #self.register_screen.iconbitmap(self.login_icon_path)
        
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

        #self.login_screen.iconbitmap(self.login_icon_path)

        Label(self.login_screen, text="Please enter details below to login").pack()
        Label(self.login_screen, text="").pack()
    
        self.username_verify = StringVar()
        self.password_verify = StringVar()
    
        Label(self.login_screen, text="Username * ").pack()
        self.username_login_entry = Entry(self.login_screen, textvariable=self.username_verify)
        self.username_login_entry.pack()
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
            username_info = base64.b64encode(cripto.hash_scrypt(self.username.get())).decode("ascii")
            password_info = base64.b64encode(cripto.hash_scrypt(self.password.get())).decode("ascii")

            with open("users.json", "r", encoding="utf-8") as users_file:
                users_data = json.load(users_file)

            # Fix duplicated users

            if username_info in users_data.keys():
                Label(self.register_screen, text="User already taken", fg="red", font=("Open Sans", 14)).pack()
                return

            users_data[username_info] = password_info

            with open("users.json", "w", encoding="utf-8") as users_file:
                json.dump(users_data, users_file, indent=4)

            self.username_entry.delete(0, END)
            self.password_entry.delete(0, END)

            Label(self.register_screen, text="Registration Success", fg="green", font=("Open Sans", 14)).pack()
    
    def login_verify(self):
        """
        Auxiliar method of login that verifies the log-in checking the data files
        """
        session_key = cripto.pbkdf2hmac(self.password_verify.get())
        username1 = base64.b64encode(cripto.hash_scrypt(self.username_verify.get())).decode("ascii")
        password1 = base64.b64encode(cripto.hash_scrypt(self.password_verify.get())).decode("ascii")

        self.username_login_entry.delete(0, END)
        self.password_login_entry.delete(0, END)
        
        file1 = open("users.json", "r")
        verify = json.load(file1)
        file1.close()

        password_not_recognised = user_not_found = False

        for user in verify.keys():
            if username1 == user:
                if verify[user] == password1:
                    self.login_sucess(session_key)
                    user_not_found = False  
                    password_not_recognised = False
                else:
                    password_not_recognised = True   
            else:
                user_not_found = True


        if password_not_recognised:
            self.password_not_recognised()

        if user_not_found and password_not_recognised == False:
            self.user_not_found()

    def login_sucess(self, session_key):
        """
        Open the login success screen
        """
        """
        self.login_success_screen = Toplevel(self.login_screen)
        self.login_success_screen.title("Success")
        self.login_success_screen.geometry("150x100")
        self.login_success_screen.resizable(False,False)
        
        #self.login_success_screen.iconbitmap(self.login_icon_path)
        
        Label(self.login_success_screen, text="Login Success").pack()
        Button(self.login_success_screen, text="OK", command=self.delete_login_success).pack()
        """
        # Delete Login Screen & MainLogin Screen
        self.login_screen.destroy()
        self.main_login.destroy()

        #Init App

        agenda_screen = Tk()
        Agenda(agenda_screen, session_key)
        agenda_screen.mainloop()
       
    
    def password_not_recognised(self):
        """
        Open the password not recognised screen
        """
        self.password_not_recog_screen = Toplevel(self.login_screen)
        self.password_not_recog_screen.title("Success")
        self.password_not_recog_screen.geometry("150x100")
        self.password_not_recog_screen.resizable(False,False)

        #self.password_not_recog_screen.iconbitmap(self.login_icon_path)
        
        Label(self.password_not_recog_screen, text="Invalid Password ").pack()
        Button(self.password_not_recog_screen, text="OK", command=self.delete_password_not_recognised).pack()
    
    def user_not_found(self):
        """
        Open the user not found screen
        """
        self.user_not_found_screen = Toplevel(self.login_screen)
        self.user_not_found_screen.title("Success")
        self.user_not_found_screen.geometry("150x100")
        self.user_not_found_screen.resizable(False,False)

        #self.user_not_found_screen.iconbitmap(self.login_icon_path)

        Label(self.user_not_found_screen, text="User Not Found").pack()
        Button(self.user_not_found_screen, text="OK", command=self.delete_user_not_found_screen).pack()
    
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
    
    
    def delete_user_not_found_screen(self):
        """
        Deletes the user not found screen
        """            
        self.user_not_found_screen.destroy()
    

if __name__== '__main__':
    """
    Initialize the Register & Log In screen
    """
    cripto = Criptograpy()
    main_login = Tk()
    application = MainLogIn(main_login)

    main_login.mainloop()
    
