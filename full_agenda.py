#[------------Imports------------]

from tkinter import ttk
from tkinter import *
import os
from typing import Container

from cryptography.hazmat.primitives.ciphers.modes import ECB

from crypto import Cryptograpy

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

    def __init__(self, agenda_screen, session_key, user_salt,user_id):
        """
        Constructor method for Agenda Class
        """
        self.wind = agenda_screen
        self.wind.title('Personal agenda')
        self.wind.resizable(False,False)
        self.session_key = session_key
        self.user_salt = user_salt

        self.user_id = int(user_id)

        self.iv = None

        self.salt_hmac = None

        self.agenda_icon_path = os.getcwd() + "\icons\lock_agenda.ico"

        self.wind.iconbitmap(self.agenda_icon_path)

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

        # Decrypting database and filling the rows

        self.decrypt_on_open()
        
        # Encrypt the database when the app is closed

        self.wind.protocol("WM_DELETE_WINDOW", self.encrypt_on_close)

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
        """
        Decrypts database contents on start of application
        """
        # Get the stored initialization vector and key for HMAC
        cryptostore = self.run_query(constants.QUERY_GET_CRYPTO)

        for row in cryptostore:
            #if row[0] == self.user_id: 
            self.iv = row[1]
            self.salt_hmac = row[2]

        # Get the stored hmac in the hmac table
        hmacstore = self.run_query(constants.QUERY_GET_HMAC)

        # Table HMACs to authenticate data in the next loop
        hmac_data = []
        for row in hmacstore:
            for element in row:
                if element is not None:
                    #print(element)
                    hmac_data.append(element) 


        # Get the stored encrypted contacts
        db_rows = self.run_query(constants.QUERY_GET)
        # Init a list to store UPDATE parameters (both encrypted and decrypted data)
        param_list = []
        # Iterator to traverse HMAC array
        i = 0
        # Store encrypted data and decrypted data separatedly (enc_data and dec_data)
        # in order to perform an update on the database
        for row in db_rows:
            dec_data = []
            enc_data = []
            for element in row:            
                enc_data.append(element)
                # Row ID is not encrypted, so it makes no sense to try to decrypt it
                if type(element) != int:
                    # Verifies the corresponding HMAC on every data
                    try:
                        crypto.verify_hmac( self.salt_hmac, bytes(element,"latin-1"), hmac_data[i] )
                        # Decrypted data
                        dec_data.append( crypto.symetric_decrypter( self.session_key, base64.b64decode(element), self.iv ).decode('latin-1') )
                    
                    except:
                        # If it isnt verified, it raises an advice
                        self.messsage["text"] = constants.ERR_DATA_NOT_VERIFIED
                        # Non Decrypted data
                        dec_data.append(element)

                    # Decrypted data
                    #dec_data.append(crypto.symetric_decrypter(self.session_key, base64.b64decode(element),self.iv).decode('latin-1'))
                    # update HMAC list iterator
                    i+=1
                else:
                    # directly append row ID to decrypted list
                    dec_data.append(element)

            param_list.append((
                                dec_data[1], dec_data[2],
                                dec_data[3], dec_data[4],
                                enc_data[1], enc_data[2], 
                                enc_data[3], enc_data[4]
                                ))
                                
        # UPDATE database by substituting encrypted data with decrypted data
        # Note: it is mandatory to exhaust db_rows before performing any other query: db_rows is a cursor
        #       pointing to the database, so the base is locked while db_rows is not totally read
        for i in range(len(param_list)):
            self.run_query(constants.QUERY_UPDATE, param_list[i])

        # Once contents are updated, load the information in the app
        self.get_contacts()
        
    def encrypt_on_close(self):
        """
        Encrypts database right before closing the app
        """
        # Generate two new values for encryption and authentication and update
        # the old ones in 'cryptostore' table, so next time decrypt_on_open
        # has the new values available

        size = self.run_query(constants.QUERY_GET)

        # Counters the number of cells of the table
        counter = 0
        # 4 columns is constant
        for i in size:
            counter+=4
        
        #IVSTORE

        parameters_ivstore = [[os.urandom(16) for j in range(4)] for i in range(counter)]
        
        self.run_query(constants.QUERY_DELETE_IVSTORE)
        self.run_query(constants.QUERY_INSERT_IVSTORE, parameters_ivstore)

        #SALT_HMAC_STORE

        parameters_salt_hmac_store = [[os.urandom(16) for j in range(4)] for i in range(counter)]
        
        self.run_query(constants.QUERY_DELETE_SALT_HMAC_STORE)
        self.run_query(constants.QUERY_INSERT_SALT_HMAC_STORE, parameters_salt_hmac_store)

        # Iterate throught each field of each contact and store separately ciphered data,
        # plain text and hmac of ciphered data in order to perform an update query on the database rows
        param_list = []
        param_hmac = []
        db_rows = self.run_query(constants.QUERY_GET)
        for row in db_rows:
            plain_data = []
            cipher_data = []
            hmac_data = []
            for element in row:            
                plain_data.append(element)
                #encrypterd_data = crypto.symetric_cipher(self.session_key, element, self.iv)
                
                #cipher_data.append(encrypterd_data)
                
                cipher_data.append( crypto.symetric_cipher(self.session_key, element, self.iv) )

            # Save parameters to load in agenda database
            parameters = (
                          base64.b64encode( cipher_data[1] ).decode("ascii"), 
                          base64.b64encode( cipher_data[2] ).decode("ascii"), 
                          base64.b64encode( cipher_data[3] ).decode("ascii"), 
                          base64.b64encode( cipher_data[4] ).decode("ascii"), 
                          plain_data[1],
                          plain_data[2],
                          plain_data[3], 
                          plain_data[4]
                        )
            
            # HMAC the parameters
            hmac_data.append( crypto.hmac( self.salt_hmac, bytes(parameters[0],"latin-1") ) )
            hmac_data.append( crypto.hmac( self.salt_hmac, bytes(parameters[1],"latin-1") ) )
            hmac_data.append( crypto.hmac( self.salt_hmac, bytes(parameters[2],"latin-1") ) )
            hmac_data.append( crypto.hmac( self.salt_hmac, bytes(parameters[3],"latin-1") ) )

            param_list.append(parameters)
            param_hmac.append(hmac_data)
            

        # UPDATE database by substituting encrypted data with decrypted data
        # Note: it is mandatory to exhaust db_rows before performing any other query: db_rows is a cursor
        #       pointing to the database, so the base is locked while db_rows is not totally read
        for i in range(len(param_list)):
            self.run_query(constants.QUERY_UPDATE, param_list[i])

        # UPDATE HMAC table with new Message Authentication Codes
        self.run_query(constants.QUERY_DELETE_HMAC)
        for i in range(len(param_hmac)):
            self.run_query(constants.QUERY_INSERT_HMAC, param_hmac[i])
        
        # Close app
        self.wind.destroy()


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

        self.login_icon_path = os.getcwd() + "\icons\login_icon.ico"
        self.main_login.iconbitmap(self.login_icon_path)

        self.salt = None
        
        #Check if exist any user
        
        with open("users.json", "r") as users_json:
            users_json = json.load(users_json)

        if users_json:        

            Label(text="Introduce your user", bg="blue", width="300", height="2", font=("Open Sans", 14)).pack()
            Label(text="").pack()

            Button(text="Login", height="2", width="30", command = self.login).pack()
            Label(text="").pack()
        
        else:

            Label(text="Register your user", bg="blue", width="300", height="2", font=("Open Sans", 14)).pack()
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

        self.register_screen.iconbitmap(self.login_icon_path)
        
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

        self.login_screen.iconbitmap(self.login_icon_path)

        Label(self.login_screen, text="Please enter details below to login").pack()
        Label(self.login_screen, text="").pack()
    
        self.userid_verify = StringVar()
        self.password_verify = StringVar()
    
        Label(self.login_screen, text="ID * ").pack()
        self.userid_login_entry = Entry(self.login_screen, textvariable=self.userid_verify)
        self.userid_login_entry.pack()
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
            username_info = base64.b64encode( crypto.hash_scrypt(self.username.get(), self.salt) ).decode("ascii")
            password_info = base64.b64encode( crypto.hash_scrypt(self.password.get(), self.salt) ).decode("ascii")

            with open("users.json", "r", encoding="utf-8") as users_file:
                users_data = json.load(users_file)

            contador = 0
            while str(contador) in users_data.keys():
                contador += 1

            contador = str(contador)
            users_data[contador] = {}
            users_data[contador]["user"] = username_info
            users_data[contador]["password"] = password_info
            users_data[contador]["salt"] = self.salt
            
            with open("users.json", "w", encoding="utf-8") as users_file:
                json.dump(users_data, users_file, indent=4)

            self.username_entry.delete(0, END)
            self.password_entry.delete(0, END)

            Label(self.register_screen, text="Registration Success", fg="green", font=("Open Sans", 14)).pack()
            Label(self.register_screen, text="Your ID is {}, keep it with you".format(contador), fg="green", font=("Open Sans", 14)).pack()
    
    def login_verify(self):
        """
        Auxiliar method of login that verifies the log-in checking the data files
        """
        
        with open("users.json", "r") as file1:
            verify = json.load(file1)
        
        userid = self.userid_verify.get()
        introduced_password = self.password_verify.get()
        self.userid_login_entry.delete(0, END)
        self.password_login_entry.delete(0, END)

        if userid not in verify.keys():
            self.id_not_found()
            return

        # Get salted password from entry in order to compare it with the stored one
        self.salt = verify[userid]["salt"]
        salted_password = base64.b64encode(crypto.hash_scrypt(introduced_password, self.salt)).decode("ascii")
        
        if verify[userid]["password"] == salted_password:
            session_key = crypto.pbkdf2hmac(introduced_password)
            self.login_sucess(session_key, userid)
        else:
            self.password_not_recognised()
            
    def login_sucess(self, session_key, userid):
        """
        Open the login success screen
        """
        # Delete Login Screen & MainLogin Screen
        self.login_screen.destroy()
        self.main_login.destroy()

        #Init App

        agenda_screen = Tk()
        Agenda(agenda_screen, session_key, self.salt, userid)
        agenda_screen.mainloop()
       
    
    def password_not_recognised(self):
        """
        Open the password not recognised screen
        """
        self.password_not_recog_screen = Toplevel(self.login_screen)
        self.password_not_recog_screen.title("password not recognised")
        self.password_not_recog_screen.geometry("150x100")
        self.password_not_recog_screen.resizable(False,False)

        self.password_not_recog_screen.iconbitmap(self.login_icon_path)
        
        Label(self.password_not_recog_screen, text="Invalid Password ").pack()
        Button(self.password_not_recog_screen, text="OK", command=self.delete_password_not_recognised).pack()
    
    def id_not_found(self):
        """
        Open the id not found screen
        """
        self.id_not_found_screen = Toplevel(self.login_screen)
        self.id_not_found_screen.title("Not found")
        self.id_not_found_screen.geometry("150x100")
        self.id_not_found_screen.resizable(False,False)

        self.id_not_found_screen.iconbitmap(self.login_icon_path)

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
    

if __name__== '__main__':
    """
    Initialize the Register & Log In screen
    """
    crypto = Cryptograpy()
    main_login = Tk()
    application = MainLogIn(main_login)

    main_login.mainloop()
    
