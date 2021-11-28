#[------------Imports------------]
import base64
import datetime
import json
import os
import sqlite3
import constants as cte

from cryptography.hazmat.primitives.ciphers.modes import ECB
from tkinter import ttk
from tkinter import *
from typing import Container
from crypto import Cryptograpy


#[------Agenda------]

class Agenda:
    """
    Class that represents the Agenda with all the funcionalities
    """
    db_name = cte.DB_NAME

    def __init__(self, agenda_screen, session_key, introduced_pw):
        """
        Constructor method for Agenda Class
        """
        self.cripto = Cryptograpy()
        self.wind = agenda_screen
        self.wind.title('Personal agenda')
        self.wind.resizable(False,False)
        self.agenda_icon_path = os.getcwd() + "\icons\lock_agenda.ico"
        try: self.wind.iconbitmap(self.agenda_icon_path)
        except: pass
        
        # Get useful data for symmetric cipher
        self.session_key = session_key
        self.introduced_pw = introduced_pw

        # Get AC1 certificate in order to verify it
        with open("AC1/ac1cert.pem", "rb") as ac1_certificate:
            ac1_certificate = self.cripto.load_certificate(ac1_certificate.read())
            
        try:
            self.cripto.verify_sign(ac1_certificate, None)
        except:
            pass
            #Añadir popup excepción

        
        # Get A certificate in order to verify it
        
        with open("A/Acert.pem", "rb") as a_certificate:
            a_certificate = self.cripto.load_certificate(a_certificate.read())
        try:
            self.cripto.verify_sign(a_certificate,"ac1_key")
        except:
            pass
            #Añadir popup excepción
        # Creates a new log
        self.log()

        ########## Creating a Frame Containter for the Agenda ###########
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
        ####################

        # Decrypt database and fill the rows
        self.decrypt_on_open()
        
        # Encrypt the database when the app is closed
        self.wind.protocol("WM_DELETE_WINDOW", self.encrypt_on_close)

    def validation(self, *params):
        """
        Validation method that verify if the params have len 0
        """
        ret = True
        for i in params:
            if len(i) == 0:
                ret = False
        return ret

    def add_contact(self):
        """
        Add a contact to the database
        """
        if self.validation(self.name.get(), self.telephone.get(), self.email.get(), self.description.get()):
            query = cte.QUERY_INSERT
            parameters = (self.name.get(), self.telephone.get(), self.email.get(), self.description.get())
            self.run_query(query, parameters)
            self.messsage["text"] = "Contact {} added successfully".format(self.name.get())
            self.name.delete(0, END)
            self.telephone.delete(0, END)
            self.email.delete(0, END)
            self.description.delete(0, END)
        else:
            self.messsage["text"] = cte.ERR_MISSING_PARAMS
        self.get_contacts()

    def delete_contact(self):
        """
        Delete a contact form the database
        """
        self.messsage["text"] = ""
        try:
            self.tree.item(self.tree.selection())["text"][0]
        except IndexError as error:
            self.messsage["text"] = cte.ERR_REC_NOT_SELECTED
            return
        self.messsage["text"] = ""
        name = self.tree.item(self.tree.selection())["text"]
        query = cte.QUERY_DELETE
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
            self.messsage["text"] = cte.ERR_REC_NOT_SELECTED
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
            query = cte.QUERY_UPDATE
            parameters = (new_name, new_telephone, new_email, new_description, name, old_telephone, old_email, old_description)
            self.run_query(query, parameters)
            self.edit_wind.destroy()
            self.messsage["text"] = "Contact {} updated successfully".format(name)
        else:
            self.messsage["text"] = cte.ERR_MISSING_PARAMS
            
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
        
        query = cte.QUERY_GET
        db_rows = self.run_query(query)
        j = self.run_query(query)
        # Filling data
        for row in db_rows:
            self.tree.insert("", 0, text = row[1], values = (row[2], row[3], row[4]))
            

    def log(self):
        """
        Writes a log sign by the Certificate Authority
        """
        # Create the log message (displays the time when the user logs in)
        now = datetime.datetime.now()
        time = now.strftime('%H:%M:%S on %A, %B the %dth, %Y')
        msg = f"Session started at {time}"
        
        # Prepare the digest to sign
        hashed_msg = self.cripto.hash(msg.encode("UTF-8"))
    
        # Get the private key and sign the hashed message
        private_key = self.cripto.load_private_key("A/Akey.pem",b"a_req_pw")
        serialize_key = self.cripto.serialize_key(private_key,"ac1_key")
        sign_for_msg = self.cripto.signing(serialize_key, hashed_msg)

        # Store the message
        with open ("session.log", "w") as logfile:
            logfile.write(sign_for_msg)
            
        # Store the sign
        with open ("sign.s", "w") as signfile:
            signfile.write(msg)
            
    def extract_from_table(self, cursor):
        """
        Auxiliar method to extract data from a table and return it in the form 
        of a list of lists
        """
        out_data = list()
        for row in cursor:
            out_data.append([])
            row = row[1:] #do not store row id
            for element in row:
                out_data[-1].append(element)
                
        return out_data

    def decrypt_on_open(self):
        """
        Decrypts database contents on start of application
        """
        # Retrieve last salt for derivation to use it in symmetric decryption
        db_cryptostore = self.run_query(cte.QUERY_GET_CRYPTO)
    
        #CRYPTOSTORE: get the salt and generate last session's key
        for i in db_cryptostore:
            salt_pbk = i[1]
        self.session_key = self.cripto.pbkdf2hmac(self.introduced_pw, salt_pbk)

        #IVSTORE: get the IVs used in encryption last time
        db_ivstore = self.run_query(cte.QUERY_GET_IVSTORE)
        ivstore =    self.extract_from_table(db_ivstore)

        #SALT_HMAC_STORE: get the HMAC salts used to authenticate data last time
        db_salt_hmac_store = self.run_query(cte.QUERY_GET_SALT_HMAC_STORE)
        salt_hmac_store =    self.extract_from_table(db_salt_hmac_store)

        #HMAC: get HMACs to authenticate data prior decrypting
        db_hmacstore = self.run_query(cte.QUERY_GET_HMAC)
        hmac_data =    self.extract_from_table(db_hmacstore)

        # Create a list to UPDATE agenda information (substitutes encrypted for decrypted data)
        param_list = list()
        # Get the stored encrypted contacts
        db_rows = self.run_query(cte.QUERY_GET)
        # Iterator to traverse HMAC array
        contador = 0
        for row in db_rows:
            # Store encrypted data and decrypted data separatedly (enc_data and dec_data)
            # in order to perform an update on the database
            dec_data = list()
            enc_data = list()
            row = row[1:] # do not store row id
            
            for element in row:           
                enc_data.append(element)
                # Verify the corresponding HMAC on every element
                try:
                    self.cripto.verify_hmac( salt_hmac_store[contador//4][contador%4], 
                                             bytes(element,"latin-1"), 
                                             hmac_data[contador//4][contador%4] 
                                            )
                    # Data element is authenticated, now decrypt it
                    dec_data.append( self.cripto.symetric_decrypter( self.session_key, 
                                                                     base64.b64decode(element), 
                                                                     ivstore[contador//4][contador%4] 
                                                                    ).decode('latin-1') )                    
                except:
                    # If it isn't verified, display a warning but don't stop working
                    self.messsage["text"] = cte.ERR_DATA_NOT_VERIFIED
                    # Do not decrypt non-authenticated data, just display it as it is to warn user
                    dec_data.append(element)

                # Update HMAC list iterator
                contador += 1 
                   
            # For each row, add row data to the list of parameters
            param_list.append( (dec_data[0], dec_data[1],
                                dec_data[2], dec_data[3],
                                enc_data[0], enc_data[1], 
                                enc_data[2], enc_data[3]) )
                                
        # UPDATE database by substituting encrypted data with decrypted data
        # Note: it is mandatory to exhaust db_rows before performing this query: db_rows is a cursor
        #       pointing to the database, so the base is locked while db_rows is not totally read
        for i in range(len(param_list)):
            self.run_query(cte.QUERY_UPDATE, param_list[i])

        # Once contents are updated in the table, load the information in the app
        self.get_contacts()
        
    def encrypt_on_close(self):
        """
        Encrypts database right before closing the app
        """
        # Generate two new values for encryption and authentication and update
        # the old ones in 'cryptostore' table, so next time decrypt_on_open
        # has the new values available
        
        # Uptade table cryptostore with a new random salt for PBKDF2HMAC
        self.run_query(cte.QUERY_DELETE_CRYPTO)
        salt_pbk_new = []
        salt_pbk_new.append([os.urandom(16)])
        for i in salt_pbk_new:
            self.run_query(cte.QUERT_INSERT_CRYPTO,i)
        
        self.session_key = self.cripto.pbkdf2hmac(self.introduced_pw, salt_pbk_new[0][0])

        # We need the number of rows of the agenda in order to create new tables
        # for the IVs, salts for HMAC
        size = self.run_query(cte.QUERY_GET)
        counter = 0
        for i in size: counter += 1
        
        #IVSTORE
        parameters_ivstore = []
        for i in range(counter):
            parameters_ivstore.append([])
            for j in range(4):
                parameters_ivstore[i].append(os.urandom(16))
        
        self.run_query(cte.QUERY_DELETE_IVSTORE)
        for i in parameters_ivstore:
            self.run_query(cte.QUERY_INSERT_IVSTORE, i)

        #SALT_HMAC_STORE
        parameters_salt_hmac_store = []
        for i in range(counter):
            parameters_salt_hmac_store.append([])
            for j in range(4):
                parameters_salt_hmac_store[i].append(os.urandom(16))
        
        self.run_query(cte.QUERY_DELETE_SALT_HMAC_STORE)
        for i in parameters_salt_hmac_store:
            self.run_query(cte.QUERY_INSERT_SALT_HMAC_STORE, i)

        # Iterate throught each field of each contact and store separately ciphered data,
        # plain text and hmac of ciphered data in order to perform an update query on the database rows
        param_list = list()
        param_hmac = list()
        contador = 0
        db_rows = self.run_query(cte.QUERY_GET)
        for row in db_rows:
            plain_data = list()
            cipher_data = list()
            hmac_data = list()
            row = row[1:] # do not store row id
            
            for element in row:
                # Store both plain data and encrypted data in orden to perform an update later
                plain_data.append(element)
                cipher_data.append( self.cripto.symetric_cipher(self.session_key, element, parameters_ivstore[contador//4][contador%4]))
                contador += 1

            # Save current row information to update it later
            parameters = (
                          base64.b64encode( cipher_data[0] ).decode("ascii"), 
                          base64.b64encode( cipher_data[1] ).decode("ascii"), 
                          base64.b64encode( cipher_data[2] ).decode("ascii"), 
                          base64.b64encode( cipher_data[3] ).decode("ascii"), 
                          plain_data[0],
                          plain_data[1],
                          plain_data[2], 
                          plain_data[3]
                        )
            
            # HMAC the parameters
            hmac_data.append( self.cripto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][0], bytes(parameters[0],"latin-1") ) )
            hmac_data.append( self.cripto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][1], bytes(parameters[1],"latin-1") ) )
            hmac_data.append( self.cripto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][2], bytes(parameters[2],"latin-1") ) )
            hmac_data.append( self.cripto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][3], bytes(parameters[3],"latin-1") ) )

            param_list.append(parameters)
            param_hmac.append(hmac_data)
            
            

        # UPDATE database by substituting encrypted data with decrypted data
        # Note: it is mandatory to exhaust db_rows before performing any other query: db_rows is a cursor
        #       pointing to the database, so the base is locked while db_rows is not totally read
        for i in range(len(param_list)):
            self.run_query(cte.QUERY_UPDATE, param_list[i])

        # UPDATE HMAC table with new Message Authentication Codes
        self.run_query(cte.QUERY_DELETE_HMAC)
        for i in range(len(param_hmac)):
            self.run_query(cte.QUERY_INSERT_HMAC, param_hmac[i])
        
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
            username_info = base64.b64encode( crypto.hash_scrypt(self.username.get(), self.salt) ).decode("ascii")
            password_info = base64.b64encode( crypto.hash_scrypt(self.password.get(), self.salt) ).decode("ascii")

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
        salted_password = base64.b64encode(crypto.hash_scrypt(
                                                        self.introduced_password, 
                                                        self.salt)
                                                             ).decode("ascii")
        salted_user = base64.b64encode(crypto.hash_scrypt(
                                                        self.name_verify.get(), 
                                                        self.salt)
                                                             ).decode("ascii")
        if verify["password"] == salted_password: #verify["user"] == salted_user and verify["password"] == salted_password:
            session_key = crypto.pbkdf2hmac(self.introduced_password, salt_pbk)
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

if __name__== '__main__':
    """
    Initialize the Register & Log In screen
    """
    crypto = Cryptograpy()
    main_login = Tk()
    application = MainLogIn(main_login)

    main_login.mainloop()

