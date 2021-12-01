#[------------Imports------------]
import base64
import datetime
import os
import sqlite3
import constants as cte

from tkinter import ttk
from tkinter import *
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
        self.crypto = Cryptograpy()
        self.wind = agenda_screen
        self.wind.title('Personal agenda')
        self.wind.resizable(False,False)
        self.agenda_icon_path = os.getcwd() + "\icons\lock_agenda.ico"
        try: self.wind.iconbitmap(self.agenda_icon_path)
        except: pass
        
        # Get useful data for symmetric cipher
        self.session_key = session_key
        self.introduced_pw = introduced_pw

        #[--------Digital Sign section--------] 
       
        # Verifies the certificates
        self.verify_certificates()

        # Verifies the certificates
        self.verify_sign()

        # Creates a new log and signs it
        self.log()

        #[--------Creating a Frame Containter for the Agenda--------]

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
        
        #[--------On open--------]

        # Decrypt database and fill the rows
        self.decrypt_on_open()
        
        #[--------On close--------]
        
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
        # Filling data
        for row in db_rows:
            self.tree.insert("", 0, text = row[1], values = (row[2], row[3], row[4]))
            
    def verify_certificates(self):
        """
        Verificates all the certificates
        """    
        # Get AC1 certificate in order to verify it    
        with open("AC1/ac1cert.pem", "rb") as ac1_certificate:
            ac1_certificate = self.crypto.load_certificate(ac1_certificate.read())
        try:
            self.crypto.verify_certificate(ac1_certificate, ac1_certificate.public_key())
        except:
            self.certificate_not_verified("Ac1")

        # Get A certificate in order to verify it
        with open("A/Acert.pem", "rb") as a_certificate:
            a_certificate = self.crypto.load_certificate(a_certificate.read())
        try:
            self.crypto.verify_certificate(a_certificate, ac1_certificate.public_key())
        except:
            self.certificate_not_verified("A")

    def certificate_not_verified(self,certificate_name):
        """
        Manage the error that occurs when a certificate is invalid
        """
        self.certificate_not_verified_screen = Toplevel(self.wind)
        self.certificate_not_verified_screen.title(f"{certificate_name} not verified ")
        self.certificate_not_verified_screen.geometry("500x75")
        self.certificate_not_verified_screen.resizable(False, False)
        Label(self.certificate_not_verified_screen, text=f"{certificate_name} not verified ", fg="red", font=("Open Sans", 14)).pack()
        Button(self.certificate_not_verified_screen, text="OK", command=self.delete_certificate_not_verified).pack()

    def delete_certificate_not_verified(self):
        """
        Destroy the certificate_not_verified window
        """
        self.certificate_not_verified_screen.destroy()
    
    def verify_sign(self):
        """
        Verifies a given sign
        """
        try:
            with open ("session.log", "r") as logfile:
                msg = logfile.read()
        except:
            return
        
        hashed_msg = self.crypto.hash(msg.encode("UTF-8"))

        try:
            with open ("sign.sig", "r") as signfile:
                sign = bytes(signfile.read(),"latin-1")
        except:
            return
        
        with open("A\Acert.pem","rb") as public_key:
            key = self.crypto.load_certificate(public_key.read())

        
        try:
            self.crypto.verify_sign(key,sign,bytes(hashed_msg,"latin-1"))
        except:
            self.sign_not_verified()

    def sign_not_verified(self):
        """
        Manage the error that occurs when a certificate is invalid
        """
        self.sign_not_verified_screen = Toplevel(self.wind)
        self.sign_not_verified_screen.title("Sign is not verified ")
        self.sign_not_verified_screen.geometry("500x75")
        self.sign_not_verified_screen.resizable(False, False)
        Label(self.sign_not_verified_screen, text="Sign is not verified ", fg="red", font=("Open Sans", 14)).pack()
        Button(self.sign_not_verified_screen, text="OK", command=self.delete_sign_not_verified).pack()

    def delete_sign_not_verified(self):
        """
        Destroy the certificate_not_verified window
        """
        self.sign_not_verified_screen.destroy()

    def log(self):
        """
        Writes a log sign by the Certificate Authority
        """
        # Create the log message (displays the time when the user logs in)
        now = datetime.datetime.now()
        time = now.strftime('%H:%M:%S on %A, %B the %dth, %Y')
        msg = f"Session started at {time}"
        
        # Prepare the digest to sign
        hashed_msg = self.crypto.hash(msg.encode("UTF-8"))
    
        # Get the private key and sign the hashed message
        private_key = self.crypto.load_private_key("A/Akey.pem")
    
        sign_for_msg = self.crypto.signing(private_key, bytes(hashed_msg,"latin-1"))

        # Store the message
        with open ("session.log", "w") as logfile:
            logfile.write(msg)
            
        # Store the sign
        with open ("sign.sig", "w") as signfile:
            signfile.write(base64.b64encode(sign_for_msg).decode("ascii"))

            
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
        self.session_key = self.crypto.pbkdf2hmac(self.introduced_pw, salt_pbk)

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
                    self.crypto.verify_hmac( salt_hmac_store[contador//4][contador%4], 
                                             bytes(element,"latin-1"), 
                                             hmac_data[contador//4][contador%4] 
                                            )
                    # Data element is authenticated, now decrypt it
                    dec_data.append( self.crypto.symetric_decrypter( self.session_key, 
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
        
        self.session_key = self.crypto.pbkdf2hmac(self.introduced_pw, salt_pbk_new[0][0])

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
                cipher_data.append( self.crypto.symetric_cipher(self.session_key, element, parameters_ivstore[contador//4][contador%4]))
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
            hmac_data.append( self.crypto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][0], bytes(parameters[0],"latin-1") ) )
            hmac_data.append( self.crypto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][1], bytes(parameters[1],"latin-1") ) )
            hmac_data.append( self.crypto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][2], bytes(parameters[2],"latin-1") ) )
            hmac_data.append( self.crypto.hmac( parameters_salt_hmac_store[(contador-len(row))//4][3], bytes(parameters[3],"latin-1") ) )

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
        

