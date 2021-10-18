#[------------Imports------------]

from tkinter import ttk
from tkinter import *
import os

from cryptography.hazmat.primitives.ciphers.modes import ECB

from cripto import Criptograpy

import sqlite3

import base64

import constants

# Path



#[------------Classes------------]

#[------Agenda------]

class Agenda:
    """
    Class that represents the Agenda with all the funcionalities
    """
    db_name = constants.DB_NAME

    def __init__(self,agenda_screen):
        """
        Constructor method for Agenda Class
        """
        self.wind = agenda_screen
        self.wind.title('Personal agenda')
        self.wind.resizable(False,False)

        agenda_icon_path=path+"\icons\lock_agenda.ico"
        if os.name == "nt": self.wind.iconbitmap(agenda_icon_path)

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
        self.get_contacts()

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
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)
        query = constants.QUERY_GET
        db_rows = self.run_query(query)

        # Filling data
        for row in db_rows:
            self.tree.insert("", 0, text = row[1], values = (row[2], row[3], row[4]))

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
        self.contador = 0
        
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

        """
        login_icon_path=path+"\icons\login_icon.ico"
        self.password_not_recog_screen.iconbitmap(login_icon_path)
        """
        
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

        """
        login_icon_path=path+"\icons\login_icon.ico"
        self.password_not_recog_screen.iconbitmap(login_icon_path)
        """

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
        username_info = base64.b64encode(cripto.hash(self.username.get())).decode("ascii")
        password_info = base64.b64encode(cripto.hash(self.password.get())).decode("ascii")

        print ("USERNAME INFO",username_info)
        self.contador+=1
        filename = "User"+str(self.contador)

        file = open(filename, "w",encoding = "latin-1")
        file.write(username_info + "\n")
        file.write(password_info)
        file.close()
    
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
    
        Label(self.register_screen, text="Registration Success", fg="green", font=("Open Sans", 14)).pack()
    
    def login_verify(self):
        """
        Auxiliar method of login that verifies the log-in checking the data files
        """
        username1 = self.username_verify.get()
        password1 = self.password_verify.get()
        self.username_login_entry.delete(0, END)
        self.password_login_entry.delete(0, END)
    
        list_of_files = os.listdir()

        if username1 in list_of_files:
            file1 = open(username1, "r")
            verify = file1.read().splitlines()
            if password1 in verify:
                self.login_sucess()
    
            else:
                self.password_not_recognised()
    
        else:
            self.user_not_found()
    
    def login_sucess(self):
        """
        Open the login success screen
        """
        self.login_success_screen = Toplevel(self.login_screen)
        self.login_success_screen.title("Success")
        self.login_success_screen.geometry("150x100")
        self.login_success_screen.resizable(False,False)
        
        """
        login_icon_path=path+"\icons\login_icon.ico"
        self.password_not_recog_screen.iconbitmap(login_icon_path)
        """

        Label(self.login_success_screen, text="Login Success").pack()
        Button(self.login_success_screen, text="OK", command=self.delete_login_success).pack()
        
        # Delete Login Screen & MainLogin Screen

        self.login_screen.destroy()
        self.main_login.destroy()

        #Init App

        agenda_screen = Tk()
        Agenda(agenda_screen)
        agenda_screen.mainloop()
       
    
    def password_not_recognised(self):
        """
        Open the password not recognised screen
        """
        self.password_not_recog_screen = Toplevel(self.login_screen)
        self.password_not_recog_screen.title("Success")
        self.password_not_recog_screen.geometry("150x100")
        self.password_not_recog_screen.resizable(False,False)

        """
        login_icon_path=path+"\icons\login_icon.ico"
        self.password_not_recog_screen.iconbitmap(login_icon_path)
        """
        
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

        """
        login_icon_path=path+"\icons\login_icon.ico"
        self.user_not_found_screen.iconbitmap(login_icon_path)
        """

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
    cripto=Criptograpy()
    main_login = Tk()
    application = MainLogIn(main_login)

    path = os.getcwd()

    """
    login_icon_path = path + "\icons\login_icon.ico"
    print("PATH",login_icon_path)
    photo= tk.PhotoImage()
    main_login.iconphoto(False,login_icon_path)
    """

    main_login.mainloop()
    