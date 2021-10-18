from tkinter import ttk
from tkinter import *

import sqlite3

import constants

class Agenda:
    
    db_name = constants.DB_NAME

    def __init__(self,window):
        self.wind = window
        self.wind.title('Personal agenda')

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
        for i in params:
            if len(i) == 0:
                return False
        return True

    def add_contact(self):
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
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            result = cursor.execute(query, parameters)
            conn.commit()
        return result

    def get_contacts(self):
        # Cleaning table
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)
        query = constants.QUERY_GET
        db_rows = self.run_query(query)

        # Filling data
        for row in db_rows:
            self.tree.insert("", 0, text = row[1], values = (row[2], row[3], row[4]))

        
if __name__== '__main__':
    window = Tk()
    application = Agenda(window)

    # Icon
    #window.iconbitmap("rocket.ico")

    #window.configure(bg="white")

    window.mainloop()


