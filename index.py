from tkinter import ttk
from tkinter import *

import sqlite3

class Coordinates:

    db_name = "database.db"

    def __init__(self,window):
        self.wind =window
        self.wind.title('Coordinates')

        # Creating a Frame Containter
        
        frame= LabelFrame(self.wind, text = 'Register a new coordinate')
        frame.grid(row = 0, column = 0, columnspan = 3, pady = 20)

        # Name Input

        Label(frame, text= 'Name:').grid(row = 1,column = 0)
        self.name = Entry(frame)
        self.name.focus
        self.name.grid(row = 1, column = 1)

        # Coordinates input

        Label(frame, text= 'Coordinates:').grid(row = 2,column = 0)
        self.coordinate = Entry(frame)
        self.coordinate.grid(row = 2,column = 1)

        # Button Add Coordinate

        ttk.Button(frame, text = 'Save coordinate', command = self.add_coordinate).grid(row = 3, columnspan = 2,sticky = W+E)

        # Output messasges

        self.messsage = Label( text= "", fg = "red")
        self.messsage.grid(row = 3, column = 0, columnspan = 2, sticky = W + E)

        # Table

        self.tree = ttk.Treeview(height = 10, columns = 2)
        self.tree.grid(row = 4, column = 0, columnspan = 2)
        self.tree.heading("#0", text = "Name", anchor = CENTER)
        self.tree.heading("#1", text = "Coordinates", anchor = CENTER)
        #self.tree.heading("#3", text = "coordinate X", anchor = CENTER)

        # Buttons

        ttk.Button(text = "Edit", command = self.edit_coordinates).grid(row = 5, column = 0, sticky = W+E)
        ttk.Button(text = "Delete", command = self.delete_coordinate).grid(row = 5, column = 1, sticky = W+E)

        # Filling the rows
        self.get_coordinates()

    def validation(self):
        return len(self.name.get())!=0 and len(self.coordinate.get())!=0

    def add_coordinate(self):
        if self.validation():
            query ="INSERT INTO coordinates VALUES(NULL, ?, ?)"
            parameters = (self.name.get(), self.coordinate.get())
            self.run_query(query, parameters)
            self.messsage["text"] = "Coordinate {} added successfully".format(self.name.get())
            self.name.delete(0, END)
            self.coordinate.delete(0, END)
        else:
            self.messsage["text"] = "Name and coordinates are required"
        self.get_coordinates()

    def delete_coordinate(self):
        self.messsage["text"] = ""
        try:
            self.tree.item(self.tree.selection())["text"][0]
        except IndexError as error:
            self.messsage["text"] = "Please select a record"
            return
        self.messsage["text"] = ""
        name = self.tree.item(self.tree.selection())["text"]
        query = "DELETE FROM coordinates WHERE name = ?"
        self.run_query(query, (name,))
        self.messsage["text"] = " Record {} deleted successfully".format(name)
        self.get_coordinates()

    def edit_coordinates(self):
        self.messsage["text"] = ""
        try:
            self.tree.item(self.tree.selection())["text"][0]
        except IndexError as error:
            self.messsage["text"] = "Please select a record"
            return
        self.messsage["text"] = ""
        name = self.tree.item(self.tree.selection())["text"]
        old_coordinate = self.tree.item(self.tree.selection())["values"][0]
        self.edit_wind = Toplevel()
        self.edit_wind.title = "Edit coordinate"

        # Old name

        Label(self.edit_wind, text = "Old name: ").grid(row = 0, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = name), state = "readonly").grid(row = 0, column = 2)

        # New name

        Label(self.edit_wind, text = "New name: ").grid(row = 1, column = 1)
        new_name = Entry(self.edit_wind)
        new_name.grid(row = 1, column = 2)

        # Old coordinate

        Label(self.edit_wind, text = "Old coordinate: ").grid(row= 2, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_coordinate), state = "readonly").grid(row = 2, column = 2)

        # New coordinate

        Label(self.edit_wind, text = "New coordinate: ").grid(row = 3, column = 1)
        new_coordinate = Entry(self.edit_wind)
        new_coordinate.grid(row = 3, column = 2)

        Button(self.edit_wind, text = "Update", command = lambda: self.edit_records(new_name.get(), name, new_coordinate.get(), old_coordinate)).grid(row = 4, column = 2, sticky = W)
        

    def edit_records(self, new_name, name, new_coordinate, old_coordinate):
        query = "UPDATE coordinates SET name = ?, coordinate = ? WHERE name = ? AND coordinate = ?"
        parameters = (new_name, new_coordinate, name, old_coordinate)
        self.run_query(query, parameters)
        self.edit_wind.destroy()
        self.messsage["text"] = "Record {} updated successfully".format(name)
        self.get_coordinates()

    def run_query(self, query, parameters=()):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            result = cursor.execute(query, parameters)
            conn.commit()
        return result

    def get_coordinates(self):
        # Cleaning table
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)
        query = "SELECT * FROM coordinates ORDER BY name DESC"
        db_rows = self.run_query(query)

        # Filling data
        for row in db_rows:
            self.tree.insert("", 0, text = row[1], values = row[2])

if __name__== '__main__':
    window = Tk()
    application = Coordinates(window)
    window.mainloop()
