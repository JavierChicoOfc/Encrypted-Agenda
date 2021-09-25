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

        Label(frame, text= 'Coordinate X:').grid(row = 2,column = 0)
        self.coordinate_x = Entry(frame)
        self.coordinate_x.grid(row = 2,column = 1)

        Label(frame, text= 'Coordinate Y:').grid(row = 3,column = 0)
        self.coordinate_y = Entry(frame)
        self.coordinate_y.grid(row = 3,column = 1)

        Label(frame, text= 'Coordinate Z:').grid(row = 4,column = 0)
        self.coordinate_z = Entry(frame)
        self.coordinate_z.grid(row = 4,column = 1)

        # Button Add Coordinate

        ttk.Button(frame, text = 'Save coordinate', command = self.add_coordinate).grid(row = 5, columnspan = 2,sticky = W+E)

        # Output messasges

        self.messsage = Label( text= "", fg = "red")
        self.messsage.grid(row = 3, column = 0, columnspan = 2, sticky = W + E)

        # Table

        self.tree = ttk.Treeview(height = 10, columns=("#0","#1","#2"))
        self.tree.grid(row = 6, column = 0, columnspan = 2)
        self.tree.heading("#0", text = "Name", anchor = CENTER)
        self.tree.heading("#1", text = "Coordinate X", anchor = CENTER)
        self.tree.heading("#2", text = "Coordinate Y", anchor = CENTER)
        self.tree.heading("#3", text = "Coordinate Z", anchor = CENTER)

        # Buttons

        ttk.Button(text = "Edit", command = self.edit_coordinates).grid(row = 7, column = 0, sticky = W+E)
        ttk.Button(text = "Delete", command = self.delete_coordinate).grid(row = 7, column = 1, sticky = W+E)

        # Filling the rows
        self.get_coordinates()

    def validation(self):
        return len(self.name.get())!=0 and len(self.coordinate_x.get())!=0 and len(self.coordinate_y.get())!=0 and len(self.coordinate_z.get())!=0

    def add_coordinate(self):
        if self.validation():
            query ="INSERT INTO coordinates VALUES(NULL, ?, ?, ?, ?)"
            parameters = (self.name.get(), self.coordinate_x.get(), self.coordinate_y.get(), self.coordinate_z.get())
            self.run_query(query, parameters)
            self.messsage["text"] = "Coordinate {} added successfully".format(self.name.get())
            self.name.delete(0, END)
            self.coordinate_x.delete(0, END)
            self.coordinate_y.delete(0, END)
            self.coordinate_z.delete(0, END)
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
        old_coordinate_x = self.tree.item(self.tree.selection())["values"][0]
        old_coordinate_y = self.tree.item(self.tree.selection())["values"][1]
        old_coordinate_z = self.tree.item(self.tree.selection())["values"][2]

        self.edit_wind = Toplevel()
        self.edit_wind.title = "Edit coordinate"

        # Old name

        Label(self.edit_wind, text = "Old name: ").grid(row = 0, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = name), state = "readonly").grid(row = 0, column = 2)

        # New name

        Label(self.edit_wind, text = "New name: ").grid(row = 0, column = 3)
        new_name = Entry(self.edit_wind)
        new_name.grid(row = 0, column = 4)

        # Old coordinate 

        Label(self.edit_wind, text = "Old coordinate X: ").grid(row= 1, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_coordinate_x), state = "readonly").grid(row = 1, column = 2)

        Label(self.edit_wind, text = "Old coordinate Y: ").grid(row= 2, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_coordinate_y), state = "readonly").grid(row = 2, column = 2)

        Label(self.edit_wind, text = "Old coordinate Z: ").grid(row= 3, column = 1)
        Entry(self.edit_wind, textvariable = StringVar(self.edit_wind, value = old_coordinate_z), state = "readonly").grid(row = 3, column = 2)

        # New coordinate 

        Label(self.edit_wind, text = "New coordinate X: ").grid(row = 1, column = 3)
        new_coordinate_x = Entry(self.edit_wind)
        new_coordinate_x.grid(row = 1, column = 4)

        Label(self.edit_wind, text = "New coordinate Y: ").grid(row = 2, column = 3)
        new_coordinate_y = Entry(self.edit_wind)
        new_coordinate_y.grid(row = 2, column = 4)

        Label(self.edit_wind, text = "New coordinate Z: ").grid(row = 3, column = 3)
        new_coordinate_z = Entry(self.edit_wind)
        new_coordinate_z.grid(row = 3, column = 4)

        Button(self.edit_wind, text = "Update", command = lambda: self.edit_records(new_name.get(), name, new_coordinate_x.get(), new_coordinate_y.get(), new_coordinate_z.get(), old_coordinate_x, old_coordinate_y, old_coordinate_z)).grid(row = 4, column = 2,  sticky = W+E)
        

    def edit_records(self, new_name, name, new_coordinate_x, new_coordinate_y, new_coordinate_z, old_coordinate_x, old_coordinate_y, old_coordinate_z):
        query = "UPDATE coordinates SET name = ?, coordinateX = ?, coordinateY = ?, coordinateZ = ?  WHERE name = ? AND coordinateX = ? AND coordinateY = ? AND coordinateZ = ?"
        parameters = (new_name, new_coordinate_x, new_coordinate_y, new_coordinate_z, name, old_coordinate_x, old_coordinate_y, old_coordinate_z)
        self.run_query(query, parameters)
        self.edit_wind.destroy()
        self.messsage["text"] = "Coordinate {} updated successfully".format(name)
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
            self.tree.insert("", 0, text = row[1], values = (row[2], row[3], row[4]))

if __name__== '__main__':
    window = Tk()
    application = Coordinates(window)

    # Icon
    window.iconbitmap("rocket.ico")

    #window.configure(bg="white")

    window.mainloop()
