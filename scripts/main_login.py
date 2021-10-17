#import modules
 
from tkinter import *
import os
 
# Designing window for registration
class MainLogIn:

    def __init__(self,main_screen):

        self.main_screen=main_screen
        self.main_screen.geometry("300x250")
        self.main_screen.title("Account Login")
        Label(text="Select Your Choice", bg="blue", width="300", height="2", font=("Calibri", 13)).pack()
        Label(text="").pack()
        Button(text="Login", height="2", width="30", command = self.login).pack()
        Label(text="").pack()
        Button(text="Register", height="2", width="30", command=self.register).pack()
    
    def register(self):

        self.register_screen = Toplevel(self.main_screen)
        self.register_screen.title("Register")
        self.register_screen.geometry("300x250")
    
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
    
    
    # Designing window for login 
    
    def login(self):
        global login_screen
        login_screen = Toplevel(self.main_screen)
        login_screen.title("Login")
        login_screen.geometry("300x250")
        Label(login_screen, text="Please enter details below to login").pack()
        Label(login_screen, text="").pack()
    
        
        global password_verify
    
        self.username_verify = StringVar()
        self.password_verify = StringVar()
    
        global username_login_entry
        global password_login_entry
    
        Label(login_screen, text="Username * ").pack()
        username_login_entry = Entry(login_screen, textvariable=self.username_verify)
        username_login_entry.pack()
        Label(login_screen, text="").pack()
        Label(login_screen, text="Password * ").pack()
        password_login_entry = Entry(login_screen, textvariable=self.password_verify, show= '*')
        password_login_entry.pack()
        Label(login_screen, text="").pack()
        Button(login_screen, text="Login", width=10, height=1, command = self.login_verify).pack()
    
    # Implementing event on register button
    
    def register_user(self):
    
        username_info = self.username.get()
        password_info = self.password.get()
    
        file = open(username_info, "w")
        file.write(username_info + "\n")
        file.write(password_info)
        file.close()
    
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
    
        Label(self.register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()
    
    # Implementing event on login button 
    
    def login_verify(self):
        username1 = self.username_verify.get()
        password1 = self.password_verify.get()
        username_login_entry.delete(0, END)
        password_login_entry.delete(0, END)
    
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
    
    # Designing popup for login success
    
    def login_sucess(self):
        self.login_success_screen = Toplevel(login_screen)
        self.login_success_screen.title("Success")
        self.login_success_screen.geometry("150x100")
        Label(self.login_success_screen, text="Login Success").pack()
        Button(self.login_success_screen, text="OK", command=self.delete_login_success).pack()
    
    # Designing popup for login invalid password
    
    def password_not_recognised(self):

        self.password_not_recog_screen = Toplevel(login_screen)
        self.password_not_recog_screen.title("Success")
        self.password_not_recog_screen.geometry("150x100")
        Label(self.password_not_recog_screen, text="Invalid Password ").pack()
        Button(self.password_not_recog_screen, text="OK", command=self.delete_password_not_recognised).pack()
    
    # Designing popup for user not found
    
    def user_not_found(self):
        self.user_not_found_screen = Toplevel(login_screen)
        self.user_not_found_screen.title("Success")
        self.user_not_found_screen.geometry("150x100")
        Label(self.user_not_found_screen, text="User Not Found").pack()
        Button(self.user_not_found_screen, text="OK", command=self.delete_user_not_found_screen).pack()
    
    # Deleting popups
    
    def delete_login_success(self):
        self.login_success_screen.destroy()
    
    
    def delete_password_not_recognised(self):
        self.password_not_recog_screen.destroy()
    
    
    def delete_user_not_found_screen(self):
        self.user_not_found_screen.destroy()
    

if __name__== '__main__':
    main_screen = Tk()
    application = MainLogIn(main_screen)

    # Icon
    #window.iconbitmap("rocket.ico")

    #window.configure(bg="white")

    main_screen.mainloop()