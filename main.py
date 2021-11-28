from tkinter import *
from tkinter import ttk
from crypto import Cryptograpy
from login import MainLogIn


crypto = Cryptograpy()
main_login = Tk()
application = MainLogIn(main_login)
main_login.mainloop()
