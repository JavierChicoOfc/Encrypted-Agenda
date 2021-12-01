from tkinter import *
from crypto import Cryptograpy
from login import MainLogIn

if __name__ == "__main__":
    crypto = Cryptograpy()
    main_login = Tk()
    application = MainLogIn(main_login)
    main_login.mainloop()
