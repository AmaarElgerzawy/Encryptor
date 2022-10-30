from tkinter import *
import random
from tkinter import ttk
from Crypto.Cipher import AES, DES3
from Crypto import Random
import base64
import pyrebase

class program():
    #the mode of in encription Gui -- selection
    global modes
    modes = ["Caeser", "AES", "DES3"]

    def __init__(self) -> None:
        #Google code conection to fire base with domain and api key
        firebaseConfig = {
            "apiKey": "AIzaSyDg0El2xCWsYLvAdQ78uNKFw9vPRFkGipE",
            "authDomain": "cryptograpthy.firebaseapp.com",
            "databaseURL": "https://cryptograpthy-default-rtdb.firebaseio.com",
            "projectId": "cryptograpthy",
            "storageBucket": "cryptograpthy.appspot.com",
            "messagingSenderId": "613926356685",
            "appId": "1:613926356685:web:c9dd8cb5e5cbed4dc80b84",
            "measurementId": "G-PVCH4VJC8C"
        }
        firebase = pyrebase.initialize_app(firebaseConfig)
        #the Variable Controling DATABase
        db = firebase.database()
        
        #function that open top level and send to fire base the key and channel
        def sendinf():
            def click():
                def func(x):
                    bar()
                    return x
                bar()
                db.child(func(SID.get())).child(func(token.get())).set(data=leb.get("0.0", END))
                bar()
                bar()
                top.destroy()
            top = Toplevel()
            top.geometry('300x200+450+200')
            #the progress par
            progress = ttk.Progressbar(top, orient=HORIZONTAL, length=100, mode='determinate')
            def bar():
                progress['value'] = progress['value'] + 20
                self.main.update_idletasks()
            progress.place(x = 100 , y = 100)
            labels = ["Channel Name", "Auth"]
            I = 0
            for text in labels:
                label = Label(top, text=text, fg="green")
                label.grid(row=I, column=0, sticky=W)
                I += 1

            SID = StringVar()
            entry1 = Entry(top, bg="white", width=30, textvariable=SID)
            entry1.grid(row=0, column=1, padx=5, pady=5)

            token = StringVar()
            entry2 = Entry(top, bg="white", width=30, textvariable=token)
            entry2.grid(row=1, column=1, padx=5, pady=5)

            button1 = Button(top, text="Send", fg="white", bg="gray", width=5, command=click)
            button1.grid(row=5, column=1, pady=5, sticky=E, padx=5)
        
        #function that open top level and Get Chipher from fire base the key and channel
        def getinf():
            def click():
                def func(x):
                    bar()
                    return x
                bar()
                text_entry2.insert(END, str(db.child(func(RID.get())).get().val()[func(given.get())])[:-1])
                bar()
                bar()
                top.destroy()
            top = Toplevel()
            top.geometry('300x200+450+200')
            #the progress par
            progress = ttk.Progressbar(top, orient=HORIZONTAL, length=100, mode='determinate')

            def bar():
                progress['value'] = progress['value'] + 20
                self.main.update_idletasks()
            progress.place(x=100, y=100)
            labels = ["Channel Name", "Cridinonal"]
            I = 0
            for text in labels:
                label = Label(top, text=text, fg="green")
                label.grid(row=I, column=0, sticky=W)
                I += 1

            RID = StringVar()
            entry1 = Entry(top, bg="white", width=30, textvariable=RID)
            entry1.grid(row=0, column=1, padx=5, pady=5)

            given = StringVar()
            entry2 = Entry(top, bg="white", width=30, textvariable=given)
            entry2.grid(row=1, column=1, padx=5, pady=5)

            button1 = Button(top, text="Get", fg="white", bg="gray", width=5, command=click)
            button1.grid(row=5, column=1, pady=5, sticky=E, padx=5)

        #function of Encript To Caeser
        def en_caeser(text):
            key = random.randint(15, 41)
            cipher_text = ""
            for ch in text:
                ch = ord(ch) + key % 26
                en_letter = chr(ch)
                cipher_text += en_letter
            
            #GUI
            leb.config(state=NORMAL)
            leb.delete("1.0", END)
            leb.insert("1.0", chr(key)+"*"+cipher_text+"1")
            leb.config(state=DISABLED)
        
        #function of Encript To AES
        def en_AES(text):
            block_size = 16
            def expansion(cipher): return cipher + (block_size - len(cipher) % block_size) * '*'
            key = Random.new().read(16)
            IV = Random.new().read(16)
            encryption = AES.new(key, AES.MODE_CBC, IV)
            cipher_text = base64.b64encode(key + IV + encryption.encrypt(expansion(text).encode('utf-8')))
            
            #GUI
            leb.config(state=NORMAL)
            leb.delete("1.0", END)
            leb.insert("1.0", cipher_text)
            leb.insert(END, "2")
            leb.config(state=DISABLED)

        #function of Encript To 3DES
        def en_DES3(text):
            block_size = DES3.block_size
            key = Random.new().read(16)
            IV = Random.new().read(block_size)
            encryption = DES3.new(key, DES3.MODE_OFB, IV)
            cipher_text = base64.b64encode(key + IV + encryption.encrypt(text.encode('ascii')))

            #GUI
            leb.config(state=NORMAL)
            leb.delete("1.0", END)
            leb.insert("1.0", cipher_text)
            leb.insert(END, "3")
            leb.config(state=DISABLED)

        #part of Chiper that allow us to Know Type Of Enryption
        def en_mode():
            option = mode_box.get()
            text = text_entry.get()
            #GUI
            if option == 'Caeser':
                return en_caeser(text)
            elif option == 'AES':
                return en_AES(text)
            elif option == 'DES3':
                return en_DES3(text)
        
        #function of DEEncript To Caeser
        def de_caeser(text):
            plain_text = ""
            separator = text.find("*")
            key = ord(text[:separator])
            text = text[separator+1:]
            for ch in text:
                ch = ord(ch) - key % 26
                de_letter = chr(ch)
                plain_text += de_letter

            #GUI
            de_leb.config(state=NORMAL)
            de_leb.delete("1.0", END)
            de_leb.insert("1.0", plain_text)
            de_leb.config(state=DISABLED)

        #function of DEEncript To AES
        def de_AES(text):
            key = base64.b64decode(text)[:16]
            IV = base64.b64decode(text)[16:32]
            decryption = AES.new(key, AES.MODE_CBC, IV)
            plain_text = base64.b64decode(text)[32:]
            plain_text = decryption.decrypt(plain_text)
            plain_text = plain_text.decode('utf-8')
            plain_text = plain_text.strip('*')

            #GUI
            de_leb.config(state=NORMAL)
            de_leb.delete("1.0", END)
            de_leb.insert("1.0", plain_text)
            de_leb.config(state=DISABLED)

        #function of DEEncript To 3DES
        def de_DES3(text):
            key = base64.b64decode(text)[:16]
            IV = base64.b64decode(text)[16:24]
            plain_text = base64.b64decode(text)[24:]
            decryption = DES3.new(key, DES3.MODE_OFB, IV)
            plain_text = decryption.decrypt(plain_text)
            plain_text = plain_text.decode('ascii')

            #GUI
            de_leb.config(state=NORMAL)
            de_leb.delete("1.0", END)
            de_leb.insert("1.0", plain_text)
            de_leb.config(state=DISABLED)

        #part of Chiper that allow us to Know Type Of DEEnryption
        def de_mode():
            text = text_entry2.get()
            if text[-1] == "1":
                return de_caeser(text[:len(text)-1])
            elif text[-1] == "2":
                return de_AES(text[:len(text)-1])
            elif text[-1] == "3":
                return de_DES3(text[:len(text)-1])

        # the program
        self.main = Tk()
        self.main.geometry('800x500+250+100')
        self.main.resizable(False, False)
        self.main.title('CryptoGrphy'.title())
        # the notebook
        self.nt = ttk.Notebook(self.main, height=310)
        self.nt.place(x=0, y=120)

        # the hello frame
        self.hello_frame = Frame(self.nt, width=800, height=100, bg='#fff')
        self.hello_frame.place(x=0, y=0)

        # decript frame
        self.de_frame = Frame(self.nt, width=800, height=100, bg='#bba')
        self.de_frame.place(x=0, y=0)

        # THE ADD
        self.nt.add(self.hello_frame, text='Encrypt')
        self.nt.add(self.de_frame, text="Decrypt")

        self.nt.select(self.hello_frame)

        # the welcome msg
        welcome1 = Label(self.main, text='welcome to cryptography encryption project'.title(), font=('Aril', 18), bg='White')
        welcome1.place(x=10, y=25)
        welcome2 = Label(self.main, text='i hope you found this tool usefull , feel free to encrypt text'.title(), font=('Aril', 8), bg='White')
        welcome2.place(x=10, y=65)

        # the main frame
        self.main_frame = Frame(self.hello_frame, width=800, height=350, bg='#bba')
        self.main_frame.place(x=0, y=0)

        # the variaple
        self.text = StringVar()
        self.de_text = StringVar()

        # the Encrypt GUI
        text_lbl = Label(self.main_frame, text='Enter The text : '.title(), font=('Aril', 12), bg='#bba')
        text_lbl.place(x=20, y=20)

        text_entry = Entry(self.main_frame, width=90, textvariable=self.text)
        text_entry.place(x=140, y=25)

        leb = Text(self.main_frame, width=90, height=10 , state=DISABLED)
        leb.place(x=20, y=95)

        btn = Button(self.main_frame, text='Transfer', command=en_mode)
        btn.place(x=140, y=60)

        #Copy Function
        def copt_f():
            self.main.clipboard_clear()
            self.main.clipboard_append(leb.get("0.0", END)[:-1])

        cpy = Button(self.main_frame, text='COPY TEXT', width=10, command=copt_f)
        cpy.place(x=230, y=60)

        end = Button(self.main, text='EXIT', command=self.main.quit, width=8)
        end.place(x=720, y=460)

        sendButton = Button(self.main_frame, text='SEND Message', width=12, command=sendinf)
        sendButton.place(x=20, y=60)

        # the Decrypt GUI
        text_lbl = Label(self.de_frame, text='Enter The TEXT : '.title(), font=('Aril', 12), bg='#bba')
        text_lbl.place(x=20, y=20)

        text_entry2 = Entry(self.de_frame, width=90, textvariable=self.de_text)
        text_entry2.place(x=140, y=25)

        de_leb = Text(self.de_frame, width=90, height=10 , state=DISABLED)
        de_leb.place(x=20, y=95)

        btn = Button(self.de_frame, text='Transfer', command=de_mode)
        btn.place(x=140, y=57)

        msgButton = Button(self.de_frame, text='RECIVE Message', width=12, command=getinf)
        msgButton.place(x=20, y=60)

        # Selection mode
        mode_lbl = Label(self.main_frame, text="Select Encryption")
        mode_lbl.place(x=345, y=62)

        mode_box = ttk.Combobox(self.main_frame, value=modes, width=35)
        mode_box.place(x=450, y=62)

        # starting program
        self.main.mainloop()

my_program1 = program()
