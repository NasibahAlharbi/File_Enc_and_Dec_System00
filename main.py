import os
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox
import rsa


def Generates_Pkey():  # Generates a key and save it into a file
    Pkey = Fernet.generate_key()
    return Pkey


def Generates_PR_PU_key():  # generate public and private keys, parameter key length is 512
    global privateKey
    publicKey, privateKey = rsa.newkeys(512)
    return privateKey, publicKey


# -----------------------------------------------------------------------------------------------------AES(decrypt)
# Use Prime key to Dec file


def aes_decrypt(filename, Pkey):
    File = Fernet(Pkey)
    with open(filename, "rb") as file:
        decrypted_File = File.decrypt(file.read())  # decrypt
    with open(filename, "wb") as file:  # write the original file
        file.write(decrypted_File)

    return decrypted_File


def rsa_encrypt(Prime_key, Sender_PU):  # Using Receiver’s Pub key to Enc the Prime key
    Prime = bytes(Prime_key.decode(),encoding='utf8' )
    return rsa.encrypt(Prime, Sender_PU)


def rsa_decrypt(Prime_key, PR_key):  # The receiver uses its PR key to Dec the Prime key
    return rsa.decrypt(Prime_key, PR_key).decode()


def aes_encrypt(filename, Pkey):
    f = Fernet(Pkey)
    with open(filename, "rb") as file:
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)  # read and encrypt data
    with open(filename, "wb") as file:  # write the encrypted file
        file.write(encrypted_data)

    print(encrypted_data)

    global PR_key, PU_key, rsa_Enc_prime,rsa_Dec_prime

    PR_key, PU_key = Generates_PR_PU_key()
    rsa_Enc_prime = rsa_encrypt(Pkey, PU_key)
    rsa_Dec_prime = rsa_decrypt(rsa_Enc_prime, PR_key)




def privat():
    global screen4
    screen4 = Toplevel(screen3)
    screen4.geometry('100x100')
    screen4.title("Your key")
    w = Label(screen4, text=PR_key)
    w.pack()


def public():
    global screen5
    screen5 = Toplevel(screen3)
    screen5.geometry('100x100')
    screen5.title("Your key")
    w = Label(screen5, text=PU_key)
    w.pack()


def RR():
    global screen6
    screen6 = Toplevel(screen3)
    screen6.geometry('100x100')
    screen6.title("Your M")
    k = Label(screen6, text=aes_decrypt(masseg_send.get(), rsa_Dec_prime))
    k.pack()


def regiter_user():
    username_info = username.get()
    password_info = password.get()

    password_info_hash = str(hash(password.get()))

    file = open(username_info, 'w')
    file.write(username_info + '\n')
    file.write(password_info)
    file.close()

    hash_file = open(password_info_hash, 'w')
    hash_file.write(password_info_hash + '\n')
    hash_file.close()

    Label(screen1, text='Welcom to the club', front='green', height='2', width='5')


def M():
    mas = masseg_send.get()
    file2 = open(mas, 'w')
    file2.write(mas + '\n')
    file2.close()
    global Prime_before_Enc
    Prime_before_Enc = Generates_Pkey()
    aes_encrypt(mas, Prime_before_Enc)


def register():
    global screen1
    screen1 = Toplevel(screen)
    screen1.geometry('350x250')
    screen1.title("register")
    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()
    Label(screen1, text='FILL THE DETIALS').pack()
    Label(screen1, text='').pack()
    Label(screen1, text='Username').pack()
    username_entry = Entry(screen1, textvariable=username).pack()
    Label(screen1, text='').pack()

    Label(screen1, text='Password').pack()
    password_entry = Entry(screen1, textvariable=password).pack()
    Label(screen1, text='').pack()
    Button(screen1, text='Register', height=2, width=15, command=regiter_user).pack()


def Login_user():
    username1 = usernaame_verify.get()
    password1 = password_verify.get()

    os_list = os.listdir()
    if username1 in os_list:

        file = open(username1, 'r')
        v = file.read().split()
        if password1 in v:
            Button(screen2, text='sucsses', height=2, width=15, command=after_Login).pack()
        else:
            messagebox.showinfo('not found', 'password is wrong')

    else:
        messagebox.showinfo('no user', 'pleas registar')


def after_Login():
    global screen3
    global masseg_send

    masseg_send = StringVar()
    screen3 = Toplevel(screen2)
    screen3.geometry('500x300')
    screen3.title("Your profil")

    Label(screen3, text='HI, welcom in your profil').pack()
    Label(screen3, text='').pack()

    Label(screen3, text='').pack()

    Label(screen3, text='').pack()

    Button(screen3, text='Generate keys', height=2, width=15, command=public).pack()
    Label(screen3, text='').pack()

    Label(screen3, text='').pack()

    Label(screen3, text='enter your masseg').pack()

    Entry(screen3, textvariable=masseg_send).pack()
    Label(screen3, text='').pack()
    Button(screen3, text='SEND', height=2, width=15, command=M).pack()
    Label(screen3, text='').pack()
    Button(screen3, text='received', height=2, width=15, command=RR).pack()

    '''Button(screen3, text='upload file', height=2, width=15,command=openFile).pack()'''


def login():
    global screen2
    global usernaame_verify
    global password_verify
    usernaame_verify = StringVar()
    password_verify = StringVar()
    screen2 = Toplevel(screen)
    screen2.geometry('500x300')
    screen2.title("Login")
    Label(screen2, text='Login').pack()
    Label(screen2, text='Username').pack()
    Entry(screen2, textvariable=usernaame_verify).pack()
    Label(screen2, text='Password').pack()
    Entry(screen2, textvariable=password_verify).pack()

    Button(screen2, text='Login', height=2, width=15, command=Login_user).pack()


def main():
    global screen
    screen = Tk()
    screen.geometry('400x400')
    Label(text='Login Form').pack()
    Button(text='Login', height=3, width=15, command=login).pack()
    Button(text='Register', height=3, width=15, command=register).pack()

    screen.mainloop()


main()