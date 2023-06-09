from tkinter import messagebox
from tkinter import *
#from cryptography.fernet import Fernet
import base64


window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=20)

FONT = ("Arial", 14, "normal")
file_path = "secret.txt"


#functions
def save_and_encrypt_button_clicked():
    get_text_content()

def decrypt_button_clicked():
    decrypt_notes()

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i])+ ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def get_text_content():
    
    title = title_entry.get()
    message = secret_text.get("1.0", END)
    key = key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(key) == 0:
        messagebox.showwarning(title="Error!", message="Please enter all infos")
    else:
        #encryption
        message_encrypted = encode(key,message)
        #save to file
        create_txt_file(title=title, message=message_encrypted)

def decrypt_notes():

    message_encrypted = secret_text.get("1.0", END)
    key = key_entry.get()

    if len(message_encrypted) == 0 or len(key) == 0:
        messagebox.showwarning(title="Error!", message="Please enter all infos")
    else:
        try:
            decrypted_message = decode(key=key, enc=message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showerror(title="Error", message="Please enter encrypted message")

def create_txt_file(title, message):

    global  file_path

    try:
        with open(file_path, "a") as f:
            f.write(f"\n{title}\n{message}")
    except FileNotFoundError:
        with open(file_path, "w") as f:
            f.write(f"\n{title}\n{message}")
    finally:
        title_entry.delete(0, END)
        secret_text.delete("1.0", END)
        key_entry.delete(0, END)
        f.close()


#image
image = PhotoImage(file="topsecret.png")
image_label = Label(window, image=image)
image_label.pack()

enter_title_label = Label(text="Enter your title", font=FONT)
enter_title_label.pack(pady=5)

title_entry = Entry(width=30)
title_entry.pack()

enter_secret_label = Label(text="Enter your secret", font=FONT)
enter_secret_label.pack(pady=5)

secret_text = Text(height=15, width=40)
secret_text.pack()

enter_key_label = Label(text="Enter master key", font=FONT)
enter_key_label.pack(pady=5)

key_entry = Entry(width=30)
key_entry.pack()

save_and_encrypt_button = Button(text="Save & Encrypt", width=30, command=save_and_encrypt_button_clicked)
save_and_encrypt_button.pack(pady=10)

decrypt_button = Button(text="Decrypt", width=30, command=decrypt_button_clicked)
decrypt_button.pack()

window.mainloop()
