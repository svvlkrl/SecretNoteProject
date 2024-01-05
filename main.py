from tkinter import *
import base64
from tkinter import messagebox
from PIL import ImageTk, Image

window = Tk()
window.title("Secret Notes")
window.geometry("500x700")


photo = Image.open("top_secret.png")
display = ImageTk.PhotoImage(photo)
photo_label = Label(window, image=display)
photo_label.pack()


def encode(key,clear):
    enc = []

    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
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


def save_button_clicked():
    title = title_entry.get()
    message = secretnote_text.get("1.0", END)
    password = password_entry.get()

    if len(title) == 0 or len(message) == 0 or len(password) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(password, message)

        try:
            with open("top_secret.txt", "a") as data_file:
                data_file.write(f"\nTitle: {title}\nMessage: {message_encrypted}\n")
                messagebox.showinfo(title="Success", message="Message saved and encrypted!")
        except FileNotFoundError:
            with open("top_secret.txt", "w") as data_file:
                data_file.write(f"\nTitle: {title}\nMessage: {message_encrypted}\n")
                messagebox.showerror(title="Success", message="Message saved and encrypted!")

def display_decrypted_message():
    encrypted_message = window.clipboard_get()
    password = password_entry.get()

    if not encrypted_message:
        messagebox.showinfo(title="No Message", message="Please select an encrypted message to copy.")
    else:
        try:
            decrypted_message = decode(password, encrypted_message)
            secretnote_text.delete("1.0", "end")
            secretnote_text.insert("1.0", decrypted_message)
        except Exception as e:
            messagebox.showinfo(title="Decryption Error", message="Error while decrypting the message.Please make sure to enter all the information.")

title_label = Label(text="Title",font=("Arial Black",15,"normal"))
title_label.pack()

title_entry = Entry(width=50)
title_entry.focus()
title_entry.pack()

secretnote_label = Label(text="Secret Note",font=("Arial Black",15,"normal"))
secretnote_label.pack()

secretnote_text = Text(width=50,height=15)
secretnote_text.pack()

password_label = Label(text="Enter Password",font=("Arial Black",10,"normal"))
password_label.pack()

password_entry = Entry(width=40)
password_entry.pack()

save_encrypt_button = Button(text="Save & Encrypt", command=save_button_clicked)
save_encrypt_button.pack()

decrypt_button = Button(text="Decrypt", command=display_decrypted_message)
decrypt_button.pack()


window.mainloop()