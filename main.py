from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox
import base64


def encode(key, clear):
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


def save_and_encryp():
    title = entry_title.get()
    message = notes_text.get("1.0", END)
    master = master_enrty.get()

    if len(title) == 0 or len(message) == 0 or len(master) == 0:
        messagebox.showinfo(title="Error!", message="Please Enter all info!")

    else:
        message_encryption = encode(master, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encryption}")

        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encryption}")

        finally:
            entry_title.delete(0, END)
            notes_text.delete("1.0", END)
            master_enrty.delete(0, END)


def decrypt_notes():
    message_encrypt = notes_text.get("1.0",END)
    master_decrypt = master_enrty.get()

    if len(master_decrypt) == 0 or len(message_encrypt) == 0 :
        messagebox.showinfo(title="Error!", message="Please enter all info!")

    else:
        try:
            decrypted_message = decode(master_decrypt, message_encrypt)
            notes_text.delete("1.0", END)
            notes_text.insert("1.0", decrypted_message)

        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")



#UI

window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=20)



img = PhotoImage(file="secreticons2.png")
canvas = Canvas(height=200 , width=200)
canvas.create_image(100,100,image=img)
canvas.pack()

label_title = Label(text="Enter Your Title")
label_title.pack()

entry_title = Entry(width=30)
entry_title.pack()

notes_label = Label(text="Enter Your Secret")
notes_label.pack()

notes_text = Text(width=25, height=10)
notes_text.pack()

master_label = Label(text="Enter Your Master Key")
master_label.pack()

master_enrty = Entry(width=25)
master_enrty.pack()

save_button = Button(text="Save & Encryqt", command= save_and_encryp)
save_button.pack()


bt_decryqt = Button(text="Decryqt", command=decrypt_notes)
bt_decryqt.pack()


window.mainloop()