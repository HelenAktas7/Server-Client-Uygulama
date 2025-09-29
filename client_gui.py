import socket
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import os

KEY = b"0123456789abcdef" 

def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def encrypt(data, key=KEY):
    data = pad(data)
    iv = os.urandom(16)  
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)

def send_file(file_path):
    HOST = "127.0.0.1" 
    PORT = 65432        

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        encrypted = encrypt(file_data)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(encrypted)

        messagebox.showinfo("Başarılı", f"Dosya gönderildi:\n{file_path}")

    except Exception as e:
        messagebox.showerror("Hata", str(e))

def choose_file():
    file_path = filedialog.askopenfilename(
        title="Dosya Seç",
        filetypes=(("Tüm Dosyalar", "*.*"),
                   ("Resim", "*.jpg;*.png"),
                   ("Video", "*.mp4;*.avi"),
                   ("Ses", "*.mp3;*.wav"))
    )
    if file_path:
        send_file(file_path)

root = tk.Tk()
root.title("AES Şifreli Dosya Gönderici")
root.geometry("400x200")

label = tk.Label(root, text="AES Şifreleme ile Dosya Gönderme", font=("Arial", 12))
label.pack(pady=20)

btn = tk.Button(root, text="Dosya Seç ve Gönder", command=choose_file, font=("Arial", 10))
btn.pack(pady=20)

root.mainloop()
