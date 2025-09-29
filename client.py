import socket, struct, json, base64, os
from tkinter import Tk, filedialog, Button, Text, END
from Crypto.Cipher import AES

KEY = b"0123456789abcdef0123456789abcdef"
HOST, PORT = "127.0.0.1", 65432


def encrypt_data(data: bytes):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def send_message(sock, obj):
    raw = json.dumps(obj).encode()
    length_prefix = struct.pack(">I", len(raw))
    sock.sendall(length_prefix + raw)


    try:
        response_len_data = sock.recv(4)
        if not response_len_data:
            return "Server cevap vermedi"
        response_len = struct.unpack(">I", response_len_data)[0]
        response_data = sock.recv(response_len)
        response = json.loads(response_data.decode())
        return response.get("status", "Bilinmeyen cevap")
    except Exception as e:
        return f"Hata: {e}"


def choose_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, "rb") as f:
            data = f.read()
        payload = encrypt_data(data)
        payload["filename"] = os.path.basename(filepath)
        status = send_message(client_socket, payload)
        log.insert(END, f"Gönderildi: {filepath}\nServer cevabı: {status}\n")
        print(f"Gönderildi: {filepath} | Server cevabı: {status}")


def send_text():
    msg = text_input.get("1.0", END).strip()
    if msg:
        payload = encrypt_data(msg.encode())
        payload["filename"] = None
        status = send_message(client_socket, payload)
        log.insert(END, f"Text gönderildi: {msg}\nServer cevabı: {status}\n")
        print(f"Text gönderildi: {msg} | Server cevabı: {status}")
        text_input.delete("1.0", END)


root = Tk()
root.title("AES Client")

Button(root, text="Dosya Seç & Gönder", command=choose_file).pack()
text_input = Text(root, height=3)
text_input.pack()
Button(root, text="Text Gönder", command=send_text).pack()
log = Text(root, height=15)
log.pack()


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((HOST, PORT))
    log.insert(END, "Server'a bağlanıldı.\n")
    print("Server'a bağlanıldı.")
except Exception as e:
    log.insert(END, f"Server'a bağlanılamadı: {e}\n")
    print(f"Server'a bağlanılamadı: {e}")


root.mainloop()
client_socket.close()
