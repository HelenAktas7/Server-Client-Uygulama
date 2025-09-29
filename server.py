import socket, struct, json, base64
from Crypto.Cipher import AES

KEY = b"0123456789abcdef0123456789abcdef"
HOST, PORT = "127.0.0.1", 65432

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def recv_message(sock):
    prefix = recvall(sock, 4)
    if not prefix:
        return None
    (length,) = struct.unpack(">I", prefix)
    raw = recvall(sock, length)
    return json.loads(raw.decode())


def decrypt_payload(payload):
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def send_ack(sock, status="Mesaj alındı!"):
    response = {"status": status}
    raw = json.dumps(response).encode()
    length_prefix = struct.pack(">I", len(raw))
    sock.sendall(length_prefix + raw)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Server dinliyor: {HOST}:{PORT}")

    conn, addr = s.accept()
    print("Bağlandı:", addr)

    while True:
        incoming = recv_message(conn)
        if not incoming:
            print("Bağlantı kapandı.")
            break

        try:
            data = decrypt_payload(incoming)
        except Exception as e:
            print("Deşifreleme hatası:", e)
            send_ack(conn, status=f"Hata: {e}")
            continue

        fname = incoming.get("filename")
        if fname:  
            with open("recv_" + fname, "wb") as f:
                f.write(data)
            print(f"Dosya alındı: recv_{fname}")
        else:  
            text_str = data.decode()
            print("Text alındı:", text_str)

        send_ack(conn)

    conn.close()
    s.close()

if __name__ == "__main__":
    main()
