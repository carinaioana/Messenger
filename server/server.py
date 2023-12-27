import datetime
import os
import socket
import threading

# Configurare server
host = '127.0.0.1'
port = 55555

# Creare socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

# Listă pentru stocarea clienților
clients = []
client_ids = {}


def handle_client(client):
    while True:
        try:
            message = client.recv(1024).decode('utf-8')

            if not message:
                break

            if message:
                sender_id = client_ids[client]
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                folder_path = 'chat_history'
                os.makedirs(folder_path, exist_ok=True)

                with open(os.path.join(folder_path, f"chat_history_{sender_id}.txt"), "a") as history_file:
                    history_file.write(f"{timestamp} - {message}\n")

                print(f"Received message from client {sender_id}: {message}")

                # Verifica daca mesajul e un mesaj privat
                if message.startswith("/private"):
                    parts = message.split(" ", 2)
                    if len(parts) == 3:
                        recipient_id = parts[1]
                        private_message = parts[2]

                        # Gaseste clientul destinatar și trimite mesajul privat
                        for c in clients:
                            if c != client and client_ids[c] == recipient_id:
                                try:
                                    c.send(f"Private message from {sender_id}: {private_message}".encode('utf-8'))
                                except Exception as e:
                                    print(f"Error sending private message to client {recipient_id}: {e}")
                                    remove_client(c)
                else:
                    # Trimite mesajul la toti clientii
                    for c in clients:
                        if c != client:
                            try:
                                c.send(f"Client {sender_id}: {message}".encode('utf-8'))
                            except Exception as e:
                                print(f"Error broadcasting message to client {client_ids[c]}: {e}")
                                remove_client(c)
        except Exception as e:
            print(f"Error handling client {client_ids[client]}: {e}")
            remove_client(client)
            break


# Funcție pentru eliminarea unui client
def remove_client(client):
    if client in clients:
        client_id = client_ids[client]
        print(f"Client {client_id} disconnected")
        clients.remove(client)
        del client_ids[client]
        client.close()


def main():
    # Așteaptă conexiuni și creează un fir de execuție pentru fiecare client
    while True:
        client, address = server.accept()
        print(f"Connection from {address} established")

        client_id = client.recv(1024).decode('utf-8')

        # Adaugă clientul la listă și atribuie un id
        clients.append(client)
        client_ids[client] = client_id

        client.send("Connected to the server. You can start chatting.".encode('utf-8'))

        threading.Thread(target=handle_client, args=(client,)).start()


if __name__ == "__main__":
    main()
