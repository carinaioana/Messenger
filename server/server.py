import base64
import os
import socket
import threading
import json
import logging
from cryptography.fernet import Fernet
import rsa

host = '127.0.0.1'
port = 55555

BUFFER_SIZE = 1024

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
client_ids = {}


def setup_server_logging():
    folder_path = 'server_chat_history'
    os.makedirs(folder_path, exist_ok=True)
    log_file_path = os.path.join(folder_path, f"server_chat_history.json")

    logger = logging.getLogger('server_logger')
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file_path)

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_record = {
                "time": self.formatTime(record, self.datefmt),
                "message": record.getMessage()
            }
            return json.dumps(log_record)

    formatter = JsonFormatter()
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


server_logger = setup_server_logging()


def handle_client(client):
    client_fernet_key = None
    fernet_obj = None

    client_id = client.recv(1024).decode('utf-8')

    if client_id in client_ids.values():
        client.send("This ID is already in use. Please try another ID.".encode('utf-8'))
        handle_client(client)
    else:
        client_fernet_key = client.recv(1024)

        clients.append((client, client_fernet_key))
        client_ids[client] = client_id
        client.send(f"You are connected to the server. You can start chatting, {client_id}.".encode('utf-8'))

    while True:
        try:
            encrypted_message = client.recv(BUFFER_SIZE)
            if not encrypted_message:
                break
            if client_fernet_key:
                fernet_obj = Fernet(client_fernet_key)
            message = fernet_obj.decrypt(encrypted_message).decode('utf-8')
            if message:
                client_id = client_ids[client]

                if message == "quit":
                    remove_client(client)
                    break
                elif message.startswith("/private"):
                    send_private_message(message, client, client_id)
                elif message == "/image":
                    image_data = send_image(client)
                    handle_image(client, image_data)
                else:
                    send_message(message, client, client_id)
        except Exception as e:
            remove_client(client)
            print(f"Error handling client {client_ids.get(client, 'unknown')}: {e}")
            break


def handle_image(sender, image_data):
    for recipient, key in clients:
        if recipient != sender:
            try:
                fernet_obj = Fernet(key)
                recipient.send(fernet_obj.encrypt(b"/image"))
                recipient.sendall(image_data + b"/end")
            except Exception as e:
                print(f"Error sending image: {e}")


def send_image(client):
    image_data = b""
    try:
        while image_data[-4:] != b"/end":
            image_data_chunk = client.recv(BUFFER_SIZE)
            if not image_data_chunk:
                break
            image_data += image_data_chunk
    except Exception as e:
        print(f"Error receiving image data: {e}")
    return image_data


def send_message(message, sender, sender_id):
    for c, key in clients:
        print(key)
        if c != sender:
            try:
                fernet_obj = Fernet(key)
                encrypted_message = fernet_obj.encrypt(f"Client {sender_id}: {message}".encode('utf-8'))
                c.send(encrypted_message)
                server_logger.info(f"Message from {sender_id}: {message}")
            except Exception as e:
                print(f"Error broadcasting message to client {client_ids[c]}: {e}")


def send_private_message(message, sender, sender_id):
    parts = message.split(" ", 2)
    if len(parts) == 3:
        recipient_ids = parts[1].split(",")
        private_message = parts[2]

        for recipient_id in recipient_ids:
            for c, key in clients:
                if c != sender and client_ids[c] == recipient_id.strip():
                    try:
                        fernet_obj = Fernet(key)
                        encrypted_private_message = fernet_obj.encrypt(f"Private message from {sender_id}: "
                                                                       f"{private_message}".encode('utf-8'))
                        c.send(encrypted_private_message)
                    except Exception as e:
                        print(f"Error sending private message to client {recipient_id}: {e}")
                        remove_client(c)
    else:
        sender.send(
            "Invalid /private command usage. Please provide recipient IDs and a message.".encode(
                'utf-8'))


def remove_client(client):
    print(f"Client {client_ids[client]} disconnected")
    if client in client_ids:
        del client_ids[client]

    for c, key in clients:
        if c == client:
            clients.remove((c, key))
            break

    client.close()


def main():
    while True:
        client, address = server.accept()
        print(f"Connection from {address} established")

        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
