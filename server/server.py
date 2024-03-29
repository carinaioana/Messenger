import os
import socket
import threading
import logging
import time

from cryptography.fernet import Fernet

BUFFER_SIZE = 1024

host = '127.0.0.1'
port = 55555

# creates the socket and binds it to the specified ip and port and then listens for incoming connections
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = {}  # stores the clients` keys`
client_ids = {}  # stores the clients` ids`


def setup_server_logging():
    """ creates the chat history between clients"""
    folder_path = 'server_chat_history'
    os.makedirs(folder_path, exist_ok=True)
    log_file_path = os.path.join(folder_path, "server_chat_history.log")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=log_file_path,
        filemode='a'
    )

    return logging.getLogger('server_logger')


server_logger = setup_server_logging()


def handle_client(client):
    client_fernet_key = None
    try:
        client_id = client.recv(1024).decode('utf-8')  # receives the clientID

        # if another client already used the ID, the user is informed to provide with another one
        if client_id in client_ids.values():
            client.send("This ID is already in use. Please try another ID.".encode('utf-8'))
            handle_client(client)
        else:
            client.send(f"You are connected to the server. You can start chatting, {client_id}.".encode('utf-8'))
            client_fernet_key = client.recv(1024)  # receives the key

            clients[client] = client_fernet_key  # adds the key as the client socket and the value as the fernet_key
            client_ids[client] = client_id  # adds the key as the client socket and the value as the clientID
    except Exception as e:
        logging.error(f"Error in server while trying to log in: {e}")
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
                        image_data = receive_image(client)
                        send_image(client, image_data)
                    elif message == "/pimage":
                        encrypted_recipients = client.recv(BUFFER_SIZE)
                        recipients = fernet_obj.decrypt(encrypted_recipients).decode('utf-8')
                        recipient_ids = recipients.strip().split(",")
                        image_data = receive_image(client)
                        send_private_image(client, image_data, recipient_ids)
                    else:
                        send_message(message, client, client_id)
        except Exception as e:
            server_logger.error(f"Error handling client {client_ids.get(client, 'unknown')}: {e}")
            remove_client(client)
            break


def send_image(sender, image_data):
    """sends the image to all the clients in the dictionary except the sender"""
    for recipient, key in clients.items():
        if recipient != sender:
            try:
                fernet_obj = Fernet(key)
                recipient.send(fernet_obj.encrypt(b"/image"))
                recipient.sendall(image_data)  # continues to send data from the buffer until all data has been sent
                time.sleep(0.1)  # the program waits so that the client receives all the image data
                recipient.send(fernet_obj.encrypt(f"Image from {client_ids[sender]}: ".encode('utf-8')))
            except Exception as e:
                server_logger.error(f"Error sending image: {e}")


def send_private_image(sender, image_data, recipients_ids):
    """sends the image privately to all the specified recipients"""
    for recipient_id in recipients_ids:
        for recipient, key in clients.items():
            if recipient != sender and client_ids[recipient] == recipient_id.strip():
                try:
                    fernet_obj = Fernet(key)
                    recipient.send(fernet_obj.encrypt(b"/image"))
                    recipient.sendall(image_data)
                    time.sleep(0.1)
                    recipient.send(fernet_obj.encrypt(f"Private image from {client_ids[sender]}: ".encode('utf-8')))
                except Exception as e:
                    server_logger.error(f"Error sending image: {e}")


def receive_image(client):
    image_data = b""
    try:
        # while the `/end` marker is not reached the server keeps receiving chunks of the image data
        while image_data[-4:] != b"/end":
            image_data_chunk = client.recv(BUFFER_SIZE)
            if not image_data_chunk:
                break
            image_data += image_data_chunk
    except Exception as e:
        server_logger.error(f"Error receiving image data: {e}")
    return image_data


def send_message(message, sender, sender_id):
    """sends message to everyone"""
    for recipient, key in clients.items():
        # print(key)
        if recipient != sender:
            try:
                fernet_obj = Fernet(key)
                encrypted_message = fernet_obj.encrypt(f"Client {sender_id}: {message}".encode('utf-8'))
                recipient.send(encrypted_message)
                server_logger.info(f"Message from {sender_id}: {message}")
            except Exception as e:
                server_logger.error(f"Error sending the message to everyone {client_ids[recipient]}: {e}")


def send_private_message(message, sender, sender_id):
    """sends message privately to the recipients"""
    parts = message.split(" ", 2)
    if len(parts) == 3:
        recipient_ids = parts[1].split(",")
        private_message = parts[2]

        for recipient_id in recipient_ids:
            for recipient, key in clients.items():
                if recipient != sender and client_ids[recipient] == recipient_id.strip():
                    try:
                        fernet_obj = Fernet(key)
                        encrypted_private_message = fernet_obj.encrypt(f"Private message from {sender_id}: "
                                                                       f"{private_message}".encode('utf-8'))
                        recipient.send(encrypted_private_message)
                    except Exception as e:
                        server_logger.error(f"Error sending private message to client {recipient_id}: {e}")
                        remove_client(recipient)
    else:
        sender.send(
            "Invalid /private command usage. Please provide recipient IDs and a message.".encode(
                'utf-8'))


def remove_client(client):
    """if the client wants to quit the connection
            it removes it from the dictionaries and closes the socket connection"""
    server_logger.info(f"Client {client_ids[client]} disconnected")
    if client in client_ids:
        del client_ids[client]

    if client in clients:
        del clients[client]

    client.close()


def main():
    while True:
        client, address = server.accept()  # accepts connection from client
        server_logger.info(f"Connection from {address} established")

        # starts a thread to handle each client
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
