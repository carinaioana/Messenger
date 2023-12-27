import datetime
import os
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk, Image


def save_message(client_id, message):
    folder_path = 'chat_history'
    os.makedirs(folder_path, exist_ok=True)

    with open(os.path.join(folder_path, "chat_history.txt"), "a") as history_file:
        history_file.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S:')} Client {client_id}: {message}\n")


class ChatApplication:
    def __init__(self):

        self.client_id = None
        self.text = None
        self.entry = None

        self.host = '127.0.0.1'
        self.port = 55555

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

        self.root = tk.Tk()
        self.root.title("Login")

        self.create_login_widgets()

    def create_login_widgets(self):
        label = tk.Label(self.root, text="Enter your ID: ")
        label.pack()

        self.entry = tk.Entry(self.root)
        self.entry.pack()

        button_login = tk.Button(self.root, text="Login", command=self.login)
        button_login.pack()

    def login(self):
        self.client_id = self.entry.get().strip()
        if self.client_id:
            self.client.send(self.client_id.encode('utf-8'))
            self.create_chat_widgets()

    def create_chat_widgets(self):
        self.destroy_widgets()

        self.root.title("Chat Application")

        self.text = tk.Text(self.root)
        self.text.pack(pady=10)

        self.entry = tk.Entry(self.root, width=50)
        self.entry.pack(pady=10)

        send_button = tk.Button(self.root, text="Send", command=lambda: self.send(self.entry))
        send_button.pack()

        threading.Thread(target=self.receive, args=(self.text,)).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def receive(self, text_widget):
        while True:
            try:
                message = self.client.recv(1024).decode('utf-8')
                if not message:
                    break
                text_widget.insert(tk.END, message + '\n')
                save_message(self.client_id, message)
            except Exception as e:
                print(f"Error receiving message from server: {e}")
                break

    def send(self, entry_widget):
        message = entry_widget.get()

        if message:
            self.text.insert(tk.END, "Client " + str(self.client_id) + ":" + message + '\n')

            if message.startswith("/private"):
                parts = message.split(" ", 2)
                recipient_id = parts[1] if len(parts) > 1 else None
                if recipient_id:
                    self.client.send(f"/private {recipient_id} {parts[2]}".encode('utf-8'))
            else:
                self.client.send(message.encode('utf-8'))
            entry_widget.delete(0, tk.END)

    def on_closing(self):
        try:
            if messagebox.askokcancel("Quit", "Do you want to quit?"):
                self.client.send("quit".encode('utf-8'))
                self.client.close()
                self.root.destroy()
        except Exception as e:
            print(f"Error closing the application: {e}")

    def destroy_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    chat_app = ChatApplication()
    tk.mainloop()
