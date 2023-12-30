import base64
import io
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import rsa


DARK_GRAY = "#3a3a3a"
LIGHT_GRAY = "#f5f5f5"
WHITE = "#ffffff"
FONT_NAME = "Helvetica"
FONT_SIZE = 12
BUFFER_SIZE = 1024


class ChatApplication:
    def __init__(self):
        self.client_id = None
        self.entry = None
        self.text = None

        self.public_key, self.private_key = rsa.newkeys(BUFFER_SIZE)
        self.public_partner = None

        self.fernet_key = None
        self.fernet_obj = None

        self.host = '127.0.0.1'
        self.port = 55555

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

        self.root = tk.Tk()
        self.root.title("Login")

        self.create_login_widgets()

    def create_login_widgets(self):
        self.root.configure(bg=DARK_GRAY)

        label = tk.Label(self.root, text="Enter your ID: ", bg=DARK_GRAY, fg=WHITE, font=(FONT_NAME, FONT_SIZE))
        label.pack()

        self.entry = tk.Entry(self.root, bg=LIGHT_GRAY, fg=DARK_GRAY, font=(FONT_NAME, FONT_SIZE))
        self.entry.pack()

        self.entry.bind("<Return>", self.login)

        button_login = tk.Button(self.root, text="Login", command=self.login, bg=LIGHT_GRAY, fg=DARK_GRAY,
                                 font=(FONT_NAME, FONT_SIZE))
        button_login.pack()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def login(self, event=None):
        self.fernet_key = Fernet.generate_key()
        self.fernet_obj = Fernet(self.fernet_key)

        self.client_id = self.entry.get().strip()
        if self.client_id:

            self.client.send(self.client_id.encode('utf-8'))
            self.client.send(self.fernet_key)

            server_response = self.client.recv(1024).decode('utf-8')

            if server_response == "This ID is already in use. Please try another ID.":
                messagebox.showerror("Login Failed", "This ID is already in use. Please try another ID.")
            else:
                self.create_chat_widgets()
                if self.text:
                    self.text.insert(tk.END, server_response + '\n')

    def create_chat_widgets(self):
        self.destroy_widgets()

        self.root.title("Chat Application")
        self.root.configure(bg=DARK_GRAY)

        self.text = tk.Text(self.root, bg=LIGHT_GRAY, fg=DARK_GRAY, font=(FONT_NAME, FONT_SIZE))
        scrollbar = tk.Scrollbar(self.root, command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.pack(pady=10, expand=True, fill=tk.BOTH)

        self.entry = tk.Entry(self.root, width=50, bg=LIGHT_GRAY, fg=DARK_GRAY, font=(FONT_NAME, FONT_SIZE))
        self.entry.pack(pady=10)

        # upload_images_button = tk.Button(self.root, text="Upload Images", command=self.upload_images, bg=LIGHT_GRAY,
        #                                  fg=DARK_GRAY, font=(FONT_NAME, FONT_SIZE))
        # upload_images_button.pack()

        send_button = tk.Button(self.root, text="Send", command=lambda: self.send(self.entry), bg=LIGHT_GRAY,
                                fg=DARK_GRAY, font=(FONT_NAME, FONT_SIZE))
        send_button.pack()

        self.entry.bind("<Return>", self.send)

        threading.Thread(target=self.receive_message, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # def upload_images(self):
    #     f_types = [('JPG files', '*.jpg'), ('PNG files', '*.png')]
    #     filename = tk.filedialog.askopenfilename(filetypes=f_types)
    #     img = Image.open(filename)
    #     img = img.resize((100, 100))
    #     img = ImageTk.PhotoImage(img)
    #     e1 = tk.Label(self.root)
    #     e1.pack()
    #     e1.image = img
    #     e1['image'] = img
    #     self.image_path = filename
    #
    # def send_images(self):
    #     with open(self.image_path, "rb") as image_file:
    #         image_data = base64.b64encode(image_file.read())
    #         self.client.send(f"/image {image_data}".encode('utf-8'))

    def send(self, event=None):
        self.send_message_to_server(self.entry)

    def send_message_to_server(self, entry_widget):
        message = self.entry.get()
        recipient_id = ""

        if message:
            if message.startswith("/private"):
                self.send_private_message_to_server(message)
            else:
                encrypted_message = self.fernet_obj.encrypt(message.encode('utf-8'))
                self.client.send(encrypted_message)

            if self.text:
                if message.startswith("/private"):
                    self.print_sent_private_message(message, recipient_id)
                else:
                    self.text.insert(tk.END, f"You: {message}\n")

            entry_widget.delete(0, tk.END)

    def receive_message(self):
        while True:
            try:
                encrypted_message = self.client.recv(BUFFER_SIZE)
                if not encrypted_message:
                    break
                message = self.fernet_obj.decrypt(encrypted_message).decode('utf-8')
                if self.text:
                    print(message)
                    self.text.insert(tk.END, message + '\n')
            except Exception as e:
                print(f"Error receiving message from server: {e}")
                break

    def send_private_message_to_server(self, message):
        parts = message.split(" ", 2)
        recipient_id = parts[1] if len(parts) > 1 else None
        if recipient_id:
            encrypted_message = self.fernet_obj.encrypt(message.encode('utf-8'))
            self.client.send(encrypted_message)

    def print_sent_private_message(self, message, recipient_id):
        message = message[10 + len(recipient_id):]
        self.text.insert(tk.END, f"Message to {recipient_id}: {message} \n")

    def on_close(self):
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
