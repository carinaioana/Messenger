import base64
import io
import os.path
import socket
import threading
import time
import tkinter as tk
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import logging

DARK_BLUE = "#283593"
LIGHT_BLUE = "#4a90e2"

WHITE = "#ffffff"
BLACK = "#000000"

FONT_NAME = "Arial"
FONT_SIZE = 12
BUFFER_SIZE = 1024


class ChatApplication:
    def __init__(self):
        self.recipient_entry = None
        self.image_references = []
        self.client_id = None
        self.entry = None
        self.text = None

        self.fernet_key = None
        self.fernet_obj = None

        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            filename='files/client.log',
                            filemode='a')

        # socket connection
        self.host = '127.0.0.1'
        self.port = 55555

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        self.root = tk.Tk()
        self.root.title("Login")

        self.create_login_widgets()

    def create_login_widgets(self):
        """created the login window to display an entry for clientID and a button to send"""
        self.root.configure(bg=LIGHT_BLUE)

        label = tk.Label(self.root, text="Enter your ID: ", bg=LIGHT_BLUE, fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        label.pack()

        self.entry = tk.Entry(self.root, bg=WHITE, fg=LIGHT_BLUE, font=(FONT_NAME, FONT_SIZE))
        self.entry.pack()

        self.entry.bind("<Return>", self.login)

        button_login = tk.Button(self.root, text="Login", command=self.login, bg=WHITE, fg=DARK_BLUE,
                                 font=(FONT_NAME, FONT_SIZE))
        button_login.pack()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def login(self, event=None):
        try:
            # generates a unique key for every client that logs in
            self.fernet_key = Fernet.generate_key()
            self.fernet_obj = Fernet(self.fernet_key)

            self.client_id = self.entry.get().strip()
            if self.client_id:
                # sends the id to the server and waits for response
                self.client.send(self.client_id.encode('utf-8'))
                server_response = self.client.recv(1024).decode('utf-8')

                # if the clientID has been already used gives the user a message to try another one
                if server_response == "This ID is already in use. Please try another ID.":
                    messagebox.showerror("Login Failed", "This ID is already in use. Please try another ID.")
                    return
                elif server_response.startswith("You are connected to the server. You can start chatting"):
                    # after successful login it sends the key generated for the client
                    self.client.send(self.fernet_key)
                    # opens the chat window
                    self.create_chat_window()
                    if self.text:
                        self.text.config(state=tk.NORMAL)
                        self.text.insert(tk.END, server_response + '\n')
                        self.text.config(state=tk.DISABLED)
        except Exception as e:
            logging.error(f"Unexpected error during login: {e}")
            messagebox.showerror("Login Error", "An unexpected error during login occurred.")

    def create_chat_window(self):
        self.destroy_widgets()

        self.root.title("Chat Application")
        self.root.configure(bg=LIGHT_BLUE)

        # text widget
        self.text = tk.Text(self.root, bg=WHITE, fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        self.text.config(state=tk.DISABLED)

        scrollbar = tk.Scrollbar(self.root, command=self.text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.configure(yscrollcommand=scrollbar.set)

        self.text.pack(pady=10, expand=True, fill=tk.BOTH)

        # buttons
        send_image_button = tk.Button(self.root, text="Send Image", command=self.send_type_popup, bg=WHITE,
                                      fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        send_image_button.pack(padx=(40, 5), side=tk.LEFT)

        emoji_button = tk.Button(self.root, text="Emoji List", command=self.emoji_window, bg=WHITE,
                                 fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        emoji_button.pack(padx=10, side=tk.LEFT)

        send_button = tk.Button(self.root, text="Send", command=lambda: self.send(self.entry), bg=WHITE,
                                fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        send_button.pack(padx=(15, 30), side=tk.RIGHT)

        # entry widget
        self.entry = tk.Entry(self.root, width=50, bg=WHITE, fg=LIGHT_BLUE, font=(FONT_NAME, FONT_SIZE))
        self.entry.pack(pady=(5, 0))
        self.entry.bind("<Return>", self.send)

        # starts the thread that lets the client listen for messages from the server
        threading.Thread(target=self.receive_message, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def emoji_window(self):
        emoji_data = {}

        # takes the path from computer and creates the path for the emoji_list file
        folder_path = os.path.abspath("files")
        full_path = folder_path + "\\emoji_list"

        # takes every line from the file and splits them into emoji and description
        with open(full_path, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split('\t')
                if len(parts) == 2:
                    emoji, description = parts
                    emoji_data[emoji] = description

        # creates a new window
        emoji_window = Toplevel(self.root)
        emoji_window.geometry("750x250")
        emoji_window.title("Emoji List")
        emoji_label = tk.Label(emoji_window, text="Choose an emoji and click on it to put it in your conversation",
                               bg=LIGHT_BLUE, fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        emoji_label.pack()

        emoji_text = tk.Text(emoji_window, bg=WHITE, fg=DARK_BLUE, font=(FONT_NAME, FONT_SIZE))
        emoji_text.pack()

        # inserts the dictionary created into the text widget
        for emoji_char in emoji_data:
            emoji_text.insert(END, emoji_char + ' ' + emoji_data[emoji_char] + "\n")

        emoji_text.bind("<Button-1>", self.insert_emoji)

        emoji_text.config(state=tk.DISABLED)

    def insert_emoji(self, event):
        emoji_text = event.widget  # gets the text widget in the mouse is clicked
        clicked_index = emoji_text.index(f"@{event.x},{event.y}")  # takes the mouse-click coordinates
        # retrieves the entire line where the click occurred
        line = emoji_text.get(f"{clicked_index} linestart", f"{clicked_index} lineend")
        emoji_char = line.split()[0]  # takes the emoji

        self.entry.insert(tk.END, emoji_char)

    def send_type_popup(self):
        """creates a window where the user can pick how to send the image: in private/to everyone"""
        send_type_popup = tk.Toplevel(self.root)
        send_type_popup.title("Send Image")

        message = tk.Label(send_type_popup, text="How would you like to send the image?")
        message.pack()

        private_image_button = tk.Button(send_type_popup, text="Send Privately",
                                         command=self.send_image_privately_popup)
        private_image_button.pack(side="left", padx=10, pady=10)

        everyone_image_button = tk.Button(send_type_popup, text="Send to Everyone",
                                          command=lambda: self.send_image("everyone"))
        everyone_image_button.pack(side="right", padx=10, pady=10)

    def send_image_privately_popup(self):
        """creates a window where the user needs to enter the clientID to whom he wants to send the image to"""
        send_recipients_popup = tk.Toplevel(self.root)
        send_recipients_popup.title("Send Image")

        message = tk.Label(send_recipients_popup, text="Whom would you like to send the image to?")
        message.pack()
        # the user can write a list of clients separated by commas
        self.recipient_entry = tk.Entry(send_recipients_popup)
        self.recipient_entry.pack()

        send_button = tk.Button(send_recipients_popup, text="Send", command=lambda: self.send_image("private"))
        send_button.pack(side="right", padx=10, pady=10)

    def send_image(self, choice):
        # if the image is sent privately calls the function with the user list as parameter
        if choice == "private":
            self.read_image_and_send(self.recipient_entry.get())
        # if the image is sent to everyone
        elif choice == "everyone":
            self.read_image_and_send()

    def read_image_and_send(self, recipients_ids=None):
        try:
            # opens the files from computer with the specified format
            filepath = filedialog.askopenfilename(filetypes=[('Jpg Files', '*.jpg'), ('PNG Files', '*.png')])
            if filepath:
                # if the user wants to send privately, it sends to the server a signal(`/pimage`) followed by the
                # recipient list
                if recipients_ids:
                    self.client.send(self.fernet_obj.encrypt("/pimage".encode('utf-8')))
                    self.client.send(self.fernet_obj.encrypt(recipients_ids.encode('utf-8')))
                # if the user wants to send to everyone, it sends to the server a signal(`/image`)
                else:
                    self.client.send(self.fernet_obj.encrypt("/image".encode('utf-8')))

                with open(filepath, 'rb') as image_file:
                    image_data = image_file.read()
                    base64_encoded_image = base64.b64encode(image_data)

                    # displays the image in the senders chat
                    self.text.config(state=tk.NORMAL)
                    self.text.insert(tk.END, f"You: ")
                    self.display_image(base64_encoded_image)
                    self.text.insert(tk.END, f"\n")
                    self.text.config(state=tk.DISABLED)
                    time.sleep(0.1)

                    # sends to the server the encoded image and the signal(`/end`) that marks the end of the image
                    self.client.send(base64_encoded_image + b"/end")
            else:
                logging.error("No filepath selected.")
        except socket.error as e:
            logging.error("Connection Error", f"Failed to send image: {e}")

    def send(self, event=None):
        self.send_message(self.entry)

    def send_message(self, entry_widget):
        try:
            # takes the text written in the entry widget
            message = self.entry.get()
            recipient_id = ""

            if message:
                if message.startswith("/private"):
                    parts = message.split(" ", 2)
                    # takes the second part of the message and assigns it to recipientsID
                    recipient_id = parts[1] if len(parts) > 1 else None
                    self.send_private_message(message, recipient_id)
                    logging.info(f"Sent private message (to server) to {recipient_id}.")
                else:
                    encrypted_message = self.fernet_obj.encrypt(message.encode('utf-8'))
                    self.client.send(encrypted_message)  # sends the encrypted message to the server
                    logging.info(f"Sent message (to server) to everyone.")

                if self.text:
                    self.text.config(state=tk.NORMAL)
                    # displays the message on the senders chat
                    if message.startswith("/private"):
                        if recipient_id:
                            message = message[10 + len(recipient_id):]
                            self.text.insert(tk.END, f"Message to {recipient_id}: {message} \n")
                    else:
                        self.text.insert(tk.END, f"You: {message}\n")
                    self.text.config(state=tk.DISABLED)
                entry_widget.delete(0, tk.END)
        except Exception as e:
            logging.error(f"Unexpected error in send_message: {e}")

    def receive_message(self):
        while True:
            try:
                encrypted_message = self.client.recv(BUFFER_SIZE)
                logging.info("Message received from server.")
                if not encrypted_message:
                    break
                message = self.fernet_obj.decrypt(encrypted_message)
                # if it is an image
                if message[:6] == b"/image":
                    receiving_image = True
                    image_data = b""
                    # receives the image in chunks until it reaches the `/end` marker
                    while receiving_image:
                        image_data_chunk = self.client.recv(BUFFER_SIZE)
                        if image_data_chunk.endswith(b"/end"):
                            image_data += image_data_chunk[:-4]
                            receiving_image = False
                        else:
                            image_data += image_data_chunk
                    # receives the sender_id from the server and calls display_image
                    self.text.config(state=tk.NORMAL)
                    sender_id = self.client.recv(BUFFER_SIZE)
                    sender_id = self.fernet_obj.decrypt(sender_id)
                    self.text.insert(tk.END, sender_id)
                    self.display_image(image_data)
                    self.text.insert(tk.END, '\n')
                    self.text.config(state=tk.DISABLED)
                elif self.text:
                    # if it is a text it displays the string
                    self.text.config(state=tk.NORMAL)
                    message = message.decode('utf-8')
                    self.text.insert(tk.END, message + '\n')
                    self.text.config(state=tk.DISABLED)
            except Exception as e:
                logging.error(f"Error receiving message from server: {e}")
                break

    def display_image(self, image_data):
        try:
            decoded_image_data = base64.b64decode(image_data)  # decodes image from base64 to binary
            image = Image.open(io.BytesIO(decoded_image_data))  # creates an image object from the decoded data (PIL)
            image.thumbnail((400, 400))  # resizes the image
            photo = ImageTk.PhotoImage(image)  # converts the PIL image object into tk
            # stores the reference to the Tk image in a list to prevent it from being garbage-collected
            self.image_references.append(photo)
            # inserts the image in the text widget
            self.text.image_create(tk.END, image=photo)
            self.text.insert(tk.END, '\n')
        except Exception as e:
            logging.error(f"Error displaying image: {e}")

    def send_private_message(self, message, recipient_id):
        """sends the private message encrypted to the server"""
        if recipient_id:
            encrypted_message = self.fernet_obj.encrypt(message.encode('utf-8'))
            self.client.send(encrypted_message)

    def on_close(self):
        try:
            if messagebox.askokcancel("Quit", "Do you want to quit?"):
                self.client.send("quit".encode('utf-8'))
                self.client.close()
                self.root.destroy()
        except Exception as e:
            logging.error(f"Error closing the application: {e}")

    def destroy_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    chat_app = ChatApplication()
    tk.mainloop()
