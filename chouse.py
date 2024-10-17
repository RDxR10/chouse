import time
import threading
import bcrypt
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.profile = {"bio": "", "interests": []}
        self.role = "user"

class Message:
    def __init__(self, sender, content, timestamp):
        self.sender = sender
        self.content = content
        self.timestamp = timestamp
        self.edited = False

class Room:
    def __init__(self, name, creator, category):
        self.name = name
        self.creator = creator
        self.category = category
        self.members = set([creator])
        self.messages = []
        self.banned_users = set()
        self.muted_users = set()

class Clubhouse:
    def __init__(self):
        self.users = {}
        self.rooms = {}
        self.categories = set(["General", "Technology", "Sports", "Music", "Art"])

    def register_user(self, username, password):
        if username not in self.users:
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            self.users[username] = User(username, hashed_password)
            print(f"User {username} registered successfully")
        else:
            print(f"Username {username} already exists")

    def authenticate_user(self, username, password):
        if username in self.users:
            stored_password = self.users[username].password
            return bcrypt.checkpw(password.encode('utf-8'), stored_password)
        return False

    def update_profile(self, username, bio, interests):
        if username in self.users:
            self.users[username].profile["bio"] = bio
            self.users[username].profile["interests"] = interests
            print(f"Profile updated for {username}")
        else:
            print(f"User {username} not found")

    def create_room(self, room_name, creator, category):
        if room_name not in self.rooms:
            if category not in self.categories:
                print(f"Invalid category. Available categories: {', '.join(self.categories)}")
                return
            self.rooms[room_name] = Room(room_name, creator, category)
            print(f"Room '{room_name}' created by {creator} in category {category}")
        else:
            print(f"Room '{room_name}' already exists")

    def join_room(self, room_name, user):
        if room_name in self.rooms:
            room = self.rooms[room_name]
            if user in room.banned_users:
                print(f"{user} is banned from room '{room_name}'")
            else:
                room.members.add(user)
                print(f"{user} joined room '{room_name}'")
        else:
            print(f"Room '{room_name}' does not exist")

    def leave_room(self, room_name, user):
        if room_name in self.rooms and user in self.rooms[room_name].members:
            self.rooms[room_name].members.remove(user)
            print(f"{user} left room '{room_name}'")
        else:
            print(f"{user} is not in room '{room_name}'")

    def send_message(self, room_name, sender, content):
        if room_name in self.rooms and sender in self.rooms[room_name].members:
            room = self.rooms[room_name]
            if sender in room.muted_users:
                print(f"{sender} is muted in room '{room_name}'")
            else:
                encrypted_content = self.encrypt_message(content)
                message = Message(sender, encrypted_content, time.time())
                room.messages.append(message)
                print(f"Message sent to room '{room_name}'")
        else:
            print(f"Cannot send message. {sender} is not in room '{room_name}'")

    def get_messages(self, room_name, user):
        if room_name in self.rooms and user in self.rooms[room_name].members:
            decrypted_messages = []
            for message in self.rooms[room_name].messages:
                try:
                    decrypted_content = self.decrypt_message(message.content)
                    decrypted_messages.append((message.sender, decrypted_content, message.timestamp, message.edited))
                except Exception as e:
                    print(f"Error decrypting message: {e}")
            return decrypted_messages
        else:
            print(f"Cannot view messages. {user} is not in room '{room_name}'")
            return []

    def edit_message(self, room_name, user, message_index, new_content):
        if room_name in self.rooms and user in self.rooms[room_name].members:
            room = self.rooms[room_name]
            if 0 <= message_index < len(room.messages):
                message = room.messages[message_index]
                if message.sender == user:
                    message.content = self.encrypt_message(new_content)
                    message.edited = True
                    print("Message edited successfully")
                else:
                    print("You can only edit your own messages")
            else:
                print("Invalid message index")
        else:
            print(f"Cannot edit message. {user} is not in room '{room_name}'")

    def delete_message(self, room_name, user, message_index):
        if room_name in self.rooms and user in self.rooms[room_name].members:
            room = self.rooms[room_name]
            if 0 <= message_index < len(room.messages):
                message = room.messages[message_index]
                if message.sender == user or self.users[user].role in ["admin", "moderator"]:
                    del room.messages[message_index]
                    print("Message deleted successfully")
                else:
                    print("You don't have permission to delete this message")
            else:
                print("Invalid message index")
        else:
            print(f"Cannot delete message. {user} is not in room '{room_name}'")

    def search_rooms(self, query):
        results = []
        for room_name, room in self.rooms.items():
            if query.lower() in room_name.lower() or query.lower() in room.category.lower():
                results.append((room_name, room.category))
        return results

    def set_user_role(self, admin, target_user, new_role):
        if self.users[admin].role == "admin":
            if target_user in self.users:
                self.users[target_user].role = new_role
                print(f"{target_user}'s role has been set to {new_role}")
            else:
                print(f"User {target_user} not found")
        else:
            print("Only admins can set user roles")

    def kick_user(self, moderator, room_name, target_user):
        if room_name in self.rooms:
            room = self.rooms[room_name]
            if self.users[moderator].role in ["admin", "moderator"]:
                if target_user in room.members:
                    room.members.remove(target_user)
                    print(f"{target_user} has been kicked from {room_name}")
                else:
                    print(f"{target_user} is not in {room_name}")
            else:
                print("You don't have permission to kick users")
        else:
            print(f"Room {room_name} not found")

    def ban_user(self, moderator, room_name, target_user):
        if room_name in self.rooms:
            room = self.rooms[room_name]
            if self.users[moderator].role in ["admin", "moderator"]:
                room.banned_users.add(target_user)
                if target_user in room.members:
                    room.members.remove(target_user)
                print(f"{target_user} has been banned from {room_name}")
            else:
                print("You don't have permission to ban users")
        else:
            print(f"Room {room_name} not found")

    def mute_user(self, moderator, room_name, target_user):
        if room_name in self.rooms:
            room = self.rooms[room_name]
            if self.users[moderator].role in ["admin", "moderator"]:
                room.muted_users.add(target_user)
                print(f"{target_user} has been muted in {room_name}")
            else:
                print("You don't have permission to mute users")
        else:
            print(f"Room {room_name} not found")

    def encrypt_message(self, message):
        key = os.urandom(16)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(key + iv + ciphertext).decode('utf-8')

    def decrypt_message(self, encrypted_message):
        decoded = base64.b64decode(encrypted_message.encode('utf-8'))
        key = decoded[:16]
        iv = decoded[16:32]
        ciphertext = decoded[32:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def search_messages(self, room_name, user, query):
        if room_name in self.rooms and user in self.rooms[room_name].members:
            matching_messages = []
            room = self.rooms[room_name]
            for i, message in enumerate(room.messages):
                decrypted_content = self.decrypt_message(message.content)
                if query.lower() in decrypted_content.lower():
                    matching_messages.append((i, message.sender, decrypted_content, message.timestamp, message.edited))
            return matching_messages
        else:
            print(f"Cannot search messages. {user} is not in room '{room_name}'")
            return []

def user_interface(clubhouse, username):
    while True:
        print("\n--- Clubhouse Menu ---")
        print("1. Update profile")
        print("2. Create a room")
        print("3. Join a room")
        print("4. Leave a room")
        print("5. Send a message to a room")
        print("6. View messages in a room")
        print("7. Edit a message")
        print("8. Delete a message")
        print("9. Search rooms")
        print("10. Moderation actions")
        print("11. Search messages")
        print("12. Exit")

        choice = input("Enter your choice (1-12): ")

        if choice == '1':
            bio = input("Enter your bio: ")
            interests = input("Enter your interests (comma-separated): ").split(',')
            clubhouse.update_profile(username, bio, interests)
        elif choice == '2':
            room_name = input("Enter room name: ")
            category = input(f"Enter room category {clubhouse.categories}: ")
            clubhouse.create_room(room_name, username, category)
        elif choice == '3':
            room_name = input("Enter room name to join: ")
            clubhouse.join_room(room_name, username)
        elif choice == '4':
            room_name = input("Enter room name to leave: ")
            clubhouse.leave_room(room_name, username)
        elif choice == '5':
            room_name = input("Enter room name to send message: ")
            message = input("Enter your message: ")
            clubhouse.send_message(room_name, username, message)
        elif choice == '6':
            room_name = input("Enter room name to view messages: ")
            messages = clubhouse.get_messages(room_name, username)
            print(f"\nMessages in room '{room_name}':")
            for i, (sender, msg, timestamp, edited) in enumerate(messages):
                edit_status = " (edited)" if edited else ""
                print(f"{i}. [{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}] {sender}: {msg}{edit_status}")
        elif choice == '7':
            room_name = input("Enter room name: ")
            message_index = int(input("Enter message index to edit: "))
            new_content = input("Enter new message content: ")
            clubhouse.edit_message(room_name, username, message_index, new_content)
        elif choice == '8':
            room_name = input("Enter room name: ")
            message_index = int(input("Enter message index to delete: "))
            clubhouse.delete_message(room_name, username, message_index)
        elif choice == '9':
            query = input("Enter search query: ")
            results = clubhouse.search_rooms(query)
            print("Search results:")
            for room_name, category in results:
                print(f"- {room_name} (Category: {category})")
        elif choice == '10':
            if clubhouse.users[username].role in ["admin", "moderator"]:
                print("\nModeration Actions:")
                print("1. Set user role")
                print("2. Kick user")
                print("3. Ban user")
                print("4. Mute user")
                mod_choice = input("Enter your choice (1-4): ")
                if mod_choice == '1':
                    target_user = input("Enter target username: ")
                    new_role = input("Enter new role (admin/moderator/user): ")
                    clubhouse.set_user_role(username, target_user, new_role)
                elif mod_choice == '2':
                    room_name = input("Enter room name: ")
                    target_user = input("Enter target username: ")
                    clubhouse.kick_user(username, room_name, target_user)
                elif mod_choice == '3':
                    room_name = input("Enter room name: ")
                    target_user = input("Enter target username: ")
                    clubhouse.ban_user(username, room_name, target_user)
                elif mod_choice == '4':
                    room_name = input("Enter room name: ")
                    target_user = input("Enter target username: ")
                    clubhouse.mute_user(username, room_name, target_user)
                else:
                    print("Invalid choice")
            else:
                print("You don't have permission to perform moderation actions")
        elif choice == '11':
            room_name = input("Enter room name to search messages: ")
            query = input("Enter search query: ")
            matching_messages = clubhouse.search_messages(room_name, username, query)
            if matching_messages:
                print(f"Messages containing '{query}' in room '{room_name}':")
                for i, (index, sender, content, timestamp, edited) in enumerate(matching_messages):
                    edit_status = " (edited)" if edited else ""
                    print(f"{i}. [{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}] {sender}: {content}{edit_status}")
            else:
                print(f"No messages found containing '{query}'")
        elif choice == '12':
            print("Exiting Clubhouse. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    clubhouse = Clubhouse()

    print("Welcome to the Clubhouse!")
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            username = input("Enter a username: ")
            password = input("Enter a password: ")
            clubhouse.register_user(username, password)
        elif choice == '2':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            if clubhouse.authenticate_user(username, password):
                print(f"Welcome back, {username}!")
                user_thread = threading.Thread(target=user_interface, args=(clubhouse, username))
                user_thread.start()
                user_thread.join()
                break
            else:
                print("Invalid username or password")
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
