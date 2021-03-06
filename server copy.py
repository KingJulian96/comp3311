# encoding:utf-8
from threading import Thread
from collections import defaultdict
from datetime import datetime, timedelta
from socket import *
import os

basedir = os.path.dirname(__file__)
#commands
# in a array
commands = ["block", "logout", "unblock", "whoelse", "broadcast", "whoelsesince"]

# ChatServer is to create a sever object
class ChatServer:
    def __init__(self, server_port: int, block_duration: int, timeout_: int, **kwargs):
        self.server_port = server_port

        self.block_duration = block_duration
        # long log in without doing anything
        self.timeout = timeout_
        self.clients_num = kwargs.get('clients_num', 5)
        #set the buffer size as 1024
        self.recv_size = kwargs.get('recv_size', 1024)

        self.client_auth_info = {}
        self.client_status = {}
        self.auth_block = {}
        self.sockets = {}
        self.login_records = {}

        self.cache_msg = defaultdict(list)
        self.black_list = defaultdict(set) #blooked people

        self.load_auth_info()
    # use the password and username from the credentials
    def load_auth_info(self):
        credentials_path = os.path.abspath(os.path.join(basedir, 'credentials.txt'))
        with open(credentials_path, mode='r') as credentials_file:
            for line in credentials_file.readlines():
                username, password = line.strip().split()
                self.client_auth_info[username] = password

    #recive message and decode with utf-8
    def recv(self, conn: socket):
        request = ''
        while True:
            recv = conn.recv(self.recv_size).decode('utf-8')
            request += recv
            if len(recv) < self.recv_size:
                break
        command, *command_argv = request.split()
        return command, command_argv

    #init sever and notify it
    def run_server(self):
        s = socket(AF_INET, SOCK_STREAM)
        s.bind(('0.0.0.0', self.server_port))
        s.listen(self.clients_num)
        print(f'{datetime.now()} - Server Run on ":{self.server_port}"')

        while True:
            conn, addr = s.accept()
            client_thread = Thread(target=self.handle, args=(conn,))
            client_thread.setDaemon(True)
            client_thread.start()
    #check hit which commmond line has been hitted
    def handle(self, conn: socket):
        # to handld the command
        auth_fail_count = 0
        current_user = None
        while True:
            try:
                command, command_argv = self.recv(conn)
                if command == 'login':

                    username, password = command_argv
                    auth_result = self.auth(username, password, conn)

                    if auth_result is None:
                        conn.close()
                        break

                    if auth_result is False:
                        auth_fail_count += 1
                    elif auth_fail_count == 3:
                        #3 times fail leads to be blocked
                        self.auth_block[username] = datetime.now() + timedelta(seconds=self.block_duration)

                    if auth_result is True:
                        current_user = username
                        auth_fail_count = 0
                        self.sockets[current_user] = conn
                        self.client_status[current_user] = True
                        self.login_records[current_user] = datetime.now()
                        if current_user in self.auth_block:
                            del self.auth_block[current_user]
                        while self.cache_msg[current_user]:
                            msg = self.cache_msg[current_user].pop(0)
                            conn.sendall(msg + '\n'.encode('utf-8'))
                        print(f'{datetime.now()} - Login Success - Username: {current_user}')
                        print('sockets: ', self.sockets.keys())
                        print('status: ', self.client_status.keys())
                elif command == 'message':
                    target_user = command_argv[0]
                    msg = ' '.join(command_argv[1:])
                    self.message(current_user, target_user, msg, conn)
                elif command == 'logout':
                    self.logout(conn)
                    del self.client_status[current_user]
                    del self.sockets[current_user]
                    conn.close()
                    print(f'{datetime.now()} - Logout - Username: {current_user}')
                    print('sockets: ', self.sockets.keys())
                    print('status: ', self.client_status.keys())
                    break
                elif command == 'block':
                    user = command_argv[0]
                    self.block(current_user, user, conn)
                elif command == 'unblock':
                    user = command_argv[0]
                    self.unblock(current_user, user, conn)
                elif command == 'whoelse':
                    self.whoelse(current_user, conn)
                elif command == 'broadcast':
                    msg = ' '.join(command_argv)
                    self.broadcast(current_user, msg)
                elif command == 'whoelsesince':
                    seconds = int(command_argv[0])
                    self.whoelsesince(current_user, seconds, conn)
                else:
                    print(f'Unknown command: {command}')
            except Exception as exc:
                print(repr(exc))
                conn.close()
                break

    def auth(self, username: str, password: str, conn: socket):
        if isinstance(self.auth_block.get(username), datetime) and datetime.now() < self.auth_block.get(username):
            response = 'login block'
            conn.sendall(response.encode('utf-8'))
            return None
        elif self.client_auth_info.get(username) == password:
            self.client_status[username] = True
            response = 'login sucess'
            conn.sendall(response.encode('utf-8'))
            return True
        else:
            response = 'login fail'
            conn.sendall(response.encode('utf-8'))
            return False

    def message(self, current_user, user: str, msg: str, conn: socket):
        sent_message = f"{current_user}: {msg}".encode('utf-8')
        if (current_user == user) or (user not in self.client_auth_info.keys()):
            conn.sendall("Error. Invalid user".encode('utf-8'))
        elif current_user in self.black_list[user]:
            conn.sendall("Your message could not be delivered as the recipient has blocked you".encode())
        elif self.client_status.get(user) is True:
            self.sockets[user].sendall(sent_message)
        else:
            self.cache_msg[user].append(sent_message)
    #broadcast to every one who has not been blokced
    def broadcast(self, current_user: str, msg: str):
        for user in self.client_status.keys():
            if user == current_user:
                continue
            if current_user not in self.black_list[user]:
                self.sockets[user].sendall(f"{current_user}: {msg}".encode())
    #whoelse is on line
    def whoelse(self, current_user: str, conn: socket):
        online_users = list(self.client_status.keys())
        online_users.remove(current_user)
        conn.sendall("\n".join(online_users).encode())
    #todo:testing
    def whoelsesince(self, current_user: str, seconds: int, conn: socket):
        now = datetime.now()
        for user, login_time in self.login_records.items():
            if user == current_user:
                continue
            if abs((now - login_time).total_seconds()) < seconds:
                conn.sendall(user.encode())
    #block people
    def block(self, current_user: str, user: str, conn: socket):
        if user == current_user:
            conn.sendall('Error. Cannot block self'.encode())
        else:
            self.black_list[current_user].add(user)
            conn.sendall(f'{user} is blocked'.encode())
        print(self.black_list)
    #unblock people
    def unblock(self, current_user: str, user: str, conn: socket):
        try:
            self.black_list[current_user].remove(user)
            conn.sendall(f"{user} is unblocked".encode())
        except KeyError:
            conn.sendall(f"Error. {user} was not blocked".encode())
        print(self.black_list)

    @staticmethod
    def logout(conn: socket):
        conn.sendall('logout ok'.encode())


if __name__ == '__main__':
    #set the port number as 5000 (any 4 digrt will do???), block_duration set as 10
    server = ChatServer(server_port=5000, block_duration=10, timeout_=10)
    server.run_server()
