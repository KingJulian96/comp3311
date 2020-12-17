# encoding:utf-8
from threading import Thread
from socket import *
import argparse
import sys
# for * of the password
import getpass

class ChatClient:
    def __init__(self, server_host: str, server_port: int, **kwargs):
        self.server_host = server_host
        self.server_port = server_port
        self.recv_size = kwargs.get('recv_size', 1024)

        self.name = None

        self.private_port = kwargs.get('private_port', 5001)
        self.private_clients = kwargs.get('private_clients', 5)
        self.private_socket = None
        self.private_user = None

    def recv(self, conn: socket):
        response = ''
        while True:
            recv = conn.recv(self.recv_size).decode('utf-8')
            response += recv
            if len(recv) < self.recv_size:
                break
        return response

    def handle(self):
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((self.server_host, self.server_port))
        self.login(s)

        input_thread = Thread(target=self.input_thread, args=(s,))
        input_thread.setDaemon(True)
        input_thread.start()

        while True:
            try:
                response = self.recv(s)
                if response == 'logout ok':
                    s.close()
                    sys.exit()
                elif response == 'client timeout':
                    print('Client Timeout')
                    s.close()
                    sys.exit()
                elif response[:8] == 'private@':
                    self.private_user = response[8:]
                    private_thread = Thread(target=self.private_thread, args=())
                    private_thread.setDaemon(True)
                    private_thread.start()
                    s.sendall(f"private_port {self.private_port}{response[7:]}".encode())
                    continue
                elif response[:12] == 'private_info':
                    _, target_host = response.split()
                    ip, port = target_host.split(':')
                    private_socket = socket(AF_INET, SOCK_STREAM)
                    private_socket.connect((ip, int(port)))
                    self.private_socket = private_socket

                    private_recv_thread = Thread(target=self.private_recv_thread, args=())
                    private_recv_thread.setDaemon(True)
                    private_recv_thread.start()
                    print(f"Start private messaging with {self.private_user}")
                    continue
                print(response)
            except Exception as exc:
                print('Recv: ', {repr(exc)})
                sys.exit()
    #to create a paket with usaername and password
    #only function that client side need to hanle so far
    def login(self, conn: socket):
        fail_count = 0
        username = input('Username: ')
        self.name = username
        while fail_count < 3:
            #password = input('Password: ')
            password = getpass.getpass('Password: ')
            conn.sendall(f"login {username} {password}".encode('utf-8'))
            response = self.recv(conn)
            if response == 'login sucess':
                print('Welcome to the greatest messaging application ever!')
                break
            elif response == 'login block':
                print('Your account is blocked due to multiple login failures. Please try again later')
                conn.close()
                sys.exit()
            else:
                fail_count += 1
                if fail_count == 3:
                    print('Invalid Password. Your account has been blocked. Please try again later')
                    conn.close()
                    sys.exit()
                else:
                    print('Invalid Password. Please try again')

    def input_thread(self, conn: socket):
        while True:
            try:
                command = input('')
                if command[:12] == 'startprivate':
                    _, private_user = command.split()
                    self.private_user = private_user
                if command[:11] == 'stopprivate':
                    _, private_user = command.split()
                    if private_user == self.private_user:
                        self.private_socket.sendall("stopprivate".encode())
                        self.private_socket.close()
                        self.private_socket = None
                        self.private_user = None
                elif command[:7] == 'private':
                    _, private_user, *msg = command.split()
                    msg = ' '.join(msg)
                    if private_user != self.private_user:
                        print(f'Error. Private messaging to {private_user} not enabled')
                        continue
                    self.private_socket.sendall(f"{self.name}(private): {msg}".encode())
                else:
                    conn.sendall(command.encode('utf-8'))
            except Exception as exc:
                print("Send: ", repr(exc))

    def private_thread(self):
        s = socket(AF_INET, SOCK_STREAM)
        s.bind(('0.0.0.0', self.private_port))
        s.listen(self.private_clients)

        conn, addr = s.accept()
        self.private_socket = conn
        while True:
            try:
                request = self.recv(conn)
                if request == 'stopprivate':
                    self.private_socket.close()
                    self.private_socket = None
                    self.private_user = None
                    break
                print(request)
            except:
                break

    def private_recv_thread(self):
        while True:
            try:
                response = self.recv(self.private_socket)
                if response == 'stopprivate':
                    self.private_socket.close()
                    self.private_socket = None
                    self.private_user = None
                    break
                print(response)
            except:
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-host', '-s', help='Server Host', required=True)
    parser.add_argument('--server-port', '-p', help='Server Port', required=True)
    args = parser.parse_args()

    client = ChatClient(
        server_host=args.server_host,
        server_port=int(args.server_port)
    )
    '''
    #IP set as the same on from sever.py and it is 127.0.0.1
    #port set as the same on from sever.py and it is 5000
    client = ChatClient('127.0.0.1', 5000)
    '''
    client.handle()
