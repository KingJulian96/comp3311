# encoding:utf-8
from threading import Thread
from collections import defaultdict
from datetime import datetime
from socket import *
import os
import sys
import getpass


class ChatClient:
    def __init__(self, server_host: str, server_port: int, **kwargs):
        self.server_host = server_host
        self.server_port = server_port
        self.recv_size = kwargs.get('recv_size', 1024)

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
                print(response)
            except Exception as exc:
                print('Recv: ', {repr(exc)})
                break

    #to create a paket with usaername and password
    #only function that client side need to hanle so far
    def login(self, conn: socket):
        fail_count = 0

        username = input('Username: ')
        while fail_count < 3:
            #change it to getpass
            #password = getpass('Password: ')
            password = getpass.getpass()
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

    @staticmethod
    def input_thread(conn: socket):
        while True:
            try:
                command = input('').encode('utf-8')
                conn.sendall(command)
            except Exception as exc:
                print("Send: ", repr(exc))


if __name__ == '__main__':
    #IP set as the same on from sever.py and it is 127.0.0.1
    #port set as the same on from sever.py and it is 5000
    client = ChatClient('127.0.0.1', 5000)
    client.handle()
