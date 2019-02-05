import socket
import json
from threading import Thread
import random
import sys

self_ip = "10.2.138.136"
self_port = 12004

server_ip = "10.2.138.136"
server_port = 12008

q = None
alpha = None
X = None
Y = None
Y_server = None
mutual_shared_key = None

def generate_key():
    global q
    global alpha
    global X
    global Y
    X = random.randint(2,q-1)
    Y = (alpha**X) % q


class ListenServer(Thread):
    def __init__(self, sock, self_ip, self_port):
        Thread.__init__(self)
        self.sock = sock
        self.ip = self_ip
        self.port = self_port
        self.RCVCHUNKSIZE = 1024*1024*64

    def send_json_data(self, ip, port, data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.sendall(str(data).encode())
            s.close()
        except:
            print("Connection refused by the master: "+ip+":"+str(port))

    def run(self):
        global q
        global alpha
        global Y_server
        global mutual_shared_key
        data = []
        while True:
            data_rcv = self.sock.recv(self.RCVCHUNKSIZE)
            if not data_rcv:
                break
            data.append(data_rcv)
        data = b''.join(data)

        try:
            data = data.decode()
            data = data.replace("\'", "\"")
            j = json.loads(data)
            if j["topic"] == "request_keys_resp":
                q = j["data"]["q"]
                alpha = j["data"]["alpha"]
                Y_server = j["data"]["Y_server"]
                generate_key()
                print("Global Q is: ",q)
                print("Global alpha is: ",alpha)
                print("X_client is: ", X)
                print("Y_client is: ", Y)
                print("Y_server is: ",Y_server)
                mutual_shared_key = (Y_server ** X) % q
                print("Mutual Key is: ",mutual_shared_key)
                sharing_data = {}
                sharing_data["topic"] = "shared_key"
                sharing_data["ip"] = self.ip
                sharing_data["port"] = self.port
                sharing_data["data"] = {}
                sharing_data["data"]["Y_client"] = Y
                self.send_json_data(server_ip, server_port, sharing_data)
        except:
            print("Error in parsing data: ",data)

self_ip = sys.argv[1]
self_port = int(sys.argv[2])

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.connect((server_ip, server_port))

listensock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listensock.bind((self_ip, self_port))

initial_boot = {}
initial_boot["topic"] = "request_keys"
initial_boot["data"] = {}
initial_boot["ip"] = self_ip
initial_boot["port"] = self_port
tcpsock.sendall(str(initial_boot).encode())
tcpsock.close()

while True:
    listensock.listen(10)
    (conn, (ip,port)) = listensock.accept()
    listenthread = ListenServer(conn, self_ip, self_port)
    listenthread.daemon = True
    listenthread.start()

