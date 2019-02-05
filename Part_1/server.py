import socket
from threading import Thread
import json
import math
import random
from random import randrange, getrandbits

q = None
alpha = None
X = None
Y = None
Y_client = None
mutual_shared_key = None

def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2

    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

def generate_prime_candidate(length):
    p = getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=20):
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def generate_keys():
    global q
    global alpha
    global X
    global Y
    X = random.randint(2,q-1)
    Y = (alpha**X) % q

def return_roots(num):
    roots_list = []
    while num%2 == 0:
        roots_list.append(2)
        num = num/2
    root = math.sqrt(num)
    i=3
    while i<= root:
        while num%i == 0:
            roots_list.append(i)
            num = num/i
        i+=2
    if num>2:
        roots_list.append(num)
    return list(set(roots_list))

def find_premitive_root(prime):
    roots_list = return_roots(prime-1)
    r=2
    breaked = False
    while r <= (prime-1):
       flag = False
       for root in roots_list:
           to_div = int((prime-1)/root)
           val = (r**to_div) % prime
           if val == 1:
               flag = True
               break
       if flag == False:
           primitive_root = r
           breaked = True
           break
       r+=1

    if breaked == False:
        primitive_root = -1
    return primitive_root

class ListenClients(Thread):
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
        global Y_client
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
            if j["topic"] == "request_keys":
                client_ip = j["ip"]
                client_port = j["port"]
                q = generate_prime_number()
                alpha = find_premitive_root(q)
                generate_keys()
                print("Global Q is: ",q)
                print("Global alpha is: ",alpha)
                print("X_server is: ", X)
                print("Y_server is: ", Y)
                send_data = {}
                send_data["topic"] = "request_keys_resp"
                send_data["data"] = {}
                send_data["data"]["q"] = q
                send_data["data"]["alpha"] = alpha
                send_data["data"]["Y_server"] = Y
                self.send_json_data(client_ip, client_port, send_data)
            elif j["topic"] == "shared_key":
                Y_client = j["data"]["Y_client"]
                print("Y_client is: ", Y_client)
                mutual_shared_key = (Y_client ** X) % q
                print("Mutual Key is: ",mutual_shared_key)
        except:
            print("Error in parsing data: ",data)


self_ip = "10.2.138.136"
self_port = 12008
tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((self_ip, self_port))


while True:
    tcpsock.listen(1000)
    (conn, (ip,port)) = tcpsock.accept()
    listenthread = ListenClients(conn, self_ip, self_port)
    listenthread.daemon = True
    listenthread.start()
