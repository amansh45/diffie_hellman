import socket
import json
from threading import Thread
import random
import sys
import copy

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
clientConnected = False
encoding_copy = None

initial_encoding = [['A', '01'], ['B', '02'], ['C', '03'], ['D', '04'], ['E', '05'], ['F', '06'], ['G', '07'], ['H', '08'],
                    ['I', '09'], ['J', '10'], ['K', '11'], ['L', '12'], ['M', '13'], ['N', '14'], ['O', '15'], ['P', '16'],
                    ['Q', '17'], ['R', '18'], ['S', '19'], ['T', '20'], ['U', '21'], ['V', '22'], ['W', '23'], ['X', '24'],
                    ['Y', '25'], ['Z', '26'], [',', '27'], ['.', '28'], ['?', '29'], ['0', '30'], ['1', '31'], ['2', '32'],
                    ['3', '33'], ['4', '34'], ['5', '35'], ['6', '36'], ['7', '37'], ['8', '38'], ['9', '39'], ['a', '40'],
                    ['b', '41'], ['c', '42'], ['d', '43'], ['e', '44'], ['f', '45'], ['g', '46'], ['h', '47'], ['i', '48'],
                    ['j', '49'], ['k', '50'], ['l', '51'], ['m', '52'], ['n', '53'], ['o', '54'], ['p', '55'], ['q', '56'],
                    ['r', '57'], ['s', '58'], ['t', '59'], ['u', '60'], ['v', '61'], ['w', '62'], ['x', '63'], ['y', '64'],
                    ['z', '65'], ['!', '66']]


def new_encoding(val):
    global encoding_copy
    shift = val%len(initial_encoding)
    encoding_copy = copy.deepcopy(initial_encoding)
    if shift == 0:
        return encoding_copy
    else:
        m_idx = len(initial_encoding) - shift
        p=0
        while m_idx < len(initial_encoding):
            encoding_copy[p][0] = initial_encoding[m_idx][0]
            m_idx+=1
            p+=1
        p = 0
        while shift < len(initial_encoding):
            encoding_copy[shift][0] = initial_encoding[p][0]
            shift+=1
            p+=1

def decrypt(encoded_data):
    decrypted_text = ""
    i=0
    while i<len(encoded_data)-1:
        enc_substr = encoded_data[i]+encoded_data[i+1]
        for enc in encoding_copy:
            if enc_substr == "00":
                decrypted_text = decrypted_text + " "
                break
            elif enc[1] == enc_substr:
                decrypted_text = decrypted_text + enc[0]
                break
        i+=2
    return decrypted_text

def encrypt(data):
    data = str(data)
    encrypted_data = ""
    for char in data:
        if char == " ":
            encrypted_data = encrypted_data + "00"
        for x in encoding_copy:
            if x[0] == char:
                encrypted_data = encrypted_data + x[1]
    return encrypted_data

def generate_key():
    global q
    global alpha
    global X
    global Y
    X = random.randint(2,q-1)
    Y = (alpha**X) % q


class BgClientsAction(object):
    def __init__(self):
        thread = Thread(target=self.run, args=())
        thread.daemon=True
        thread.start()

    def send_json_data(self, ip, port, data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.sendall(str(data).encode())
            s.close()
        except:
            print("Connection refused by the master: "+ip+":"+str(port))

    def run(self):
        global clientConnected
        while True:
            if clientConnected == False:
                continue
            action = input("Input your action: ")
            if action == "LOGINCREATE":
                user_id = input("Input your id: ")
                user_passwd = input("Input your password: ")
                sending_data = {}
                sending_data["topic"] = action
                sending_data["ip"] = self_ip
                sending_data["port"] = self_port
                sending_data["data"] = {}
                sending_data["data"]["id"] = encrypt(user_id)
                sending_data["data"]["password"] = encrypt(user_passwd)
                sending_data["data"]["q"] = encrypt(q)
                self.send_json_data(server_ip, server_port, sending_data)
            elif action == "AUTHREQUEST":
                user_id = input("Input your id: ")
                user_passwd = input("Input your password: ")
                sending_data = {}
                sending_data["topic"] = action
                sending_data["ip"] = self_ip
                sending_data["port"] = self_port
                sending_data["data"] = {}
                sending_data["data"]["id"] = encrypt(user_id)
                sending_data["data"]["password"] = encrypt(user_passwd)
                self.send_json_data(server_ip, server_port, sending_data)
            elif action == "SERVICEREQUEST":
                user_id = input("Input your id: ")
                filename = input("Input the filename: ")
                sending_data = {}
                sending_data["topic"] = action
                sending_data["ip"] = self_ip
                sending_data["port"] = self_port
                sending_data["data"] = {}
                sending_data["data"]["id"] = encrypt(user_id)
                sending_data["data"]["filename"] = encrypt(filename)
                self.send_json_data(server_ip, server_port, sending_data)

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
        global clientConnected
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
                new_encoding(mutual_shared_key)
                clientConnected = True
                self.send_json_data(server_ip, server_port, sharing_data)
            elif j["topic"] == "LOGINREPLY":
                print(j["description"])
            elif j["topic"] == "AUTHREPLY":
                print(j["description"])
            elif j["topic"] == "SERVICEDONE":
                print(j["description"])
        except:
            print("Recieved data from the server: ")
            decrypted_data = decrypt(data)
            print(decrypted_data)

self_ip = sys.argv[1]
self_port = int(sys.argv[2])

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.connect((server_ip, server_port))

listensock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listensock.bind((self_ip, self_port))

bgthread = BgClientsAction()

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

