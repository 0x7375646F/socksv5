import socket
import threading 
import select

SOCKS_VERSION = 5

class Proxy:
    def __init__(self,username,password):
        self.username = username
        self.password = password
    
    def handle_auth_methods(self,nmethods,connection):
        methods = []
        for i in range(nmethods):
            methods.append(connection.recv(1)[0])
        return methods
    
    def handle_auth_cred(self,addr,connection):
        #    +----+------+----------+------+----------+
        #    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        #    +----+------+----------+------+----------+
        #    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        #    +----+------+----------+------+----------+
        authver, len_user = connection.recv(2)
        username = connection.recv(len_user).decode('utf-8')
        len_pass = connection.recv(1)[0]
        password = connection.recv(len_pass).decode('utf-8')
        if username == self.username and password == self.password:
            connection.sendall(bytes([authver,0]))
            return True
        print(f"[!] Invalid Creds: ({username}/{password}) From {addr}")
        connection.sendall(bytes([authver,0xFF]))
        connection.close()
        return False

    def generate_fail_reply(self,addr_type,err_code):
        return b''.join([
            SOCKS_VERSION.to_bytes(1,'big'),
            err_code.to_bytes(1,'big'),
            int(0).to_bytes(1,'big'),
            addr_type.to_bytes(1,'big'),
            int(0).to_bytes(4,'big'),
            int(0).to_bytes(2,'big'),
        ])

    def exchange_data(self,client,remote):
        try:
            while True:
                r, w, e = select.select([client, remote], [], [])
                if client in r:
                    data = client.recv(4096)
                    if not data:  # If no data is received, close the connection
                        break
                    remote.sendall(data)

                if remote in r:
                    data = remote.recv(4096)
                    if not data:  # If no data is received, close the connection
                        break
                    client.sendall(data)

        except ConnectionResetError:
            print("[!] Connection reset by peer")
        except BrokenPipeError:
            print("[!] Broken pipe error - client or server closed connection unexpectedly")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

    def conn_handler(self,addr,connection):
        # receive socks version, methods supported
                #    +----+----------+----------+
                #    |VER | NMETHODS | METHODS  |
                #    +----+----------+----------+
                #    | 1  |    1     | 1 to 255 |
                #    +----+----------+----------+
        version, nmethods = connection.recv(2)
        if version != SOCKS_VERSION:
            print(f"[!] Invalid Socks Version From {addr}")
            connection.close()
            return
        # check if user/pass authentication method is supported
        auth_methods = self.handle_auth_methods(nmethods,connection)
        # if not supported close the connection
        if 2 not in set(auth_methods):
            print(f"[!] User Authentication Not Supported From {addr}")
            connection.close()
            return
        
        # selecting user/pass authentication method
                        # +----+--------+
                        # |VER | STATUS |
                        # +----+--------+
                        # | 1  |   1    |
                        # +----+--------+
        connection.sendall(bytes([SOCKS_VERSION,2]))
        if not self.handle_auth_cred(addr,connection): 
            return

        try:
            # +----+-----+-------+------+----------+----------+
            # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+
            version, cmd, _, address_type = connection.recv(4)
            if address_type == 1: #IPv4
                address = socket.inet_ntoa(connection.recv(4))
            elif address_type == 3: # Domain
                len_domain = connection.recv(1)[0]
                address = connection.recv(len_domain)
                address = socket.gethostbyname(address)
            port = int.from_bytes(connection.recv(2),'big',signed=False)

            if cmd == 1:
                # Establishing Connection To Destination Address and Port
                remote = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                remote.connect((address,port))
                bind_address = remote.getsockname()
                print(f"[*] Established connection to {address} {port}")
            else:
                print(f"[!] Not supported cmd")
                connection.close()
                return

            addr = int.from_bytes(socket.inet_aton(bind_address[0]),'big',signed=False)
            port = bind_address[1]
            # +----+-----+-------+------+----------+----------+
            # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1,'big'), #version
                int(0).to_bytes(1,'big'), # status
                int(0).to_bytes(1,'big'), # reserved
                int(1).to_bytes(1,'big'), # addr_type
                addr.to_bytes(4,'big'), # ipv4 addr
                port.to_bytes(2,'big'), # port
            ])
        except Exception as e:
            reply = self.generate_fail_reply(address_type,5)
        connection.sendall(reply)
        
        if reply[1] == 0 and cmd == 1:
            self.exchange_data(connection,remote)
            remote.close()
        connection.close()

    def run(self,host,port):
        # listener
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,port))
        s.listen()
        print(f"[+] Socks5 Proxy Is Running On: {host}:{port}")
        try:
            while True:
                # accept incoming connections
                conn, addr = s.accept()
                print(f"[*] New Connection From {addr}")
                t = threading.Thread(target=self.conn_handler,args=(addr,conn,))
                t.start()
        except KeyboardInterrupt:
            print("[-] Closing Socks5 Proxy!")
            s.close()

if __name__ == "__main__":
    proxy = Proxy("hecker","hecker1337")
    proxy.run("127.0.0.1",8080)
