from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
from Crypto.Util.number import*
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from math import gcd
import random
import os
from cryptography.hazmat.backends import default_backend

class client:
        def __init__(self):
                self.version={'TLS1.2':b'\x03\x03'}
                self.ciphers=[b'\xc0\x27']
        def client_number_random(self):
                return random.randbytes(32)
        def client_hello(self,server_name="localhost"):
                print('Client hello')
                version=self.version['TLS1.2'] 
                print('支持的版本:',version.hex())

                client_number=self.client_number_random()
                print('随机数1:',client_number.hex())

                print('支持的加密套件:',self.ciphers[0].hex())
                return {'version':version,'cipher':self.ciphers[0],'client_number':client_number}
class server:               
        def __init__(self):
                self.version={'TLS1.2':b'\x03\x03'}
                self.ciphers=[b'\xc0\x27']
        def server_number_random(self):
                return random.randbytes(32)
        def server_hello(self, client_hello):
                print('Serve Hello')
                server_version=client_hello['version']
                if server_version!=b'\x03\x03':
                        print('不支持')
                server_random = self.server_number_random()
                print('随机数2',server_random.hex())
                server_cipher=b'\xc0\x27'
                print('选择的加密:',server_cipher)
                selected_cipher=b'\xc0\x27'
                print(f"使用的加密套件: {selected_cipher}")
                return {'version':server_version,'cipher':server_cipher,'server_number':server_random}
if __name__ == "__main__":
        c=client()
        s=server()
        client_hello=c.client_hello()
        server_hello=s.server_hello(client_hello)
        print("\n握手数据摘要:")
        print(f"客户端随机数: {client_hello['client_number'].hex()}")
        print(f"服务器随机数: {server_hello['server_number'].hex()}")
        print(f"协商的TLS版本: {server_hello['version'].hex()}")
        print(f"选择的加密套件: {server_hello['cipher'].hex()}")
class certificate:
        def __init__(self):
                self.private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
                self.public_key = self.private_key.public_key()
        def send_certificate(self):
                print('发送公钥')
                return self.public_key
crt=certificate()
public_key=crt.send_certificate()
print('公钥:',public_key)
class server_DH:
        def __init__(self):    
            self.P=getPrime(512)
            self.g=getPrime(256)
            self.a=getPrime(256)
            self.a1=pow(self.g,self.a,self.P)
        def exchange(self):
                print('发送P,g,a1')
                return self.P,self.g,self.a1
        def key(self,b1):
                key=pow(b1,self.a,self.P)
                return key
class client_DH:
        def __init__(self):
                self.b=getPrime(256)
        def exchange(self,P,g):
                self.b1=pow(g,self.b,P)
                return self.b1
        def key(self,a1,P):
                key=pow(a1,self.b,P)
                return key
a=server_DH()
b=client_DH()
P,g,a1=a.exchange()
b1=b.exchange(P,g)
server_key=a.key(b1)
client_key=b.key(a1,P)
if server_key==client_key:
        key=server_key
print('协商的密钥为:',key)
class community:
        def __init__(self):
                self.key=hashlib.sha256(str(key).encode()).digest()[:16]
        def encrypte(self,message):
                self.iv=os.urandom(16)
                self.cipher=AES.new(self.key,AES.MODE_CBC,self.iv)
                ciphertext=self.cipher.encrypt(pad(message.encode(), AES.block_size))
                enc=base64.b64encode(self.iv + ciphertext).decode()
                return enc
        def decrypte(self,data):
                data=base64.b64decode(data)
                iv=data[:16]
                print('iv:',iv)
                ciphertext=data[16:]
                cipher=AES.new(self.key,AES.MODE_CBC,iv)
                message=unpad(cipher.decrypt(ciphertext),AES.block_size)
                print('收到消息:',message.decode())
while True:
    x=community()
    message1=input('请输入消息:')
    if message1=='quit':
            break
    enc1=x.encrypte(message1)
    print('客户端:')
    x.decrypte(enc1)

    message2=input('请输入消息:')
    if message2=='quit':
            break
    enc2=x.encrypte(message2)
    print('服务端:')
    x.decrypte(enc2)
