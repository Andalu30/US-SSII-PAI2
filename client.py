import socket
import select
import errno #Para codigos de errores
import sys
import hashlib
import hmac
import datetime


def recojeInformacionTransferencia():

    def getAlgo(string):
        if string == "SHA3_512":
            return hashlib.sha3_512
        else:
            pass #TODO


    my_clave = input("Clave para la verificacion de integridad: ").encode()
    my_algoritmo = input("Algoritmo a utilizar para la verificacion: ")
    my_cuentaOrigen = input("Introduzca la cuenta origen: ")
    my_cuentaDestino = input("Introduzca la cuenta destino: ")
    my_cantidad = input("Introduzca la cantidad: ")

    hora = datetime.datetime.now()

    mensaje_api_banco = f"{my_cuentaOrigen},{my_cuentaDestino},{my_cantidad}@{hora}"
    print(mensaje_api_banco)

    mac = hmac.digest(my_clave,mensaje_api_banco.encode(),getAlgo(my_algoritmo)).hex()

    return mensaje_api_banco, mac







HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234

my_username = input("Username: ")





client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((IP, PORT))
    client_socket.setblocking(False)
except Exception as e:
    print("Se ha producido un error al conectarse con el servidor. {}".format(e))
    sys.exit()



username = my_username.encode('utf-8')
username_header = f'{len(username):<{HEADER_LENGTH}}'.encode('utf-8')
client_socket.send(username_header+username)

while True:
    message, message2 = recojeInformacionTransferencia()
    #message = input(f"Introduzca su mensaje >")

    if message and message2:
        message = message.encode("utf-8")
        message2 = message2.encode("utf-8")
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(message_header + message)
        message_header2 = f"{len(message2):<{HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(message_header2 + message2)

    try:
        while True: #recibe cosas
            username_header = client_socket.recv(HEADER_LENGTH)
            if not len(username_header):
                print("Conexion cerrada por el servidor")
                sys.exit()
            username_lenght = int(username_header.decode('utf-8').strip())
            username = client_socket.recv(username_lenght).decode('utf-8')

            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length).decode('utf-8')

            print(f"{username} > {message}")


    except IOError as e: #Excepcion cuando no hay mas mensaje, esperamos que se den
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Error de lectura', str(e))
            sys.exit()

    except Exception as e:
        print('General error', str(e))
        sys.exit()