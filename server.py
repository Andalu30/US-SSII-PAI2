import socket
import select # para varias conexiones
import hmac
import hashlib
import logging
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import matplotlib
import datetime


outputfilename = "outputKPI.pdf"

mensajes_recibidos = 0
mensajes_recibidosOK = 0

HORASDELOSMENSAJES = []
HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234

logFilename = "LogsPAI2.log"
logging.basicConfig(filename=logFilename,level=logging.DEBUG,format='%(asctime)s:%(levelname)s:%(message)s')

MY_CLAVE = input("Clave para la conexion: ").encode()
my_algoritmo = input("Algoritmo a utilizar para la verificacion: ")




def generaKPIs(ratio):

    w, h = A4
    c = canvas.Canvas(outputfilename, pagesize=A4)
    c.drawString(50, h - 50, "Fichero de indicadores KPI")
    c.drawString(250, h - 50, f"{datetime.datetime.now()}")

    c.drawString(50, h - 75,f"Ratio de mensajes recibidos correctamente: {ratio}%")

    c.showPage()
    c.save()








def getAlgo(string):
    if string == "SHA3_512":
        return hashlib.sha3_512
    elif string == "SHA1":
        return hashlib.sha1
    elif string == "SHA_256":
        return hashlib.sha256
    else:
        print("Se ha producido un error al seleccionar el algoritmo")
        sys.exit()



server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1) #reuse puerto

server_socket.bind((IP,PORT))
server_socket.listen()

sockets_list = [server_socket]
clients = {}


def checkReplayAttack(message):
    horallegada = message.decode('utf-8').split('@')[1]
    if horallegada in HORASDELOSMENSAJES:
        return False
    else:
        HORASDELOSMENSAJES.append(horallegada)
        return True

def checkIntegridadMensaje(message,mac):
    calculada = hmac.digest(MY_CLAVE,message,getAlgo(my_algoritmo)).hex()
    logging.debug(calculada)
    logging.debug(mac)
    if calculada == mac.decode('utf-8'):
        return True
    else:
        return False

def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False

        message_length = int(message_header.decode("utf-8").strip())
        message = client_socket.recv(message_length)

        return {"header":message_header, "data":message}
    except:
        return False






# Servidor overkill basado en el tutorial de sockets de Harrison Kinsley
while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [],sockets_list)
    # readlist , writelist, error list

    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            #Se ha conectado al servidor
            client_socket, client_adress = server_socket.accept()
            user = receive_message(client_socket)

            if user is False:
                continue

            sockets_list.append(client_socket)
            clients[client_socket] = user
            logging.info(f"Conexion aceptada desde {client_adress[0]}:{client_adress[1]} username:{user['data'].decode('utf-8')}")

        else:
            message = receive_message(notified_socket)
            if message is False:
                logging.info(f"Conexion cerrada desde {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            user = clients[notified_socket]
            logging.info(f"Mensaje API recibido desde {user['data'].decode('utf-8')}: {message['data'].decode('utf-8')}")
            print(f"Mensaje API recibido desde {user['data'].decode('utf-8')}: {message['data'].decode('utf-8')}")
            

            message2 = receive_message(notified_socket)
            if message2 is False:
                logging.info(f"Conexion cerrada desde {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            user = clients[notified_socket]
            logging.info(f"Mensaje MAC recibido desde {user['data'].decode('utf-8')}: {message2['data'].decode('utf-8')}")
            print(f"Mensaje MAC recibido desde {user['data'].decode('utf-8')}: {message2['data'].decode('utf-8')}")

            mensajes_recibidos = mensajes_recibidos + 1


            if checkIntegridadMensaje(message['data'],message2['data']):
                if checkReplayAttack(message['data']):
                    logging.info("OK, integridad confirmada")
                    print("OK, integridad confirmada")
                    mensajes_recibidosOK = mensajes_recibidosOK + 1
                    

                else:
                    logging.warning("Ataque de Replay detectado")
                    print("ERROR: Ataque de Replay detectado")

            else:
                logging.warning("NOPE, integridad comprometida")
                print("ERROR: integridad comprometida del mensaje")


            ratioKPI = (mensajes_recibidosOK/mensajes_recibidos)*100
            generaKPIs(ratioKPI)




            ##Enviar mensaje a todos menos al que lo ha mandado
            #for client_socket in clients:
            #    if client_socket != notified_socket:
            #        client_socket.send(user['header']+user['data']+message['header']+message['data'])


        for notified_socket in exception_sockets:
            sockets_list.remove(notified_socket)
            del clients[notified_socket]
