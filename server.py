import socket
import select # para varias conexiones
import hmac
import hashlib

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234



my_clave = input("Clave para la conexion: ").encode()




server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1) #reuse puerto

server_socket.bind((IP,PORT))
server_socket.listen()

sockets_list = [server_socket]
clients = {}




def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False

        message_length = int(message_header.decode("utf-8").strip())
        message = client_socket.recv(message_length)

        decrypt = hmac.new(my_clave,message,hashlib.sha3_512)



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
            print(f"Conexion aceptada desde {client_adress[0]}:{client_adress[1]} username:{user['data'].decode('utf-8')}")

        else:
            message = receive_message(notified_socket)
            if message is False:
                print(f"Conexion cerrada desde {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            user = clients[notified_socket]
            print(f"Mensaje recibido desde {user['data'].decode('utf-8')}: {message['data'].decode('utf-8')}")


            #Enviar mensaje a todos pero al que lo ha mandado
            for client_socket in clients:
                if client_socket != notified_socket:
                    client_socket.send(user['header']+user['data']+message['header']+message['data'])


        for notified_socket in exception_sockets:
            sockets_list.remove(notified_socket)
            del clients[notified_socket]