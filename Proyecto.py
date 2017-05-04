import nmap
import socket
import os
import sys
import subprocess
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import http.server
import getpass
import telnetlib


def servidorHTTP(port, bind, cgi):
    try:
        if cgi == True:
            http.server.test(HandlerClass=http.server.CGIHTTPRequestHandler, port=port, bind=bind)
        else:
            http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler, port=port, bind=bind)

    except KeyboardInterrupt:
            print("Saliendo...")
            
    except OSError:
            print("Error al host no valido para crear el servicio!")



def servidorFTP(ip):
    try:
        # Se inicializa la automatizacion para el manejo de usuarios virtuales
        authorizer = DummyAuthorizer()

        # Se define un usuario (master) con privilegios de lectura y escritura
        # Se define un usuario anonimo con privilegios de solo lectura

        # unicode(aythorizer.add_user(utf-8,errors))

        authorizer.add_user('master', 'password', os.getcwd(), perm='elradfmM')
        authorizer.add_anonymous(os.getcwd())

        # manejador de instacias FTP
        handler = FTPHandler
        handler.authorizer = authorizer
        # Establece la direccion y puerto del servidor FTP
        direccion = (ip, 21)
        servidor = FTPServer(direccion, handler)
        # Establece un limite de conexiones
        servidor.max_cons = 256
        servidor.max_cons_per_ip = 5
        # Inicia el servidor FTP
        servidor.serve_forever()

    except KeyboardInterrupt:
        print("Saliendo...")
    except OSError:
        print("Error host no valido para crear el servicio!")

def escanearRed():
    nm=nmap.PortScanner()
    ip=[ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if #Obtenemos la ip
            not ip.startswith("127.")][0]



    nm.scan(hosts=ip+'/24', arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        if ip==host:
            datos = socket.gethostname()
            print("Ip: "+host," \t ","MAC: "+obtenerMacAddress()+": "+limpiar(datos))
            ips.append(host)

        else:
            try:
                nm.scan(host, arguments='-O')
                datos = nm[host]['vendor']
                print("Ip: " + host , "\t " , "MAC: " + limpiar(datos))
                ips.append(host)
            except KeyError:
                a=""


def obtenerMacAddress():
    if sys.platform == 'win32':  # Para Windows
        for lineadecomando in os.popen("ipconfig/all"):
            if lineadecomando.lstrip().startswith('Direcci'):
                direccion_MAC = lineadecomando.split(':')[1].strip().replace('-', ':')
                #print(direccion_MAC)
                break
    else:  # Para Linux
        for lineadecomando in os.popen("/sbin/ifconfig"):
            if lineadecomando.find('Ether') > -1:
                direccion_MAC = lineadecomando.split()[4]
                #print(direccion_MAC)
                break

    return direccion_MAC

def validarNumero(n):
    try:
        val = int(n)
        return True
    except ValueError:
        print("Error no es un número entero!")
        return False



def puertosAbiertos(remoteIP):


    primero=input("Puerto de inicio: ")

    while validarNumero(primero)==False:
        primero=input("Puerto de inicio: ")


    segundo= input("Puerto de fin: ")

    while validarNumero(segundo)==False:
        segundo=input("Puerto de fin: ")

    #subprocess.call('clear', shell=True)
    print('-' * 60)
    print('Por favor espera, escaneando puertos', remoteIP)
    print('-' * 60)

    try:
        for port in range(int(primero), int(segundo)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteIP, port))
            if result == 0:
                print('Puerto {}: \t Abierto'.format(port))


            sock.close
    except KeyboardInterrupt:
        print('Se interrumpio ')
        #sys.exit()
    except socket.gaierror:
        print('IP no puede ser resuelta. Saliendo')
        #sys.exit()
    except socket.erro:
        print('No se pudo conectar al server')
        #sys.exit()

    print('Escaneo completo')


def limpiar (datos):
    b="{}'"
    string=str(datos)

    for char in b:
        string= string.replace(char,"")


    return string

def comprobarIp(ip):
    for i in ips:
        if str(i)==str(ip):
            return True

    return False

def validarSiesIp(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


def servidorTelnet(ip):
    HOST = ip
    user = input("Meter cuenta : ")
    password = getpass.getpass()

    tn = telnetlib.Telnet(HOST, "23")

    tn.read_until("Usuario: ")
    tn.write(user + "\n")
    if password:
        tn.read_until("Contraseña: ")
        tn.write(password + "\n")

    tn.write("ls\n")
    tn.write("salir\n")

    print(tn.read_all())



#-------------------------------------

ips=[]



while True:

    print("*"*60)
    print("1.- Escanear red")
    print("2.- Escanear puertos de la red")
    print("3.- Montar servidor FTP")
    print("4.- Montar servidor HTTP")
    print("5.- Montar servidor Telnet")
    print("6.- Salir")
    print("*"*60)
    op=input("Opcion: ")

    if op=='1':
        print("-* Escaneando Red *-")
        escanearRed()

    elif op=='2':
        ip=str(input("Dame host: "))

        if validarSiesIp(ip) or ip=="localhost" :
            puertosAbiertos(ip)
        else:
            print("Error host no valido!")

    elif op=='3':

        ip=str(input("Dame host: "))

        if validarSiesIp(ip) or ip=="localhost":
            servidorFTP(ip)
        else:
            print("Error host no valido!")

    elif op=='4':
        ip=str(input("Dame host: "))

        if validarSiesIp(ip)or ip=="localhost":
            servidorHTTP(80,ip,False)
        else:
            print("Error host no valido!")

    elif op=='5':

        ip = str(input("Dame host: "))

        if validarSiesIp(ip)or ip=="localhost":
            servidorTelnet(ip)
        else:
            print("Error host no valido!")


    elif op=='6':
        print("Saliendo...")
        break

    else:
        print("Error opción no valida!")


















