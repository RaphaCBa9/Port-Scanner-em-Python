#!/usr/bin/python3

import sys
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from tcpKnownPorts import tcp_wkp as WELL_KNOWN_PORTS_TCP
from udpKnownPorts import udp_wkp as WELL_KNOWN_PORTS_UDP



def port_scan_tcp(host, porta, nome, openOnly=True):
    """Realiza o scan de uma única porta TCP"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        if s.connect_ex((host, int(porta))) == 0:
            print(f"Porta {porta} ({nome}) [TCP] aberta")
        elif(not (openOnly)):
            print(f"Porta {porta} ({nome}) [TCP] fechada")

def port_scan_udp(host, porta, nome, openOnly=True):
    """Realiza o scan de uma única porta UDP"""

    if socket.getservbyport(porta, "udp"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            if s.connect_ex((host, int(porta))) == 0:
                print(f"Porta {porta} ({nome}) [UDP] aberta")
            elif(not (openOnly)):
                print(f"Porta {porta} ({nome}) [TCP] fechada")




def listar_hosts():
    """Lista os hosts conectados na rede usando o comando ARP"""
    print("\nHosts conectados na rede:\n")
    try:
        sistema = sys.platform
        if sistema.startswith("win"):
            comando = ["arp", "-a"]
        else:
            comando = ["arp", "-n"]
        
        resultado = subprocess.run(comando, capture_output=True, text=True)
        print(resultado.stdout)
    except Exception as e:
        print(f"Erro ao listar hosts: {e}")



def main():
    
    print("\n\nRoteiro 01: Port Scanner\n\n")

    while True:
        print("\n*************************************\n")
        print("Selecione uma opção:")
        print('0 - Verificar hosts conectados na rede')
        print("1 - Escanear portas principais TCP (well-known ports)")
        print("2 - Escanear portas principais UDP (well-known ports)")
        print("3 - Intervalo de portas ou portas específicas")
        print("4 - Sair")

        opcao = input("\nSelecione: ")

        if opcao == "0":
            listar_hosts()

        elif opcao == "1":
            host = input("\nDigite o host ou aperte 'Enter' para voltar: ")
            if not host:
                continue
            openOnly = input("\nGostaria de mostrar apenas as portas abertas? (s/n):").lower()
            if openOnly == 's':
                print("Mostrando apenas as portas abertas")
                openOnly = True
            if openOnly == 'n':
                print("Mostrando o estado de todas as portas (pode demorar um pouco mais)")
                openOnly = True
            with ThreadPoolExecutor(max_workers=10) as executor:
                for port, service in WELL_KNOWN_PORTS_TCP.items():
                    executor.submit(port_scan_tcp, host, port, service, openOnly)
        
        elif opcao == "2":
            host = input("\nDigite o host ou aperte 'Enter' para voltar: ")
            if not host:
                continue
            with ThreadPoolExecutor(max_workers=10) as executor:
                for port, service in WELL_KNOWN_PORTS_UDP.items():
                    executor.submit(port_scan_udp, host, port, service)

        elif opcao == "3":
            host = input("\nDigite o host ou aperte 'Enter' para voltar: ")
            if not host:
                continue
            portas = input("\nDigite o intervalo deportas (formato: <porta1:portaN>), porta única ou aperte 'Enter' para voltar: ")
            if not portas:
                continue
            protocolo = input("\nDigite o protocolo (TCP/UDP): ").upper()
            if not protocolo:
                continue
            if protocolo not in ("TCP", "UDP"):
                print("\nErro: Protocolo inválido. Use TCP ou UDP.")
                continue
            
            try:
                inicio, fim = map(int, portas.split(":"))
                if protocolo == "UDP":
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        for porta in range(inicio, fim + 1):
                            executor.submit(port_scan_udp, host, porta, f"Porta {porta}", False)
                else:
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        for porta in range(inicio, fim + 1):
                            executor.submit(port_scan_tcp, host, porta, f"Porta {porta}", False)
            except ValueError:
                print("\nErro: Formato inválido. Use o formato <porta_1:porta_N>.")

        elif opcao == "4":
            print("\nSaindo...")
            break

        else:
            print("\nOpção inválida!")
    print("\nFim do programa.")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan cancelado pelo usuário.")
        sys.exit(1)


