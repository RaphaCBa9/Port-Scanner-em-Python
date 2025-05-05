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

def PortScanning():
    while True:
        print("\n*************************************\n")
        print("Selecione uma opção:")
        print('0 - Verificar hosts conectados na rede')
        print("1 - Escanear portas principais TCP (well-known ports)")
        print("2 - Escanear portas principais UDP (well-known ports)")
        print("3 - Intervalo de portas ou portas específicas")
        print("4 - Voltar ao menu principal")

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
    
    return

def whois_lookup():

    alvo = input("\nDigite o domínio ou IP para consulta WHOIS (ou pressione Enter para voltar): ")
    if not alvo:
        return

    print(f"\nConsultando WHOIS para: {alvo}\n")
    try:
        resultado = subprocess.run(["whois", alvo], capture_output=True, text=True, timeout=10)
        print(resultado.stdout)
    except FileNotFoundError:
        print("\nErro: O utilitário 'whois' não está instalado no sistema.")
    except subprocess.TimeoutExpired:
        print("\nErro: A consulta WHOIS excedeu o tempo limite.")
    except Exception as e:
        print(f"\nErro ao executar WHOIS: {e}")

def wafw00f_scan():

    alvo = input("\nDigite a URL ou IP para análise com wafw00f (ou pressione Enter para voltar): ")
    if not alvo:
        return

    print(f"\nAnalisando proteção WAF em: {alvo}\n")
    try:
        resultado = subprocess.run(["wafw00f", alvo], capture_output=True, text=True, timeout=15)
        print(resultado.stdout)
    except FileNotFoundError:
        print("\nErro: O utilitário 'wafw00f' não está instalado. Use 'pip install wafw00f' para instalar.")
    except subprocess.TimeoutExpired:
        print("\nErro: A execução do wafw00f excedeu o tempo limite.")
    except Exception as e:
        print(f"\nErro ao executar wafw00f: {e}")

def dirb_scan():
    alvo = input("\nDigite a URL ou IP para varredura de diretórios (ou pressione Enter para voltar): ")
    if not alvo:
        return

    print(f"\nIniciando varredura de diretórios em: {alvo}\n")
    try:
        resultado = subprocess.run(["dirb", alvo, "/usr/share/dirb/wordlists/small.txt"], capture_output=True, text=True, timeout=90)
        print(resultado.stdout)
    except FileNotFoundError:
        print("\nErro: O utilitário 'dirb' não está instalado. Use 'apt install dirb' para instalar.")
    except subprocess.TimeoutExpired:
        print("\nErro: A execução do dirb excedeu o tempo limite.")
    except Exception as e:
        print(f"\nErro ao executar dirb: {e}")

def nikto_scan():
    """Executa o nikto para varredura de vulnerabilidades web"""
    alvo = input("\nDigite a URL ou IP do alvo para escanear com nikto (ou pressione Enter para voltar): ")
    if not alvo:
        return

    print(f"\nIniciando varredura com nikto em: {alvo}\n")
    try:
        resultado = subprocess.run(
            ["nikto", "-h", alvo],
            capture_output=True,
            text=True,
            timeout=120
        )
        print(resultado.stdout)
    except FileNotFoundError:
        print("\nErro: O utilitário 'nikto' não está instalado. Use 'sudo apt install nikto'.")
    except subprocess.TimeoutExpired:
        print("\nErro: A execução do nikto excedeu o tempo limite.")
    except Exception as e:
        print(f"\nErro ao executar nikto: {e}")


def main():
    
    print("\n\n Este é TargetRecon, seu aplicativo de reconhecimento de alvos \n\n")
    print("Criado por: @RaphaCBa9")

    while True:
        print("\n*************************************\n")
        print("Selecione uma opção:")
        print('0 - Port Scanning')
        print("1 - Consulta WHOIS")
        print("2 - Detecção de WAF (wafw00f)")
        print("3 - Varredura de diretórios (DIRB)")
        print("4 - Varredura de Vulnerabilidades (nikto)")
        print("5 - Finalizar")

        opcao = input("\nSelecione: ")

        if opcao == "0":
            PortScanning()

        elif opcao == "1":
            whois_lookup()

        elif opcao == "2":
            wafw00f_scan()

        elif opcao == "3":
            dirb_scan()
        
        elif opcao == "4":
            nikto_scan()

        elif opcao == "5":
            print("\nSaindo...")
            break
    
    print("\nObrigado por usar TargetRecon!")




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n Programa cancelado pelo usuário.")
        sys.exit(1)


