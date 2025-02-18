import time
import os
from scapy.all import sniff, Ether, IP, TCP, UDP

def limpartela():
    os.system('cls' if os.name == 'nt' else 'clear')

def exibir_ascii_art():
    ascii_art = r"""
.------------.  /\_/\ 
| SnifferPy  | ( o.o )
'------------'  > - <
"""
    print(ascii_art)

def exibir_menu():
    print("\nMenu:")
    print("[1] Iniciar Sniffer")
    print("[2] Como usar")
    print("[3] Sair")

def sobre():
    limpartela()
    exibir_ascii_art()
    print("\Como usar o SnifferPy:")
    print("Defina a porta de rede e a quantidade de pacotes a serem capturados. Use netsh para identificar o nome de suas interfaces.")
    print("Use com responsabilidade.")
    input("\nAperte qualquer tecla para voltar ao Menu...")

def packet_callback(packet):
    if Ether in packet:
        print(f"Ethernet Frame: {packet[Ether].src} -> {packet[Ether].dst}")

    if IP in packet:
        print(f"IP Packet: {packet[IP].src} -> {packet[IP].dst}")

        if TCP in packet:
            print(f"TCP Segment: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Datagram: {packet[UDP].sport} -> {packet[UDP].dport}")

    print("-" * 40)

def start_sniffer(interface=None, count=0):
    print(f"Iniciando Sniffer na Interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=count)

def main():
    while True:
        limpartela()
        exibir_ascii_art()
        exibir_menu()

        escolha = input("\nEscolha uma opção: ")

        if escolha == "1":
            limpartela()
            exibir_ascii_art()
            interface = input("Digite a interface de rede (ex: ethernet, Wi-Fi): ")
            count = int(input("Digite o número de pacotes: "))
            start_sniffer(interface=interface, count=count)
            input("\nAperte qualquer tecla para voltar ao Menu")

        elif escolha == "2":
            sobre()

        elif escolha == "3":
            print("Fechando..")
            break

        else:
            print("Opção inválida!")
            time.sleep(1)

if __name__ == "__main__":
    main()