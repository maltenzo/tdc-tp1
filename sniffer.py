import pandas as pd
from scapy.all import *
from math import log
from time import time

CSV_PATH = "./paquetes.csv"
DF = pd.DataFrame(columns=["src", "kind", "dst", "type","timeStamp","timeAfterBegginSniffing","entropia"])

S1 = {}
def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("\n".join([ " %s : %.5f" % (d,k/N) for d,k in simbolos ]))
    print()

def add_pkt_to_csv(pkt):
    N = sum(S1.values())
    I = dict([ (s_i, (-1) * log(S1[s_i]/N, 2)) for s_i in S1 ])
    H = sum([S1[s_i]/N * I[s_i] for s_i in S1])

    if pkt.haslayer(Ether):
        sniffingTime = time()
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        DF.loc[len(DF)] = [pkt[Ether].src, dire, pkt[Ether].dst, proto, sniffingTime, sniffingTime-StartTime , H]
        

def callback(pkt):
    add_pkt_to_csv(pkt)
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0

def main():
    global StartTime
    StartTime = time()
    sniff(count=10000, prn=callback)

    N = sum(S1.values())
    I = dict([ (s_i, (-1) * log(S1[s_i]/N, 2)) for s_i in S1 ])
    H_S1 = sum([S1[s_i]/N * I[s_i] for s_i in S1])
    DF.to_csv(CSV_PATH, index=False)

    with open("salida.txt", "w") as f:
        f.write("Fuente S1:\n")
        f.write("Cantidad de paquetes: " + str(N) + "\n")
        f.write("\n".join([ " %s : %.5f" % (d,k/N) for d,k in S1.items() ]) + "\n")
        f.write("\nInformación de los simbolos de la fuente S1:\n")
        f.write("\n".join([ " %s : %.5f" % (d,k) for d,k in I.items() ]) + "\n")
        f.write("\nEntropía de la fuente S1: %.5f\n" % H_S1)
    

if __name__ == "__main__":
    main()