import pandas as pd
from scapy.all import *
from math import log
from time import time

CSV_PATH = "./paquetes.csv"
DF = pd.DataFrame(columns=["src", "dst","ip_src","ip_dst","informacion","entropia","kind","type","timeStamp",])

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
    ip_src = "unknown"
    ip_dst = "unknown"
    sniffingTime = time()
    kind = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
    proto = pkt[Ether].type # El campo type del frame tiene el protocolo
    s = (kind, proto) # Aca se define el simbolo de la fuente
    if ( pkt.haslayer(IP) ):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    DF.loc[len(DF)] = [pkt[Ether].src, pkt[Ether].dst, ip_src, ip_dst, I[s], H, kind, proto, sniffingTime-StartTime]
        

def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0
        add_pkt_to_csv(pkt)

def main():
    global StartTime
    StartTime = time()
    sniff(count=100, prn=callback)

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



### Explico que hace el codigo de este archivo como si estuviera escribiendo un informe

### Para la experimentacion se utilizo la libreria scapy, la cual permite capturar paquetes de red
### y analizarlos. Para la captura de paquetes se utilizo la funcion sniff de la libreria, a la cual
### le indicamos que capture 10000 paquetes y que para cada uno de ellos
### ejecute la funcion callback. Esta funcion se encarga de agregar el paquete a un dataframe
### y de actualizar la fuente S1. Para esto, se utiliza el campo type del frame, el cual indica
### el protocolo utilizado en el paquete. Si el paquete es unicast, se agrega a la fuente S1
### el simbolo (UNICAST, protocolo), y si es broadcast, se agrega el simbolo (BROADCAST, protocolo).
### Luego de capturar los 10000 paquetes, se calcula la entropia de la fuente S1 y se guarda
### el dataframe en un archivo csv.