#!/bin/python3
import sys, math
import pandas as pd

# Asumiendo que los simbolos de S2 son solamente los src de los ARP

df = pd.read_csv("paquetes.csv")
df = df.loc[df["type"] == 2054] 
srcs = df["src"].tolist() # lento pero me da paja pandas

simbolos = set(srcs)
simbolos.discard("ff:ff:ff:ff:ff:ff")
simbolos.discard("")

S = { s:srcs.count(s) for s in simbolos }
N = sum(S.values())
I = dict([ (s_i, (-1) * math.log(S[s_i]/N, 2)) for s_i in S ])
H = sum([S[s_i]/N * I[s_i] for s_i in S])

with open("s2.txt", "w") as o:
	o.write("Fuente S2:\n")
	o.write("Cantidad de paquetes: " + str(N) + "\n")
	o.write("\n".join([ " %s : %.5f" % (d,k/N) for d,k in S.items() ]) + "\n")
	o.write("\nInformación de los simbolos de la fuente S2:\n")
	o.write("\n".join([ " %s : %.5f" % (d,k) for d,k in I.items() ]) + "\n")
	o.write("\nEntropía de la fuente S2: %.5f\n" % H)
