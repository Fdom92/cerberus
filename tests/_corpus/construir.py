#!/usr/bin/env python3
"""Construye el corpus de la validación externa a partir de las listas descargadas.

Semilla fija: la muestra de phishing es siempre la misma, así que dos ejecuciones distintas
dan la misma cifra y se pueden comparar. Uso:  python3 tests/_corpus/construir.py
"""
import json, os, random

AQUI = os.path.dirname(os.path.abspath(__file__))
random.seed(20260924)

legitimos = []
with open("/tmp/tranco/top-1m.csv", encoding="utf-8") as f:
    for linea in f:
        legitimos.append(linea.strip().split(",", 1)[1])
        if len(legitimos) >= 25000:
            break

phishing = set()
for ruta in ("/tmp/openphish.txt", "/tmp/phishdb.txt"):
    if not os.path.exists(ruta):
        continue
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for linea in f:
            linea = linea.strip()
            if linea.startswith("http"):
                phishing.add(linea)

phishing = sorted(phishing)
random.shuffle(phishing)
phishing = phishing[:20000]

# Los 20.000 primeros sirven para medir y para generar las excepciones de typosquat; el
# tramo 20.001-25.000 queda reservado para comprobar la mejora sobre dominios no vistos.
json.dump(legitimos[:20000], open(os.path.join(AQUI, "legitimos.json"), "w"), ensure_ascii=False)
json.dump(legitimos[20000:], open(os.path.join(AQUI, "legitimos_reservados.json"), "w"), ensure_ascii=False)
json.dump(phishing, open(os.path.join(AQUI, "phishing.json"), "w"), ensure_ascii=False)
print(f"legítimos: {len(legitimos[:20000])}   reservados: {len(legitimos[20000:])}   phishing: {len(phishing)}")
