# Corpus para la validación externa

No se versiona (listas enormes, y una de ellas son URLs maliciosas reales). Para regenerarlo:

```bash
# Legítimos: el millón de dominios más visitados
curl -sL -o /tmp/tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o -q /tmp/tranco.zip -d /tmp/tranco

# Phishing confirmado por terceros
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36'
curl -sL -A "$UA" -o /tmp/openphish.txt  https://openphish.com/feed.txt
curl -sL -A "$UA" -o /tmp/phishdb.txt    https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt
```

Después:

```bash
python3 tests/_corpus/construir.py
```

Ese script sí se versiona, y usa semilla fija (20260924), así que la muestra de phishing es
siempre la misma y dos ejecuciones son comparables.

Abrir `tests/validacion-externa.html` con un servidor estático. Por defecto usa 5.000 de cada
lista; `?n=20000` para el corpus completo.
