import requests
import socket
import time

# Dateiname der Textdatei mit den URLs und Keywords
url_file = "urls.txt"
results_file = "results.txt"

# Timeout und Liste der URLs
timeout = 10
url_list = []

# URLs und zugehörige Keywords aus der Textdatei lesen
with open(url_file, "r") as file:
    for line in file:
        line = line.strip()
        if line == "":
            continue
        url, keyword = line.split(" ", 1) # die erste Leerzeichen-getrennte Zeichenkette als URL, den Rest als Keyword nehmen
        url_list.append((url, keyword))

# Ergebnisse in eine Textdatei schreiben
with open(results_file, "w") as file:
    # URLs testen
    for url, keyword in url_list:
        file.write("Teste URL: " + url + "\n")

        # DNS-Lookup testen
        try:
            ip_address = socket.gethostbyname(url)
            file.write("DNS-Lookup erfolgreich!\n")
        except socket.gaierror:
            file.write("DNS-Lookup fehlgeschlagen!\n")
            continue

        # Verbindungszeit testen
        start_time = time.time()
        response = requests.get("http://" + ip_address, timeout=timeout)
        end_time = time.time()
        time_taken = end_time - start_time

        if response.status_code == 200:
            file.write("Website ist erreichbar!\n")
            file.write("Verbindungszeit: " + str(time_taken) + " Sekunden\n")
        else:
            file.write("Website ist nicht erreichbar. Status code: " + str(response.status_code) + "\n")
            continue

        # Ladegeschwindigkeit testen
        if time_taken > timeout:
            file.write("Website-Ladegeschwindigkeit zu langsam!\n")
        else:
            file.write("Website-Ladegeschwindigkeit in Ordnung.\n")

        # Textinhalt testen
        response_text = response.text.lower()
        if keyword.lower() in response_text:
            file.write("Keyword \"" + keyword + "\" gefunden!\n")
        else:
            file.write("Keyword nicht gefunden!\n")

        file.write("\n")  # eine leere Zeile zwischen den Ergebnissen einfügen

print("Testergebnisse wurden in der Datei " + results_file + " gespeichert.")
