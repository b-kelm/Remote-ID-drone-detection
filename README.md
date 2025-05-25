# Bluetooth LE & Remote ID Scanner MVP

## Beschreibung

Diese Anwendung ist ein Minimum Viable Product (MVP), das mit Streamlit und der `bleak`-Bibliothek entwickelt wurde, um nach Bluetooth Low Energy (BLE) Geräten in der Umgebung zu suchen. Ein besonderer Fokus liegt auf dem **experimentellen Versuch**, Remote ID Daten von Drohnen zu parsen, basierend auf öffentlich zugänglichen Interpretationen des OpenDroneID-Standards (welcher sich an ASTM F3411-22a anlehnt).

**WICHTIG:** Der Remote-ID-Parser in dieser Anwendung ist **hochgradig experimentell, vereinfacht** und stellt **keine validierte oder vollständige Implementierung** eines offiziellen Standards dar. Er dient als Ausgangspunkt für Entwickler und erfordert umfangreiche Tests und Verfeinerungen.

## Features

* Scannt nach Bluetooth Low Energy (BLE) Geräten in der Umgebung.
* Zeigt grundlegende Informationen der entdeckten Geräte an (Name, MAC-Adresse, RSSI-Signalstärke).
* Enthält einen **experimentellen Parser** für Broadcast Remote ID Daten:
    * Versucht, Nachrichten gemäß OpenDroneID / ASTM F3411-22a zu interpretieren.
    * Fokussiert sich auf Basic ID, Location/Vector und Message Pack Nachrichten.
* Stellt geparste Remote ID Informationen tabellarisch dar.
* Zeigt Standorte von Drohnen mit erfolgreich geparsten Standortdaten auf einer Karte an.
* Bietet eine JSON-Ansicht der Rohdaten und der geparsten Daten für ausgewählte Geräte zur detaillierten Analyse.
* Benutzeroberfläche erstellt mit Streamlit.
* Bluetooth-Kommunikation über die `bleak`-Bibliothek.

## Voraussetzungen

* Python 3.8 oder neuer.
* Ein Computer mit einem funktionierenden Bluetooth-Adapter (die primäre Anleitung wurde für Windows erstellt).
* Administratorrechte könnten unter Windows anfänglich erforderlich sein, um die PowerShell Execution Policy anzupassen (siehe Setup).

## Setup-Anleitung (Fokus auf Windows)

1.  **Repository klonen oder Dateien herunterladen:**
    Laden Sie die Projektdateien (`remote_id_scanner_app.py`, `requirements.txt`, `README.md`) in einen lokalen Ordner herunter.

2.  **Python installieren:**
    * Laden Sie Python von [python.org](https://www.python.org/downloads/windows/) herunter und installieren Sie es.
    * **Wichtig:** Stellen Sie sicher, dass Sie während der Installation die Option "Add Python to PATH" auswählen.

3.  **Virtuelle Umgebung erstellen und aktivieren:**
    Es wird dringend empfohlen, eine virtuelle Umgebung zu verwenden. Öffnen Sie eine Eingabeaufforderung oder PowerShell im Projektverzeichnis:
    ```bash
    # Virtuelle Umgebung erstellen
    python -m venv venv
    ```
    Aktivieren der virtuellen Umgebung:
    * In der **Eingabeaufforderung (cmd.exe)**:
        ```bash
        venv\Scripts\activate.bat
        ```
    * In **PowerShell**:
        ```powershell
        # Möglicherweise müssen Sie zuerst die Ausführungsrichtlinie für die aktuelle Sitzung anpassen:
        # Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
        venv\Scripts\Activate.ps1
        ```
    Nach der Aktivierung sollte `(venv)` am Anfang Ihrer Kommandozeile erscheinen.

4.  **Abhängigkeiten installieren:**
    Installieren Sie die benötigten Python-Pakete mit pip:
    ```bash
    pip install -r requirements.txt
    ```

5.  **Bluetooth aktivieren:**
    Stellen Sie sicher, dass Bluetooth auf Ihrem Laptop/PC aktiviert ist (Systemeinstellungen -> Bluetooth und Geräte).

## Anwendung starten

Stellen Sie sicher, dass Ihre virtuelle Umgebung aktiviert ist und Sie sich im Hauptverzeichnis des Projekts befinden. Führen Sie dann folgenden Befehl aus:

```bash
streamlit run remote_id_scanner_app.py