import streamlit as st
import pandas as pd
import asyncio
from bleak import BleakScanner, BleakError
import platform # Um OS-spezifische Hinweise zu geben
from datetime import datetime
import queue # Für spätere Erweiterungen (kontinuierlicher Scan)

# Session State verwenden, um entdeckte Geräte und Scanner-Status zu speichern
if 'discovered_devices' not in st.session_state:
    st.session_state.discovered_devices = {} # Speichert Geräte nach Adresse
if 'scan_log' not in st.session_state:
    st.session_state.scan_log = []
if 'scanner_running' not in st.session_state:
    st.session_state.scanner_running = False
# Die Queue ist hier für einen Button-basierten Scan nicht zwingend,
# aber nützlich für zukünftige Erweiterungen mit einem Hintergrund-Scanner-Thread.
if 'ble_data_queue' not in st.session_state:
    st.session_state.ble_data_queue = queue.Queue()


def log_message(message):
    """Fügt eine Nachricht zum Scan-Log hinzu."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.scan_log.append(f"{timestamp}: {message}")
    # Log-Größe überschaubar halten
    if len(st.session_state.scan_log) > 100:
        st.session_state.scan_log = st.session_state.scan_log[-100:]

async def scan_ble_devices_async(scan_duration=5):
    """Scannt asynchron für BLE-Geräte für eine bestimmte Dauer."""
    log_message(f"Starte BLE Scan für {scan_duration} Sekunden...")
    discovered_devices_temp = {}
    try:
        # BleakScanner.discover ist eine Coroutine
        devices = await BleakScanner.discover(timeout=float(scan_duration))
        for device in devices:
            # Konvertiere Byte-Daten (Herstellerdaten) in Hex-Strings für die Anzeige
            manufacturer_data_hex = {}
            if device.metadata and "manufacturer_data" in device.metadata:
                for key, value in device.metadata["manufacturer_data"].items():
                    manufacturer_data_hex[key] = value.hex()
            
            discovered_devices_temp[device.address] = {
                "name": device.name or "N/A",
                "address": device.address,
                "rssi": device.rssi,
                "manufacturer_data": manufacturer_data_hex,
                "service_uuids": device.metadata.get("uuids", []),
                "platform_specific_details": str(device.details), # Details können je nach OS variieren
                "timestamp": datetime.now().isoformat()
            }
        log_message(f"{len(devices)} Geräte während des Scans gefunden.")
    except BleakError as e:
        log_message(f"BLEAK Fehler: {e}")
        st.error(f"Bluetooth-Fehler: {e}. Stellen Sie sicher, dass Bluetooth aktiviert ist und die App die nötigen Berechtigungen hat.")
        return None # Fehler signalisieren
    except Exception as e:
        log_message(f"Allgemeiner Fehler beim Scannen: {e}")
        st.error(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
        return None # Fehler signalisieren
    return discovered_devices_temp


# --- Streamlit App Aufbau ---
st.set_page_config(page_title="Real Bluetooth Device Scanner", layout="wide")
st.title("📡 Real Bluetooth Device Scanner MVP")
st.caption(f"Dieses MVP scannt nach Bluetooth Low Energy (BLE) Geräten in der Umgebung mit dem Bluetooth-Adapter Ihres Laptops. (System: {platform.system()})")

# --- Seitenleiste für Steuerelemente ---
st.sidebar.header("Steuerung")
scan_duration_seconds = st.sidebar.slider("Scan-Dauer (Sekunden)", 1, 20, 5, key="scan_duration")

if st.sidebar.button("Starte Bluetooth Scan", key="start_scan_button", disabled=st.session_state.scanner_running):
    st.session_state.scanner_running = True
    # Zeige einen Spinner während des Scans
    with st.spinner(f"Suche nach BLE-Geräten für {scan_duration_seconds} Sekunden..."):
        # Führe die asynchrone Scan-Funktion aus.
        # asyncio.run() startet eine neue Event-Loop und führt die Coroutine aus, bis sie abgeschlossen ist.
        # Dies blockiert für die Dauer des Scans, was für einen Button-Klick in Streamlit akzeptabel ist.
        newly_discovered = asyncio.run(scan_ble_devices_async(scan_duration_seconds))

    if newly_discovered is not None: # Überprüfen, ob der Scan erfolgreich war
        # Aktualisiere die Hauptliste der Geräte mit neuen Funden oder füge neue hinzu
        for addr, data in newly_discovered.items():
            st.session_state.discovered_devices[addr] = data # Überschreibt oder fügt hinzu
        log_message(f"Scan beendet. {len(st.session_state.discovered_devices)} eindeutige Geräte insgesamt protokolliert.")
    else:
        log_message("Scan fehlgeschlagen oder es wurden keine Geräte gefunden.")
    
    st.session_state.scanner_running = False
    st.rerun() # Erzwingt ein Neuladen der App, um die neuen Daten anzuzeigen

st.sidebar.markdown("---")
st.sidebar.subheader("Wichtige Hinweise:")
st.sidebar.info(
    """
    - **Bluetooth Aktivierung:** Stellen Sie sicher, dass Bluetooth auf Ihrem Laptop **aktiviert** ist.
    - **Berechtigungen:** Die Anwendung benötigt Zugriff auf Bluetooth. Unter Windows werden Sie normalerweise nicht explizit gefragt, aber das System muss es zulassen.
    - **Remote ID Parsing:** Diese App zeigt allgemeine BLE-Geräte. Die Identifizierung und das Parsen spezifischer **Remote ID Daten** (z.B. gemäß ASTM F3411-22a) erfordert zusätzliche, komplexe Logik zur Interpretation der `Herstellerdaten` oder `Servicedaten`. **Dies ist nicht Teil dieses MVPs.**
    - **`bleak` Bibliothek:** Verwendet die `bleak` Bibliothek für die BLE-Kommunikation.
    """
)
if platform.system() == "Windows":
    st.sidebar.markdown(
        "**Windows-spezifisch:** `bleak` verwendet die Windows Runtime (WinRT) APIs. "
        "Es sind normalerweise keine speziellen Treiber erforderlich, solange Ihr Bluetooth-Adapter von Windows korrekt erkannt wird und funktioniert."
    )

# --- Hauptanzeigebereich ---
st.subheader("🔍 Entdeckte BLE Geräte")

if not st.session_state.discovered_devices:
    st.info("Noch keine Geräte entdeckt. Starten Sie einen Scan über die Seitenleiste.")
else:
    devices_df_list = []
    for address, data in st.session_state.discovered_devices.items():
        # Bereite Daten für die tabellarische Anzeige vor
        devices_df_list.append({
            "Adresse": address,
            "Name": data.get("name", "N/A"),
            "RSSI (dBm)": data.get("rssi", "N/A"),
            # Zeige nur die Schlüssel (IDs) der Herstellerdaten für die Übersichtstabelle
            "Herstellerdaten (IDs)": ", ".join(map(str, data.get("manufacturer_data", {}).keys())) or "Keine",
            # Zeige nur einen Auszug der Service UUIDs
            "Service UUIDs (Auszug)": ", ".join(data.get("service_uuids", [])[:3]) + ("..." if len(data.get("service_uuids", [])) > 3 else "") or "Keine",
            "Zuletzt gesehen": datetime.fromisoformat(data.get("timestamp", "")).strftime("%H:%M:%S") if data.get("timestamp") else "N/A"
        })
    
    if devices_df_list:
        devices_df = pd.DataFrame(devices_df_list)
        st.dataframe(devices_df, use_container_width=True, key="devices_table")

        st.subheader("Rohdaten Details (ausgewähltes Gerät)")
        # Auswahlbox, um Details für ein bestimmtes Gerät anzuzeigen
        if devices_df_list: # Sicherstellen, dass die Liste nicht leer ist
            # Erstelle eine Liste von Adressen für die Selectbox
            device_addresses = [d["Adresse"] for d in devices_df_list]
            selected_address = st.selectbox(
                "Wähle ein Gerät für mehr Details:",
                options=device_addresses,
                # Formatierungsfunktion, um Name und Adresse in der Selectbox anzuzeigen
                format_func=lambda x: f"{st.session_state.discovered_devices.get(x, {}).get('name', 'N/A')} ({x})",
                key="device_selector"
            )
            if selected_address and selected_address in st.session_state.discovered_devices:
                # Zeige die vollständigen JSON-Daten des ausgewählten Geräts an
                st.json(st.session_state.discovered_devices[selected_address])
    else:
        st.info("Keine darstellbaren Gerätedaten vorhanden. (Möglicherweise war der Scan nicht erfolgreich)")

st.subheader("📜 Scan Log")
if st.session_state.scan_log:
    st.text_area("Log:", value="\n".join(reversed(st.session_state.scan_log)), height=200, disabled=True, key="scan_log_area")
else:
    st.text("Noch keine Log-Einträge.")

st.markdown("---")