import streamlit as st
import pandas as pd
import asyncio
from bleak import BleakScanner, BleakError, AdvertisementData, BLEDevice
import platform
from datetime import datetime
import queue
import struct
import json # Für JSON Lines Export
import os # Für Pfadoperationen

# --- Globale Konstanten und Hilfsfunktionen (wie zuvor) ---
# ODID_MESSAGE_TYPE_BASIC_ID, etc. und ACCURACY_MAP, ODID_HEIGHT_TYPE_AGL/MSL bleiben gleich.
# Die Parsing-Funktionen (parse_basic_id_message, parse_location_vector_message, etc.) bleiben ebenfalls gleich.
# Sie werden weiterhin für die Live-Anzeige in der UI verwendet.

# --- (Fügen Sie hier Ihre unveränderten globalen Konstanten und Parsing-Funktionen ein) ---
# ODID_MESSAGE_TYPE_BASIC_ID = 0x0
# ... (alle Parsing-Funktionen bis try_parse_remote_id_from_manufacturer_data) ...
# --- Ende der unveränderten globalen Konstanten und Parsing-Funktionen ---

# Konstanten für OpenDroneID Nachrichtentypen (entsprechen ASTM)
ODID_MESSAGE_TYPE_BASIC_ID = 0x0
ODID_MESSAGE_TYPE_LOCATION = 0x1
ODID_MESSAGE_TYPE_SELF_ID = 0x2 # Nicht implementiert in diesem Beispiel
ODID_MESSAGE_TYPE_SYSTEM = 0x3  # Nicht implementiert in diesem Beispiel
ODID_MESSAGE_TYPE_OPERATOR_ID = 0x4 # Nicht implementiert in diesem Beispiel
ODID_MESSAGE_TYPE_MESSAGE_PACK = 0x5

# ID-Typen für Basic ID Nachricht (Auszug)
UAS_ID_TYPE_SERIAL_NUMBER = 1

# Genauigkeits-Enums (Beispiele, Werte und Bedeutungen aus Standard entnehmen)
ACCURACY_MAP = {
    0: "Unbekannt", 1: "< 10m", 2: "< 3m", 3: "< 1m",
    4: "< 0.3m", 5: "< 0.1m",
}
ODID_HEIGHT_TYPE_AGL = 0 # Höhe über Grund
ODID_HEIGHT_TYPE_MSL = 1 # Höhe über Meeresspiegel (Mean Sea Level)

def log_message_ui(message): # Umbenannt, um Konflikte mit Dateilogging zu vermeiden
    """Fügt eine Nachricht zum UI-Scan-Log hinzu."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.scan_log_ui.append(f"{timestamp}: {message}")
    if len(st.session_state.scan_log_ui) > 200:
        st.session_state.scan_log_ui = st.session_state.scan_log_ui[-200:]

# --- Parsing-Funktionen (Experimentell - wie zuvor) ---
def parse_basic_id_message(payload_bytes):
    parsed_data = {"message_type_desc": "Basic ID"}
    if len(payload_bytes) < 22:
        parsed_data["error"] = f"Payload zu kurz für Basic ID ({len(payload_bytes)} statt 22 Bytes)"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
        return parsed_data
    try:
        parsed_data['id_type_enum'] = int(payload_bytes[0])
        id_type_map = {
            0: "Keine", 1: "Seriennummer (CTA-2063-A)", 2: "CAA Registrierungs-ID",
            3: "UTM Assigned ID", 4: "Spezifische Session ID"
        }
        parsed_data['id_type_desc'] = id_type_map.get(parsed_data['id_type_enum'], "Unbekannter ID-Typ")
        uas_id_raw = payload_bytes[1:21]
        try:
            parsed_data['uas_id'] = uas_id_raw.split(b'\0', 1)[0].decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            parsed_data['uas_id'] = uas_id_raw.hex() + " (UTF-8 Dekodierfehler)"
    except Exception as e:
        parsed_data["error"] = f"Fehler beim Parsen von Basic ID: {str(e)}"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    return parsed_data

def parse_location_vector_message(payload_bytes):
    parsed_data = {"message_type_desc": "Location/Vector"}
    if len(payload_bytes) < 27: # ODID Bluetooth Spec erwartet oft 27 Bytes für die Kern-Location-Nachricht
        parsed_data["error"] = f"Payload zu kurz für Location/Vector ({len(payload_bytes)} statt mind. 27 Bytes für vollst. Info)"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
        # Versuch, trotzdem Minimaldaten zu parsen, falls möglich (z.B. nur Lat/Lon wenn kürzer)
        if len(payload_bytes) >= 9: # Flags (1) + Lat (4) + Lon (4)
            try:
                flags = payload_bytes[0]
                parsed_data['status_enum'] = flags & 0b00000111
                parsed_data['height_type_enum'] = (flags >> 3) & 0x01
                parsed_data['height_type_desc'] = "AGL" if parsed_data['height_type_enum'] == ODID_HEIGHT_TYPE_AGL else "MSL"
                parsed_data['horizontal_accuracy_enum'] = (flags >> 5) & 0b00000111
                parsed_data['horizontal_accuracy_desc'] = ACCURACY_MAP.get(parsed_data['horizontal_accuracy_enum'], "N/A")
                parsed_data['latitude'] = struct.unpack_from('<i', payload_bytes, 1)[0] / 1e7
                parsed_data['longitude'] = struct.unpack_from('<i', payload_bytes, 5)[0] / 1e7
            except Exception as e_short:
                 parsed_data["error_short_parse"] = f"Fehler bei Kurz-Parse: {str(e_short)}"
        return parsed_data

    try:
        flags = payload_bytes[0]
        parsed_data['status_enum'] = flags & 0b00000111
        parsed_data['height_type_enum'] = (flags >> 3) & 0x01
        parsed_data['height_type_desc'] = "AGL" if parsed_data['height_type_enum'] == ODID_HEIGHT_TYPE_AGL else "MSL"
        parsed_data['horizontal_accuracy_enum'] = (flags >> 5) & 0b00000111
        parsed_data['horizontal_accuracy_desc'] = ACCURACY_MAP.get(parsed_data['horizontal_accuracy_enum'], "N/A")

        parsed_data['latitude'] = struct.unpack_from('<i', payload_bytes, 1)[0] / 1e7
        parsed_data['longitude'] = struct.unpack_from('<i', payload_bytes, 5)[0] / 1e7
        parsed_data['altitude_baro_m'] = (struct.unpack_from('<h', payload_bytes, 9)[0] / 2.0) - 1000.0
        parsed_data['altitude_geo_m'] = (struct.unpack_from('<h', payload_bytes, 11)[0] / 2.0) - 1000.0
        parsed_data['height_agl_m'] = (struct.unpack_from('<h', payload_bytes, 13)[0] / 2.0) - 1000.0
        parsed_data['vertical_accuracy_enum'] = int(payload_bytes[15])
        parsed_data['vertical_accuracy_desc'] = ACCURACY_MAP.get(parsed_data['vertical_accuracy_enum'], "N/A")
        parsed_data['speed_vertical_cm_s'] = struct.unpack_from('<h', payload_bytes, 16)[0]
        parsed_data['speed_horizontal_cm_s'] = struct.unpack_from('<H', payload_bytes, 18)[0]
        direction_raw = struct.unpack_from('<H', payload_bytes, 20)[0]
        parsed_data['direction_heading_deg'] = direction_raw / 100.0 if direction_raw <= 36000 else "Ungültig"
        parsed_data['timestamp_accuracy_enum'] = int(payload_bytes[22])
        timestamp_raw = struct.unpack_from('<H', payload_bytes, 23)[0]
        parsed_data['timestamp_seconds_of_hour'] = timestamp_raw / 10.0
        if len(payload_bytes) >= 26:
             parsed_data['speed_accuracy_enum'] = int(payload_bytes[25])
    except struct.error as e:
        parsed_data["error"] = f"Struct Unpacking Fehler: {str(e)}"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    except IndexError:
        parsed_data["error"] = "IndexError: Payload kürzer als erwartet für volle Location-Daten (27 Bytes)."
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    except Exception as e:
        parsed_data["error"] = f"Fehler beim Parsen von Location/Vector: {str(e)}"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    return parsed_data

def parse_message_pack(payload_bytes_after_pack_header):
    parsed_pack = {"message_type_desc": "Message Pack", "messages": []}
    if not payload_bytes_after_pack_header or len(payload_bytes_after_pack_header) < 1:
        parsed_pack["error"] = "Leeres Payload für Message Pack (nach Header)"
        return parsed_pack

    message_count_in_pack = int(payload_bytes_after_pack_header[0])
    parsed_pack["actual_message_count"] = message_count_in_pack
    offset = 1 

    for i in range(message_count_in_pack):
        if offset + 23 > len(payload_bytes_after_pack_header):
            parsed_pack["messages"].append({"error": f"Nicht genügend Daten für Nachricht {i+1} im Pack."})
            break
        
        packed_message_header = payload_bytes_after_pack_header[offset]
        packed_message_type = (packed_message_header >> 4) & 0x0F
        packed_message_payload = payload_bytes_after_pack_header[offset+1 : offset+23]

        parsed_message = {"packed_message_type_enum": packed_message_type}
        if packed_message_type == ODID_MESSAGE_TYPE_BASIC_ID:
            parsed_message.update(parse_basic_id_message(packed_message_payload))
        elif packed_message_type == ODID_MESSAGE_TYPE_LOCATION:
            parsed_message.update(parse_location_vector_message(packed_message_payload))
            if "error" not in parsed_message and len(packed_message_payload) < 27 :
                 parsed_message["info_packed_location"] = "Location (22B Payload) aus Pack, möglicherweise unvollständig."
        else:
            parsed_message["error"] = f"Nicht unterstützter gepackter Nachrichtentyp: {packed_message_type}"
            parsed_message["raw_packed_payload_hex"] = packed_message_payload.hex()
        
        parsed_pack["messages"].append(parsed_message)
        offset += 23
    return parsed_pack

def try_parse_remote_id_from_manufacturer_data(manufacturer_data_dict):
    all_parsed_rid_messages = []
    for company_id, data_bytes in manufacturer_data_dict.items():
        if not data_bytes or len(data_bytes) < 1:
            continue

        first_message_header = data_bytes[0]
        message_type = (first_message_header >> 4) & 0x0F
        first_message_payload = data_bytes[1:]

        parsed_data_for_company_id = {"source_company_id_hex": f"0x{company_id:04X}"}

        if message_type == ODID_MESSAGE_TYPE_BASIC_ID:
            parsed_data_for_company_id.update(parse_basic_id_message(first_message_payload))
            all_parsed_rid_messages.append(parsed_data_for_company_id)
        elif message_type == ODID_MESSAGE_TYPE_LOCATION:
            parsed_data_for_company_id.update(parse_location_vector_message(first_message_payload))
            all_parsed_rid_messages.append(parsed_data_for_company_id)
        elif message_type == ODID_MESSAGE_TYPE_MESSAGE_PACK:
            parsed_data_for_company_id.update(parse_message_pack(first_message_payload))
            all_parsed_rid_messages.append(parsed_data_for_company_id)
    return all_parsed_rid_messages


# --- Haupt-Scan-Funktion mit Rohdaten-Logging ---

# Globale Liste für im aktuellen Scan gesammelte Roh-Advertisements
# Wird vor jedem Scan geleert.
collected_raw_advertisements = []
# Dictionary für UI-Anzeige und Live-Parsing (einzigartige Geräte)
# Wird vor jedem Scan geleert.
ui_device_display_data = {}


def detection_callback_for_raw_logging(device: BLEDevice, advertisement_data: AdvertisementData):
    """Callback für jedes empfangene Advertisement-Paket."""
    timestamp_event = datetime.now().isoformat()
    
    # Konvertiere device.details sicher, da es unterschiedliche Typen haben kann
    device_details_repr = "N/A"
    if hasattr(device, 'details'):
        try:
            # Versuche, es in einen String umzuwandeln. Wenn es ein komplexes Objekt ist,
            # könnte man es auch anders serialisieren, aber str() ist ein Anfang.
            # Für WinRT sind das oft komplexe WinRT-Objekte.
            device_details_repr = str(device.details)
        except Exception:
            device_details_repr = "Konnte device.details nicht in String umwandeln"

    raw_ad_packet_info = {
        "timestamp_event": timestamp_event,
        "device_address": device.address,
        "device_name_bledevice": device.name, # Name aus BLEDevice (oft OS gecached)
        "advertisement_local_name": advertisement_data.local_name, # Name aus diesem spezifischen Advertisement
        "rssi": advertisement_data.rssi,
        # "tx_power": ..., # Bereits entfernt
        "manufacturer_data": {str(comp_id): data.hex() for comp_id, data in advertisement_data.manufacturer_data.items()},
        "service_data": {str(uuid): data.hex() for uuid, data in advertisement_data.service_data.items()},
        "service_uuids": [str(uuid) for uuid in advertisement_data.service_uuids],
        "device_details_platform": device_details_repr # ERSETZT advertisement_data.platform_specific
    }
    collected_raw_advertisements.append(raw_ad_packet_info)

    # Aktualisiere auch die Daten für die UI-Anzeige (einzigartige Geräte)
    # Hier nehmen wir die neuesten Infos aus dem Advertisement für ein bekanntes Gerät
    ui_device_display_data[device.address] = {
        "name": advertisement_data.local_name or device.name or "N/A", # Bevorzuge Namen aus Ad
        "address": device.address,
        "rssi": advertisement_data.rssi,
        "manufacturer_data_hex_display": {f"0x{k:04X}": v.hex() for k,v in advertisement_data.manufacturer_data.items()},
        "service_uuids": [str(uuid) for uuid in advertisement_data.service_uuids],
        "timestamp": timestamp_event, # Zeit des letzten Updates
         # Versuche auch hier Live-Parsing für die UI
        "parsed_remote_id": try_parse_remote_id_from_manufacturer_data(advertisement_data.manufacturer_data)
        # device_details_platform könnte hier auch für die UI-Detailansicht hinzugefügt werden, falls gewünscht
    }


async def scan_and_log_raw_ble_data_async(scan_duration=10):
    """Scannt nach BLE-Geräten, loggt alle Advertisements roh und aktualisiert UI-Daten."""
    log_message_ui(f"Starte Rohdaten-Scan für {scan_duration} Sekunden...")
    
    # Globale Listen für diesen Scan leeren
    global collected_raw_advertisements, ui_device_display_data
    collected_raw_advertisements = []
    ui_device_display_data = {} # Wichtig für UI-Konsistenz

    log_filename = f"ble_raw_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    log_filepath = os.path.join(os.getcwd(), log_filename) # Speichert im aktuellen Arbeitsverzeichnis

    scanner = BleakScanner(detection_callback=detection_callback_for_raw_logging)
    
    try:
        await scanner.start()
        log_message_ui(f"Scanner gestartet. Sammle Daten... Logdatei wird: {log_filename}")
        await asyncio.sleep(scan_duration)
        await scanner.stop()
        log_message_ui(f"Scanner gestoppt. {len(collected_raw_advertisements)} Roh-Advertisements erfasst.")

        # Schreibe gesammelte Rohdaten in die .jsonl Datei
        if collected_raw_advertisements:
            with open(log_filepath, 'w', encoding='utf-8') as f:
                for entry in collected_raw_advertisements:
                    json.dump(entry, f)
                    f.write('\n')
            log_message_ui(f"Rohdaten erfolgreich in '{log_filepath}' geschrieben.")
            st.session_state.last_log_file = log_filepath
        else:
            log_message_ui("Keine Roh-Advertisements zum Loggen erfasst.")
            st.session_state.last_log_file = None

    except BleakError as e:
        log_message_ui(f"BLEAK Fehler: {e}")
        st.error(f"Bluetooth-Fehler: {e}. Stellen Sie sicher, dass Bluetooth aktiviert ist.")
        st.session_state.last_log_file = None
        return None # Signalisiert Fehler
    except Exception as e:
        log_message_ui(f"Allgemeiner Fehler beim Scannen: {e}")
        st.error(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
        st.session_state.last_log_file = None
        return None # Signalisiert Fehler
    
    # Gebe die UI-Daten zurück (einzigartige Geräte mit ihren letzten Infos)
    return ui_device_display_data


# --- Streamlit App Initialisierung und UI ---

def initialize_session_state():
    """Initialisiert den Streamlit Session State."""
    if 'processed_ble_devices_ui' not in st.session_state: # Für die UI-Anzeige der geparsten Daten
        st.session_state.processed_ble_devices_ui = {}
    if 'scan_log_ui' not in st.session_state:
        st.session_state.scan_log_ui = []
    if 'scanner_running' not in st.session_state:
        st.session_state.scanner_running = False
    if 'last_log_file' not in st.session_state:
        st.session_state.last_log_file = None
    if 'recent_raw_ads_preview' not in st.session_state:
        st.session_state.recent_raw_ads_preview = []


def run_app():
    """Hauptfunktion zum Erstellen der Streamlit UI."""
    st.set_page_config(page_title="BLE Rohdaten Logger & RID Scanner", layout="wide")
    st.title("📡 Bluetooth LE Rohdaten Logger & Remote ID Scanner (Experimentell)")
    st.caption(f"Loggt alle BLE Advertisements roh und versucht Remote ID zu parsen. System: {platform.system()}")

    initialize_session_state()

    # --- Seitenleiste ---
    st.sidebar.header("Scan-Steuerung")
    scan_duration_seconds = st.sidebar.slider(
        "Scan-Dauer (Sekunden)", 5, 60, 10, key="scan_duration_slider_raw"
    )

    if st.sidebar.button(
        "Starte Rohdaten-Logging & RID Scan", 
        key="start_raw_scan_button", 
        disabled=st.session_state.scanner_running
    ):
        st.session_state.scanner_running = True
        st.session_state.recent_raw_ads_preview = [] # Preview für diese Session leeren
        
        with st.spinner(f"Logge Rohdaten & parse Remote ID für {scan_duration_seconds} Sek..."):
            # scan_and_log_raw_ble_data_async gibt jetzt die UI-Daten zurück
            ui_data_from_scan = asyncio.run(scan_and_log_raw_ble_data_async(scan_duration_seconds))
        
        if ui_data_from_scan is not None:
            st.session_state.processed_ble_devices_ui = ui_data_from_scan
            # Aktualisiere die Preview der Rohdaten für die UI
            st.session_state.recent_raw_ads_preview = collected_raw_advertisements[-5:] # Zeige die letzten 5
            log_message_ui(f"UI aktualisiert mit {len(ui_data_from_scan)} einzigartigen Geräten.")
        else:
            log_message_ui("Scan fehlgeschlagen oder keine interpretierbaren UI-Daten erhalten.")
            st.session_state.processed_ble_devices_ui = {} # Leeren im Fehlerfall
        
        st.session_state.scanner_running = False
        st.rerun()

    if st.session_state.last_log_file:
        st.sidebar.success(f"Letzte Log-Datei: {st.session_state.last_log_file}")
        # Biete Download an (Streamlit's native Download-Button ist gut für Textdateien)
        try:
            with open(st.session_state.last_log_file, "r", encoding='utf-8') as fp:
                st.sidebar.download_button(
                    label="Download Log-Datei (.jsonl)",
                    data=fp, # Streamlit kann Datei-Objekte direkt verarbeiten
                    file_name=os.path.basename(st.session_state.last_log_file),
                    mime="application/jsonl" # Oder text/plain
                )
        except Exception as e:
            st.sidebar.error(f"Fehler beim Vorbereiten des Downloads: {e}")


    st.sidebar.markdown("---")
    st.sidebar.subheader("Wichtige Hinweise:")
    st.sidebar.warning( # Wichtiger Hinweis zum Parser
        """
        **Parser ist HOCHEXPERIMENTELL:**
        - Der Remote ID Parser basiert auf vereinfachten Annahmen und ist **keine vollständige oder validierte Implementierung** des ASTM F3411-22a Standards.
        - Er dient als **Ausgangspunkt** und funktioniert möglicherweise **nicht** für alle Drohnen oder alle Nachrichtentypen korrekt.
        - **Echte Tests** mit diversen Drohnen sind zwingend notwendig.
        - Für eine robuste Lösung ist der **Zugriff auf die offiziellen Standards** unerlässlich.
        """
    )
    st.sidebar.info( # Allgemeine Hinweise
        """
        - **Rohdaten-Logging:** Diese Version loggt alle empfangenen BLE Advertisement Pakete in eine `.jsonl` Datei im Programmverzeichnis. Diese Datei ist für Ihre Offline-Analyse gedacht.
        - **Bluetooth:** Muss auf Ihrem Laptop aktiviert sein.
        """
    )

    # --- Hauptanzeige ---
    st.subheader("📜 UI Scan Log & Status")
    if st.session_state.scan_log_ui:
        st.text_area("UI Log:", value="\n".join(reversed(st.session_state.scan_log_ui)), height=150, disabled=True, key="ui_scan_log_area")
    else:
        st.text("Noch keine UI Log-Einträge.")

    st.subheader("📊 Live-Analyse & Potentielle Remote ID (basierend auf einzigartigen Geräten)")
    if not st.session_state.processed_ble_devices_ui:
        st.info("Noch keine Gerätedaten für die UI-Analyse verarbeitet. Bitte starten Sie einen Scan.")
    else:
        display_list_ui = []
        rid_map_data_ui = []

        for address, data_ui in st.session_state.processed_ble_devices_ui.items():
            rid_summary_ui = "Nein"
            basic_id_info_ui = "N/A"
            location_info_ui = "N/A"
            
            if data_ui.get("parsed_remote_id"):
                rid_messages_ui = data_ui["parsed_remote_id"]
                rid_summary_ui = f"Ja ({len(rid_messages_ui)} Parsing-Versuche)"
                for rid_msg_container in rid_messages_ui:
                    msg_desc_ui = rid_msg_container.get("message_type_desc", "Unbekannt")
                    source_cid_ui = rid_msg_container.get("source_company_id_hex", "")

                    if rid_msg_container.get("error"):
                        error_info_ui = f"Parse-Fehler ({msg_desc_ui} von {source_cid_ui}): {rid_msg_container['error']}"
                        if "Basic ID" in msg_desc_ui: basic_id_info_ui = error_info_ui
                        elif "Location" in msg_desc_ui: location_info_ui = error_info_ui
                        elif "Message Pack" in msg_desc_ui: location_info_ui += f" | {error_info_ui}"
                        continue

                    if msg_desc_ui == "Basic ID":
                        basic_id_info_ui = f"{rid_msg_container.get('uas_id', 'N/A')} ({rid_msg_container.get('id_type_desc', 'N/A')}) von {source_cid_ui}"
                    elif msg_desc_ui == "Location/Vector":
                        lat, lon, alt_geo = rid_msg_container.get('latitude'), rid_msg_container.get('longitude'), rid_msg_container.get('altitude_geo_m')
                        if lat is not None and lon is not None:
                            location_info_ui = f"Lat: {lat:.5f}, Lon: {lon:.5f} (von {source_cid_ui})"
                            if alt_geo is not None: location_info_ui += f", AltGeo: {alt_geo:.1f}m"
                            if -90 <= lat <= 90 and -180 <= lon <= 180:
                                 rid_map_data_ui.append({"lat": lat, "lon": lon, "name": data_ui.get("name", address)})
                        else: location_info_ui = f"Standortdaten unvollständig ({source_cid_ui})."
                    elif msg_desc_ui == "Message Pack":
                        pack_summary_ui = f" [Pack ({rid_msg_container.get('actual_message_count',0)} Msgs) von {source_cid_ui}]"
                        for packed_msg in rid_msg_container.get("messages", []):
                            if packed_msg.get("error"): pack_summary_ui += f" | Pack-Fehler: {packed_msg.get('packed_message_type_enum','?')}: {packed_msg['error']}"
                            elif packed_msg.get("packed_message_type_enum") == ODID_MESSAGE_TYPE_BASIC_ID: basic_id_info_ui = f"{packed_msg.get('uas_id', 'N/A')} (Pack: {packed_msg.get('id_type_desc', 'N/A')})"
                            elif packed_msg.get("packed_message_type_enum") == ODID_MESSAGE_TYPE_LOCATION:
                                lat_p, lon_p = packed_msg.get('latitude'), packed_msg.get('longitude')
                                if lat_p is not None and lon_p is not None:
                                    pack_summary_ui += f" | Pack-Loc: {lat_p:.4f}, {lon_p:.4f}"
                                    if -90 <= lat_p <= 90 and -180 <= lon_p <= 180: rid_map_data_ui.append({"lat": lat_p, "lon": lon_p, "name": f"{data_ui.get('name', address)} (Pack)"})
                                elif packed_msg.get("info_packed_location"): pack_summary_ui += f" | {packed_msg['info_packed_location']}"
                        location_info_ui += pack_summary_ui
            
            display_list_ui.append({
                "Name": data_ui.get("name", "N/A"), "Adresse": address, "RSSI (dBm)": data_ui.get("rssi", "N/A"),
                "Remote ID Parse?": rid_summary_ui, "RID Basic ID (UI)": basic_id_info_ui, "RID Standort (UI)": location_info_ui,
                "Letztes Update": datetime.fromisoformat(data_ui.get("timestamp", "")).strftime("%H:%M:%S") if data_ui.get("timestamp") else "N/A"
            })

        if display_list_ui:
            devices_df_ui = pd.DataFrame(display_list_ui)
            cols_to_show_ui = ["Name", "Adresse", "RSSI (dBm)", "Remote ID Parse?", "RID Basic ID (UI)", "RID Standort (UI)", "Letztes Update"]
            valid_cols_ui = [col for col in cols_to_show_ui if col in devices_df_ui.columns]
            st.dataframe(devices_df_ui[valid_cols_ui], use_container_width=True, key="ui_devices_table_final")

            if rid_map_data_ui:
                st.subheader("📍 Standorte (aus UI Live-Analyse)")
                map_df_ui = pd.DataFrame(rid_map_data_ui).dropna(subset=['lat', 'lon'])
                if not map_df_ui.empty: st.map(map_df_ui, zoom=10)
                else: st.info("Keine gültigen Standortdaten für Karte aus UI-Analyse.")

            st.subheader("🔍 Detailansicht UI-Daten (ausgewähltes Gerät)")
            device_addresses_ui = [d["Adresse"] for d in display_list_ui]
            if device_addresses_ui:
                selected_address_ui = st.selectbox(
                    "Wähle Gerät für UI-Daten Details:", options=device_addresses_ui,
                    format_func=lambda x: f"{st.session_state.processed_ble_devices_ui.get(x, {}).get('name', 'N/A')} ({x})",
                    key="ui_device_selector_final"
                )
                if selected_address_ui and selected_address_ui in st.session_state.processed_ble_devices_ui:
                    st.json(st.session_state.processed_ble_devices_ui[selected_address_ui])
        else: st.info("Keine Gerätedaten für die UI-Tabelle vorhanden.")

    # --- Rohdaten-Vorschau ---
    st.subheader("🔬 Vorschau der letzten Roh-Advertisement-Pakete (aus Log-Puffer)")
    if st.session_state.recent_raw_ads_preview:
        for i, raw_ad in enumerate(reversed(st.session_state.recent_raw_ads_preview)): # Neueste zuerst
            with st.expander(f"Raw Ad #{len(st.session_state.recent_raw_ads_preview)-i}: {raw_ad['device_address']} ({raw_ad.get('advertisement_local_name', 'N/A')}) @ {raw_ad['timestamp_event']}"):
                st.json(raw_ad)
    else:
        st.info("Keine Roh-Advertisements in der aktuellen Vorschau. Starten Sie einen Scan.")
    
    st.markdown("---")
    st.caption("Denken Sie daran, die Installationsanweisungen für Python, Streamlit und Bleak zu befolgen, falls noch nicht geschehen.")

if __name__ == "__main__":
    run_app()