import streamlit as st
import pandas as pd
import asyncio
from bleak import BleakScanner, BleakError, AdvertisementData, BLEDevice
import platform
from datetime import datetime
import struct
import json
import os
import threading # Für Scapy Sniffing in eigenem Thread
import time # Für Wartezeiten

# --- Scapy Import (optional, da es nicht überall installiert ist) ---
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11EltVendorSpecific
    SCAPY_AVAILABLE = True
except ImportError:
    st.warning("Scapy ist nicht installiert. WiFi Remote ID Scanning wird nicht verfügbar sein. Installieren mit: pip install scapy")
except OSError as e: # Kann auf einigen Systemen beim Import von Scapy auftreten, wenn z.B. npcap/libpcap fehlt
    st.warning(f"Scapy konnte aufgrund eines Systemfehlers nicht geladen werden: {e}. WiFi Remote ID Scanning ist möglicherweise nicht verfügbar.")


# --- Globale Konstanten und Hilfsfunktionen ---

# Konstanten für OpenDroneID Nachrichtentypen (entsprechen ASTM F3411-22a)
ODID_MESSAGE_TYPE_BASIC_ID = 0x0
ODID_MESSAGE_TYPE_LOCATION = 0x1
ODID_MESSAGE_TYPE_SELF_ID = 0x2
ODID_MESSAGE_TYPE_SYSTEM = 0x3
ODID_MESSAGE_TYPE_OPERATOR_ID = 0x4
ODID_MESSAGE_TYPE_MESSAGE_PACK = 0xF

# ID-Typen für Basic ID Nachricht (Auszug)
UAS_ID_TYPE_SERIAL_NUMBER = 1

ACCURACY_MAP = {
    0: "Unknown", 1: "< 10m", 2: "< 3m", 3: "< 1m",
    4: "< 0.3m", 5: "< 0.1m",
    6: "< 150m", 7: "< 45m", 8: "< 25m", 9: "< 10m",
    10: "< 3m", 11: "< 1m"
}

ODID_HEIGHT_TYPE_AGL = 0
ODID_HEIGHT_TYPE_MSL = 1

ODID_SERVICE_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"
ODID_SERVICE_UUID_SHORT = "fffa"
APPLE_COMPANY_ID = 0x004C

# OpenDroneID over WiFi Beacon (ASTM F3411-22a, Section 8.3.2)
ODID_WIFI_ASTM_OUI = b'\x00\x1A\x70' # ASTM International OUI (00-1A-70)
# Der Vendor Specific OUI Type kann variieren, oft 0xDD oder 0x10.
# In opendroneid-core-c wird für den Empfang oft nicht explizit auf diesen Type geprüft,
# sondern direkt nach der OUI der Payload geparsed.
# Wir nehmen hier an, dass nach der OUI direkt die ODID Daten beginnen oder ein spezifischer Typ-Byte folgt.
# Für den Empfang ist es oft robuster, nach der OUI zu suchen und dann zu versuchen, die Daten zu parsen.
# Die C-Lib Beispiele (z.B. wifi_spec_oui_tx.c) verwenden ODID_WIFI_OUI_TYPE_MESSAGE_PACK = 0x0F
# oder ODID_WIFI_OUI_TYPE_MESSAGE = 0x0D. Wir gehen davon aus, dass die Daten direkt nach dem OUI kommen
# oder der erste Byte der Daten der ODID Header ist.
# Der Standard ASTM F3411-22a (8.3.2) sagt: OUI (3 bytes), gefolgt von "Vendor Specific OUI Type" (1 byte).
# Dieser "Vendor Specific OUI Type" ist oft 0xDD für "Open Drone ID".
ODID_WIFI_VENDOR_OUI_TYPE_OPENDROENID = 0xDD # Gemäß Standardtext


def log_message_ui(message, log_area_key="ble_scan_log_ui"):
    """Fügt eine Nachricht zum UI-Scan-Log hinzu."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if log_area_key not in st.session_state:
        st.session_state[log_area_key] = []
    st.session_state[log_area_key].append(f"{timestamp}: {message}")
    if len(st.session_state[log_area_key]) > 200:
        st.session_state[log_area_key] = st.session_state[log_area_key][-200:]

# --- Parsing-Funktionen (angepasst für korrekte Längen und Fehlerbehandlung) ---
# (Die Parsing-Funktionen parse_basic_id_message, parse_location_vector_message, 
#  parse_message_pack, parse_odid_data_stream bleiben im Wesentlichen gleich wie im Original-Skript)

def parse_basic_id_message(payload_bytes):
    """
    Parses an OpenDroneID Basic ID message payload.
    ASTM F3411-22a: Basic ID message payload is 22 bytes.
    """
    parsed_data = {"message_type_desc": "Basic ID"}
    if len(payload_bytes) < 22: 
        parsed_data["error"] = f"Payload zu kurz für Basic ID ({len(payload_bytes)} statt 22 Bytes)"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
        return parsed_data
    try:
        parsed_data['id_type_enum'] = int(payload_bytes[0])
        id_type_map = {
            0: "None", 1: "Serial Number (CTA-2063-A)", 2: "CAA Registration ID",
            3: "UTM Assigned ID (UUID)", 4: "Specific Session ID (UTM)",
        }
        parsed_data['id_type_desc'] = id_type_map.get(parsed_data['id_type_enum'], f"Unbekannter ID-Typ ({parsed_data['id_type_enum']})")
        uas_id_raw = payload_bytes[1:21]
        try:
            parsed_data['uas_id'] = uas_id_raw.split(b'\0', 1)[0].decode('utf-8', errors='replace').strip()
        except UnicodeDecodeError:
            parsed_data['uas_id'] = uas_id_raw.hex() + " (UTF-8 Dekodierfehler)"
        parsed_data['rfu_basic_id'] = payload_bytes[21]
    except Exception as e:
        parsed_data["error"] = f"Fehler beim Parsen von Basic ID: {str(e)}"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    return parsed_data

def parse_location_vector_message(payload_bytes):
    """
    Parses an OpenDroneID Location/Vector message payload.
    ASTM F3411-22a: Location message payload is 22 bytes for legacy BT.
    """
    parsed_data = {"message_type_desc": "Location/Vector"}
    if len(payload_bytes) < 22:
        parsed_data["error"] = f"Payload zu kurz für Location/Vector ({len(payload_bytes)} statt 22 Bytes)"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
        return parsed_data

    try:
        status_byte = payload_bytes[0]
        parsed_data['status_enum'] = status_byte & 0b00001111
        status_map = {0: "Undeclared", 1: "Ground", 2: "Airborne", 3: "Emergency", 4: "Remote ID System Failure"}
        parsed_data['status_desc'] = status_map.get(parsed_data['status_enum'], f"Unknown Status ({parsed_data['status_enum']})")
        parsed_data['height_type_enum'] = (status_byte >> 4) & 0x01
        parsed_data['height_type_desc'] = "AGL" if parsed_data['height_type_enum'] == ODID_HEIGHT_TYPE_AGL else "MSL"
        
        direction_raw = struct.unpack_from('<H', payload_bytes, 1)[0]
        parsed_data['direction_heading_deg'] = direction_raw / 100.0 if direction_raw <= 35999 else "Invalid"
        
        speed_horizontal_raw = payload_bytes[3]
        parsed_data['speed_horizontal_m_s'] = speed_horizontal_raw * 0.25 if speed_horizontal_raw < 255 else "Invalid"
        
        speed_vertical_raw = struct.unpack_from('<b', payload_bytes, 4)[0]
        parsed_data['speed_vertical_m_s'] = speed_vertical_raw * 0.5 if speed_vertical_raw != -128 else "Invalid"
        
        parsed_data['latitude'] = struct.unpack_from('<i', payload_bytes, 5)[0] / 1e7
        parsed_data['longitude'] = struct.unpack_from('<i', payload_bytes, 9)[0] / 1e7
        
        parsed_data['altitude_baro_m'] = (struct.unpack_from('<h', payload_bytes, 13)[0] * 0.5) - 1000.0
        parsed_data['altitude_geo_m'] = (struct.unpack_from('<h', payload_bytes, 15)[0] * 0.5) - 1000.0
        parsed_data['height_agl_m'] = (struct.unpack_from('<h', payload_bytes, 17)[0] * 0.5) - 1000.0
        
        accuracies_byte = payload_bytes[19]
        parsed_data['horizontal_accuracy_enum'] = accuracies_byte & 0x0F
        parsed_data['horizontal_accuracy_desc'] = ACCURACY_MAP.get(parsed_data['horizontal_accuracy_enum'], "N/A")
        parsed_data['vertical_accuracy_enum'] = (accuracies_byte >> 4) & 0x0F
        parsed_data['vertical_accuracy_desc'] = ACCURACY_MAP.get(parsed_data['vertical_accuracy_enum'], "N/A")
        
        parsed_data['speed_accuracy_enum'] = payload_bytes[20] & 0x0F
        speed_accuracy_map = {0: "Unknown", 1: "< 10 m/s", 2: "< 3 m/s", 3: "< 1 m/s", 4: "< 0.3 m/s"}
        parsed_data['speed_accuracy_desc'] = speed_accuracy_map.get(parsed_data['speed_accuracy_enum'], "N/A")

        parsed_data['timestamp_accuracy_enum'] = (payload_bytes[20] >> 4) & 0x0F
        ts_accuracy_map = {0: "Unknown", 1: "< 0.1s", 2: "< 0.2s", 3: "< 0.3s"}
        parsed_data['timestamp_accuracy_desc'] = ts_accuracy_map.get(parsed_data['timestamp_accuracy_enum'], "N/A")

        timestamp_raw_byte = payload_bytes[21]
        parsed_data['timestamp_seconds_of_minute'] = timestamp_raw_byte / 10.0 if timestamp_raw_byte < 600 else "Invalid"

    except struct.error as e:
        parsed_data["error"] = f"Struct Unpacking Fehler: {str(e)}"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    except IndexError:
        parsed_data["error"] = "IndexError: Payload kürzer als erwartet für Location-Daten."
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    except Exception as e:
        parsed_data["error"] = f"Fehler beim Parsen von Location/Vector: {str(e)}"
        parsed_data["raw_payload_hex"] = payload_bytes.hex()
    return parsed_data

def parse_message_pack(payload_bytes_after_pack_header, source_description=""):
    parsed_pack = {"message_type_desc": f"Message Pack from {source_description}", "messages": []}
    if not payload_bytes_after_pack_header or len(payload_bytes_after_pack_header) < 1:
        parsed_pack["error"] = "Leeres Payload für Message Pack (nach Pack-Header)"
        return parsed_pack

    message_count_in_pack = int(payload_bytes_after_pack_header[0])
    parsed_pack["declared_message_count"] = message_count_in_pack
    
    if message_count_in_pack > 10: # Max 10 messages for BT Legacy
        parsed_pack["warning"] = f"Zu viele Nachrichten im Pack deklariert ({message_count_in_pack} > 10 max für BT Legacy). Parse bis zu 10."
        message_count_in_pack = 10 

    offset = 1 
    for i in range(message_count_in_pack):
        if offset + 23 > len(payload_bytes_after_pack_header):
            parsed_pack["messages"].append({"error": f"Nicht genügend Daten für Nachricht {i+1} im Pack."})
            break
        
        packed_message_full = payload_bytes_after_pack_header[offset : offset+23]
        packed_message_header = packed_message_full[0]
        packed_message_payload = packed_message_full[1:]

        packed_message_type = (packed_message_header >> 4) & 0x0F
        parsed_message = {"packed_message_type_enum": packed_message_type}

        if packed_message_type == ODID_MESSAGE_TYPE_BASIC_ID:
            parsed_message.update(parse_basic_id_message(packed_message_payload))
        elif packed_message_type == ODID_MESSAGE_TYPE_LOCATION:
            parsed_message.update(parse_location_vector_message(packed_message_payload))
        # Add parsers for other types (Self ID, System, Operator ID) if needed
        else:
            parsed_message["error"] = f"Nicht unterstützter gepackter Nachrichtentyp: {packed_message_type}"
            parsed_message["raw_packed_payload_hex"] = packed_message_payload.hex()
        
        parsed_pack["messages"].append(parsed_message)
        offset += 23
    return parsed_pack

def parse_odid_data_stream(data_bytes, source_description="Unknown Source"):
    all_parsed_messages = []
    offset = 0

    while offset < len(data_bytes):
        if len(data_bytes) - offset < 1: break # Not enough for a header

        current_header = data_bytes[offset]
        message_type = (current_header >> 4) & 0x0F
        parsed_entry = {"source_description": source_description, "raw_header_hex": f"{current_header:02X}"}

        if message_type == ODID_MESSAGE_TYPE_MESSAGE_PACK:
            pack_payload_start_offset = offset + 1
            if len(data_bytes) - pack_payload_start_offset < 1: # Need at least 1 byte for message count
                parsed_entry["error"] = "Datenstrom zu kurz für Message Pack Payload (fehlt Message Count)"
                all_parsed_messages.append(parsed_entry)
                break
            
            pack_payload = data_bytes[pack_payload_start_offset:]
            parsed_pack_data = parse_message_pack(pack_payload, source_description)
            
            if "messages" in parsed_pack_data:
                 for msg_idx, msg in enumerate(parsed_pack_data["messages"]):
                    msg["source_description"] = f"Msg {msg_idx+1} in Pack from {source_description}"
                    all_parsed_messages.append(msg)
            elif "error" in parsed_pack_data:
                 all_parsed_messages.append({"error": parsed_pack_data["error"], 
                                             "source_description": f"Message Pack from {source_description}",
                                             "declared_message_count": parsed_pack_data.get("declared_message_count")})

            # Determine consumed bytes by message pack: 1 (pack_header) + 1 (msg_count) + (num_actual_msgs * 23)
            # This is tricky if pack is malformed. For simplicity, assume it tries to consume based on declared count
            # or available data.
            # A robust way is for parse_message_pack to return consumed length.
            # Here, we assume the pack parser consumes what it can and we might over-consume or under-consume
            # if the stream has more data after a pack, or the pack is shorter than expected.
            # For now, let's assume one pack per advertisement payload for WiFi beacons.
            num_messages_parsed = len(parsed_pack_data.get("messages", []))
            consumed_by_pack_payload = 1 + (num_messages_parsed * 23) if num_messages_parsed > 0 else 1
            offset += (1 + consumed_by_pack_payload) # 1 for pack header + consumed payload
            # If an error occurred early in pack parsing, offset might need adjustment.
            # This part is simplified; a more robust parser would handle offsets precisely.
            # For now, if a pack is detected, we assume it's the only content or we stop.
            break # Simplification: process one top-level item (pack or single msg) from this source.

        elif message_type in [ODID_MESSAGE_TYPE_BASIC_ID, ODID_MESSAGE_TYPE_LOCATION, 
                              ODID_MESSAGE_TYPE_SELF_ID, ODID_MESSAGE_TYPE_SYSTEM, ODID_MESSAGE_TYPE_OPERATOR_ID]:
            if len(data_bytes) - offset < 23: # 1 header + 22 payload
                parsed_entry["error"] = f"Datenstrom zu kurz für einzelne Nachricht Typ {message_type} (braucht 23 Bytes, hat {len(data_bytes) - offset})"
                all_parsed_messages.append(parsed_entry)
                break 
            
            message_payload = data_bytes[offset+1 : offset+23]
            
            if message_type == ODID_MESSAGE_TYPE_BASIC_ID:
                parsed_entry.update(parse_basic_id_message(message_payload))
            elif message_type == ODID_MESSAGE_TYPE_LOCATION:
                parsed_entry.update(parse_location_vector_message(message_payload))
            else:
                parsed_entry["error"] = f"Nicht unterstützter einzelner Nachrichtentyp: {message_type}"
                parsed_entry["raw_payload_hex"] = message_payload.hex()
            
            all_parsed_messages.append(parsed_entry)
            offset += 23
        else:
            parsed_entry["error"] = f"Unbekannter Message Type {message_type} im Datenstrom an Offset {offset}"
            all_parsed_messages.append(parsed_entry)
            break 
    return all_parsed_messages


# --- BLE Scan ---
ble_collected_raw_advertisements = []
ble_ui_device_display_data = {}

def ble_detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    timestamp_event = datetime.now().isoformat()
    device_details_repr = str(device.details) if hasattr(device, 'details') else "N/A"
    manufacturer_data_hex = {str(k): v.hex() for k, v in advertisement_data.manufacturer_data.items()}
    service_data_hex = {str(k): v.hex() for k, v in advertisement_data.service_data.items()}

    ble_collected_raw_advertisements.append({
        "timestamp_event": timestamp_event, "device_address": device.address,
        "device_name_bledevice": device.name, "advertisement_local_name": advertisement_data.local_name,
        "rssi": advertisement_data.rssi, "manufacturer_data": manufacturer_data_hex,
        "service_data": service_data_hex, "service_uuids": [str(uuid) for uuid in advertisement_data.service_uuids],
        "device_details_platform": device_details_repr
    })

    parsed_rid_messages_for_ui = []
    # Check Service Data
    for uuid_str, data_hex_str in service_data_hex.items():
        if ODID_SERVICE_UUID_SHORT in uuid_str.lower() or ODID_SERVICE_UUID.lower() in uuid_str.lower():
            try:
                service_payload_bytes = bytes.fromhex(data_hex_str)
                parsed_messages = parse_odid_data_stream(service_payload_bytes, f"BLE ServiceData UUID {uuid_str[:10]}")
                parsed_rid_messages_for_ui.extend(parsed_messages)
            except ValueError:
                log_message_ui(f"Fehler Dekod. Service Data Hex (BLE) {device.address}: {data_hex_str}", "ble_scan_log_ui")

    # Check Manufacturer Data
    for company_id_str, data_hex_str in manufacturer_data_hex.items():
        try:
            company_id = int(company_id_str)
            manufacturer_payload_bytes = bytes.fromhex(data_hex_str)
            if company_id == APPLE_COMPANY_ID and len(manufacturer_payload_bytes) > 1 and \
               manufacturer_payload_bytes[0] == 0x02 and manufacturer_payload_bytes[1] == 0x15:
                continue # Skip iBeacon

            parsed_messages = parse_odid_data_stream(manufacturer_payload_bytes, f"BLE ManufData CID {company_id_str} (0x{company_id:04X})")
            parsed_rid_messages_for_ui.extend(parsed_messages)
        except ValueError:
            log_message_ui(f"Fehler Dekod. Manuf Data Hex (BLE) {device.address}, CID {company_id_str}: {data_hex_str}", "ble_scan_log_ui")
        except Exception as e:
            log_message_ui(f"Allg. Fehler Parsen Manuf Data (BLE) {device.address}, CID {company_id_str}: {e}", "ble_scan_log_ui")

    if parsed_rid_messages_for_ui: # Nur hinzufügen, wenn RID-Daten gefunden wurden oder Fehler beim Parsen auftraten
        ble_ui_device_display_data[device.address] = {
            "name": advertisement_data.local_name or device.name or "N/A", "address": device.address,
            "rssi": advertisement_data.rssi, "manufacturer_data_hex_display": manufacturer_data_hex,
            "service_data_hex_display": service_data_hex, "service_uuids": [str(uuid) for uuid in advertisement_data.service_uuids],
            "timestamp": timestamp_event, "parsed_remote_id": parsed_rid_messages_for_ui
        }

async def scan_ble_for_odid_async(scan_duration=10):
    log_message_ui(f"Starte BLE Rohdaten-Scan für {scan_duration} Sekunden...", "ble_scan_log_ui")
    global ble_collected_raw_advertisements, ble_ui_device_display_data
    ble_collected_raw_advertisements = []
    ble_ui_device_display_data = {} 

    log_filename = f"ble_raw_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    log_filepath = os.path.join(os.getcwd(), log_filename)
    
    scanner = BleakScanner(detection_callback=ble_detection_callback)
    
    try:
        await scanner.start()
        log_message_ui(f"BLE Scanner gestartet. Sammle Daten... Logdatei: {log_filename}", "ble_scan_log_ui")
        await asyncio.sleep(scan_duration)
        await scanner.stop()
        log_message_ui(f"BLE Scanner gestoppt. {len(ble_collected_raw_advertisements)} Roh-Advertisements erfasst.", "ble_scan_log_ui")

        if ble_collected_raw_advertisements:
            with open(log_filepath, 'w', encoding='utf-8') as f:
                for entry in ble_collected_raw_advertisements:
                    json.dump(entry, f)
                    f.write('\n')
            log_message_ui(f"BLE Rohdaten erfolgreich in '{log_filepath}' geschrieben.", "ble_scan_log_ui")
            st.session_state.last_ble_log_file = log_filepath
        else:
            log_message_ui("Keine BLE Roh-Advertisements zum Loggen erfasst.", "ble_scan_log_ui")
            st.session_state.last_ble_log_file = None
    except BleakError as e:
        log_message_ui(f"BLEAK Fehler: {e}", "ble_scan_log_ui")
        st.error(f"Bluetooth-Fehler: {e}. Stellen Sie sicher, dass Bluetooth aktiviert ist.")
        st.session_state.last_ble_log_file = None
        return None 
    except Exception as e:
        log_message_ui(f"Allgemeiner Fehler beim BLE Scannen: {e}", "ble_scan_log_ui")
        st.error(f"Ein unerwarteter Fehler beim BLE Scannen ist aufgetreten: {e}")
        st.session_state.last_ble_log_file = None
        return None 
    return ble_ui_device_display_data


# --- WiFi Scan (mit Scapy) ---
wifi_collected_odid_packets = [] # Store raw packets that might contain ODID
wifi_ui_device_display_data = {} # Store parsed ODID data from WiFi
global_wifi_scan_stop_event = threading.Event()

def wifi_odid_packet_handler(packet):
    """
    Scapy packet handler for WiFi ODID.
    This function is called for each captured packet.
    """
    if global_wifi_scan_stop_event.is_set(): # Stop sniffing if event is set
        return True # Returning True to Scapy's sniff tells it to stop

    if packet.haslayer(Dot11Beacon):
        beacon_frame = packet.getlayer(Dot11Beacon)
        source_mac = packet.addr2 # MAC address of the AP

        # Iterate through Information Elements (IEs) in the beacon frame
        current_elt = beacon_frame.payload
        while isinstance(current_elt, Dot11Elt) or isinstance(current_elt, Dot11EltVendorSpecific) :
            if current_elt.ID == 221: # Vendor Specific IE
                # Check for ASTM OUI (00:1A:70)
                # Scapy's Dot11EltVendorSpecific has an 'oui' field (usually int) and 'info' field (bytes)
                # Convert ODID_WIFI_ASTM_OUI to integer for comparison if needed, or compare bytes directly.
                # For simplicity, we assume 'info' starts with OUI if not directly available as a field.
                # A more robust way: check current_elt.oui if available and matches.
                # The 'info' field of Dot11EltVendorSpecific contains: OUI (3 bytes) + Vendor Specific Data
                
                vendor_info = getattr(current_elt, 'info', b'')
                
                if len(vendor_info) > 3 and vendor_info.startswith(ODID_WIFI_ASTM_OUI):
                    # Check for the Vendor Specific OUI Type (e.g., 0xDD)
                    # ASTM F3411-22a (8.3.2) specifies this byte after the OUI.
                    if len(vendor_info) > 4 and vendor_info[3] == ODID_WIFI_VENDOR_OUI_TYPE_OPENDROENID:
                        odid_payload = vendor_info[4:] # Data after OUI and Vendor Specific OUI Type
                        
                        timestamp_event = datetime.now().isoformat()
                        log_message_ui(f"Potenzielles WiFi ODID Beacon von {source_mac} (OUI: {ODID_WIFI_ASTM_OUI.hex()}, Type: {ODID_WIFI_VENDOR_OUI_TYPE_OPENDROENID:02X}) Payload: {odid_payload.hex()}", "wifi_scan_log_ui")
                        
                        # Store raw packet info for logging
                        raw_packet_info = {
                            "timestamp_event": timestamp_event,
                            "source_mac": source_mac,
                            "rssi": packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A",
                            "channel": packet.ChannelFrequency if hasattr(packet, 'ChannelFrequency') else "N/A",
                            "oui": ODID_WIFI_ASTM_OUI.hex(),
                            "vendor_oui_type": f"{ODID_WIFI_VENDOR_OUI_TYPE_OPENDROENID:02X}",
                            "raw_odid_payload_hex": odid_payload.hex(),
                            "full_packet_summary": packet.summary() # For debugging
                        }
                        wifi_collected_odid_packets.append(raw_packet_info)

                        # Parse the ODID data stream
                        parsed_messages = parse_odid_data_stream(odid_payload, f"WiFi Beacon MAC {source_mac}")
                        
                        if parsed_messages:
                            # Aggregate messages by source MAC
                            if source_mac not in wifi_ui_device_display_data:
                                wifi_ui_device_display_data[source_mac] = {
                                    "name": f"WiFi AP {source_mac}", # Could try to get SSID if available
                                    "address": source_mac, # MAC address
                                    "rssi": raw_packet_info["rssi"],
                                    "timestamp": timestamp_event,
                                    "parsed_remote_id": []
                                }
                            # Update timestamp and RSSI for existing device
                            wifi_ui_device_display_data[source_mac]["timestamp"] = timestamp_event
                            wifi_ui_device_display_data[source_mac]["rssi"] = raw_packet_info["rssi"]
                            
                            # Append new messages, avoiding duplicates if necessary (complex logic not added here)
                            for msg in parsed_messages:
                                # Add some context about the WiFi source to the message
                                msg["wifi_source_mac"] = source_mac
                                wifi_ui_device_display_data[source_mac]["parsed_remote_id"].append(msg)
                        return # Found and processed ODID, move to next packet
            
            # Move to the next element in the linked list of IEs
            if not hasattr(current_elt, 'payload') or current_elt.payload is None :
                break 
            current_elt = current_elt.payload
    return False # Continue sniffing


def run_scapy_sniff(duration, iface=None):
    """Runs scapy.sniff in a separate thread."""
    if not SCAPY_AVAILABLE:
        log_message_ui("Scapy nicht verfügbar, WiFi-Scan übersprungen.", "wifi_scan_log_ui")
        return

    global global_wifi_scan_stop_event
    global_wifi_scan_stop_event.clear() # Reset stop event

    log_message_ui(f"Starte WiFi ODID Scan für {duration}s auf Interface '{iface if iface else 'default'}'...", "wifi_scan_log_ui")
    
    # Ensure Scapy uses the correct promiscuous mode settings if needed.
    # This can be platform-specific. For example, on Linux:
    # from scapy.arch import get_if_hwaddr, conf
    # conf.iface = iface # Set default interface for scapy
    # conf.sniff_promisc=True # May be needed

    try:
        # `prn` is the callback, `stop_filter` can stop sniffing if prn returns True
        # `timeout` stops sniffing after a duration.
        # `store=0` means packets are not stored in memory by sniff itself.
        # `lfilter` can be used to pre-filter packets, e.g., `lfilter=lambda p: p.haslayer(Dot11Beacon)`
        sniff(iface=iface, prn=wifi_odid_packet_handler, stop_filter=lambda p: global_wifi_scan_stop_event.is_set(), timeout=duration, store=0)
        log_message_ui("WiFi ODID Scan beendet (Timeout oder manueller Stopp).", "wifi_scan_log_ui")
    except PermissionError:
        log_message_ui("PermissionError: Scapy benötigt Root-/Admin-Rechte für WiFi Sniffing.", "wifi_scan_log_ui")
        st.error("WiFi Scan fehlgeschlagen: Keine Berechtigung. Führen Sie die App als Administrator/Root aus.")
    except OSError as e: # Catch errors like "Network is down" or "No such device"
         log_message_ui(f"OSError beim WiFi Sniffing: {e}. Ist das Interface korrekt und aktiv?", "wifi_scan_log_ui")
         st.error(f"WiFi Scan OS-Fehler: {e}. Prüfen Sie das angegebene Interface.")
    except Exception as e:
        log_message_ui(f"Allgemeiner Fehler beim WiFi Sniffing: {e}", "wifi_scan_log_ui")
        st.error(f"Ein unerwarteter Fehler beim WiFi Scannen ist aufgetreten: {e}")


async def scan_wifi_for_odid_async(scan_duration=10, iface=None):
    """
    Manages the WiFi ODID scan using Scapy in a separate thread.
    """
    if not SCAPY_AVAILABLE:
        st.error("Scapy ist nicht installiert oder konnte nicht geladen werden. WiFi Scan nicht möglich.")
        return None

    log_message_ui(f"Initialisiere WiFi ODID Scan für {scan_duration} Sekunden...", "wifi_scan_log_ui")
    global wifi_collected_odid_packets, wifi_ui_device_display_data
    wifi_collected_odid_packets = []
    wifi_ui_device_display_data = {} # Reset data for new scan

    # Run Scapy sniff in a separate thread to avoid blocking Streamlit's event loop
    # Scapy's sniff is blocking.
    scan_thread = threading.Thread(target=run_scapy_sniff, args=(scan_duration, iface))
    scan_thread.start()
    
    # Wait for the thread to complete (or for the timeout)
    # We need a way for Streamlit to remain responsive.
    # A simple join might block. Let's use a loop with sleep to allow UI updates.
    start_time = time.time()
    while scan_thread.is_alive():
        if time.time() - start_time > scan_duration + 2: # Add a small buffer
            log_message_ui("WiFi Scan Thread Timeout überschritten, versuche zu stoppen.", "wifi_scan_log_ui")
            global_wifi_scan_stop_event.set() # Signal thread to stop
            break
        await asyncio.sleep(0.5) # Allow other asyncio tasks to run

    if scan_thread.is_alive():
        scan_thread.join(timeout=2) # Final attempt to join
        if scan_thread.is_alive():
             log_message_ui("WiFi Scan Thread konnte nicht sauber beendet werden.", "wifi_scan_log_ui")


    log_message_ui(f"WiFi ODID Scan abgeschlossen. {len(wifi_collected_odid_packets)} potenzielle ODID-Pakete geloggt.", "wifi_scan_log_ui")

    if wifi_collected_odid_packets:
        log_filename = f"wifi_odid_raw_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        log_filepath = os.path.join(os.getcwd(), log_filename)
        with open(log_filepath, 'w', encoding='utf-8') as f:
            for entry in wifi_collected_odid_packets:
                json.dump(entry, f)
                f.write('\n')
        log_message_ui(f"WiFi ODID Rohdaten erfolgreich in '{log_filepath}' geschrieben.", "wifi_scan_log_ui")
        st.session_state.last_wifi_log_file = log_filepath
    else:
        log_message_ui("Keine WiFi ODID Pakete zum Loggen erfasst.", "wifi_scan_log_ui")
        st.session_state.last_wifi_log_file = None
    
    return wifi_ui_device_display_data


# --- Streamlit App Initialisierung und UI ---
def initialize_session_state():
    # BLE related
    if 'processed_ble_devices_ui' not in st.session_state:
        st.session_state.processed_ble_devices_ui = {}
    if 'ble_scan_log_ui' not in st.session_state:
        st.session_state.ble_scan_log_ui = []
    if 'ble_scanner_running' not in st.session_state:
        st.session_state.ble_scanner_running = False
    if 'last_ble_log_file' not in st.session_state:
        st.session_state.last_ble_log_file = None
    if 'ble_recent_raw_ads_preview' not in st.session_state:
        st.session_state.ble_recent_raw_ads_preview = []

    # WiFi related
    if 'processed_wifi_devices_ui' not in st.session_state:
        st.session_state.processed_wifi_devices_ui = {}
    if 'wifi_scan_log_ui' not in st.session_state:
        st.session_state.wifi_scan_log_ui = []
    if 'wifi_scanner_running' not in st.session_state:
        st.session_state.wifi_scanner_running = False
    if 'last_wifi_log_file' not in st.session_state:
        st.session_state.last_wifi_log_file = None
    if 'wifi_recent_raw_packets_preview' not in st.session_state:
        st.session_state.wifi_recent_raw_packets_preview = []


def display_parsed_data_table_and_map(data_dict, map_placeholder_key):
    """Helper to display parsed data in a table and map."""
    if not data_dict:
        st.info("Noch keine Gerätedaten für die UI-Analyse verarbeitet. Bitte starten Sie einen Scan.")
        return

    display_list_ui = []
    rid_map_data_ui = []

    for address, data_ui in data_dict.items():
        rid_summary_ui = "Nein"
        basic_id_info_ui = "N/A"
        location_info_ui = "N/A"
        
        parsed_rid_msgs = data_ui.get("parsed_remote_id", [])
        if parsed_rid_msgs:
            # Count actual messages, not just attempts or errors at the top level
            actual_message_count = sum(1 for m in parsed_rid_msgs if not m.get("error") or ("message_type_desc" in m))
            rid_summary_ui = f"Ja ({actual_message_count} Nachrichten)"
            
            uas_ids_found = set()
            locations_found = []

            for rid_msg in parsed_rid_msgs:
                msg_src_desc = rid_msg.get("source_description", "Unbekannt")
                if rid_msg.get("error") and not ("message_type_desc" in rid_msg) : # Show only critical errors here
                    error_info_ui = f"Parse-Fehler ({msg_src_desc}): {rid_msg['error']}"
                    if "Basic ID" in rid_msg.get("message_type_desc", ""): basic_id_info_ui = error_info_ui
                    elif "Location" in rid_msg.get("message_type_desc", ""): location_info_ui = error_info_ui
                    elif "Message Pack" in rid_msg.get("message_type_desc", "") : location_info_ui += f" | {error_info_ui}"
                    continue

                msg_type_desc = rid_msg.get("message_type_desc", "Unbekannt")

                if "Basic ID" in msg_type_desc:
                    uas_id = rid_msg.get('uas_id', 'N/A')
                    id_type = rid_msg.get('id_type_desc', 'N/A')
                    uas_ids_found.add(f"{uas_id} ({id_type})")
                
                elif "Location/Vector" in msg_type_desc:
                    lat, lon = rid_msg.get('latitude'), rid_msg.get('longitude')
                    alt_geo = rid_msg.get('altitude_geo_m')
                    if lat is not None and lon is not None:
                        loc_str = f"Lat: {lat:.5f}, Lon: {lon:.5f}"
                        if alt_geo is not None: loc_str += f", AltGeo: {alt_geo:.1f}m"
                        locations_found.append(loc_str + f" (via {msg_src_desc.split(' ')[-1]})") # Shorten src desc
                        if -90 <= lat <= 90 and -180 <= lon <= 180:
                             rid_map_data_ui.append({"lat": lat, "lon": lon, "name": f"{data_ui.get('name', address)} ({msg_src_desc.split(' ')[-1]})"})
            
            if uas_ids_found: basic_id_info_ui = " | ".join(list(uas_ids_found))
            if locations_found: location_info_ui = " | ".join(locations_found)

        display_list_ui.append({
            "Name/MAC": data_ui.get("name", "N/A"), "Adresse/MAC": address, "RSSI (dBm)": data_ui.get("rssi", "N/A"),
            "Remote ID?": rid_summary_ui, "RID Basic ID(s)": basic_id_info_ui, "RID Standort(e)": location_info_ui,
            "Letztes Update": datetime.fromisoformat(data_ui.get("timestamp", "")).strftime("%H:%M:%S") if data_ui.get("timestamp") else "N/A"
        })

    if display_list_ui:
        devices_df_ui = pd.DataFrame(display_list_ui)
        cols_to_show_ui = ["Name/MAC", "Adresse/MAC", "RSSI (dBm)", "Remote ID?", "RID Basic ID(s)", "RID Standort(e)", "Letztes Update"]
        valid_cols_ui = [col for col in cols_to_show_ui if col in devices_df_ui.columns]
        st.dataframe(devices_df_ui[valid_cols_ui], use_container_width=True)

        if rid_map_data_ui:
            st.subheader("📍 Standorte (aus geparsten RID-Daten)")
            map_df_ui = pd.DataFrame(rid_map_data_ui).dropna(subset=['lat', 'lon'])
            if not map_df_ui.empty: 
                map_df_ui = map_df_ui.drop_duplicates(subset=['lat', 'lon', 'name'])
                st.map(map_df_ui, zoom=10, key=f"{map_placeholder_key}_map")
            else: st.info("Keine gültigen Standortdaten für Karte aus RID-Analyse.")

        st.subheader("🔍 Detailansicht Roh- & Parsed-Daten (ausgewähltes Gerät)")
        device_addresses_ui = [d["Adresse/MAC"] for d in display_list_ui]
        if device_addresses_ui:
            selected_address_ui = st.selectbox(
                "Wähle Gerät für Details:", options=device_addresses_ui,
                format_func=lambda x: f"{data_dict.get(x, {}).get('name', 'N/A')} ({x})",
                key=f"{map_placeholder_key}_selector"
            )
            if selected_address_ui and selected_address_ui in data_dict:
                st.json(data_dict[selected_address_ui])
    else: st.info("Keine Gerätedaten für die UI-Tabelle vorhanden.")


def run_app():
    st.set_page_config(page_title="OpenDroneID Scanner (BLE & WiFi)", layout="wide")
    st.title("📡 OpenDroneID Scanner (Bluetooth LE & WiFi Beacon)")
    st.caption(f"Loggt BLE Advertisements & WiFi Beacons und versucht Remote ID (ASTM F3411-22a) zu parsen. System: {platform.system()}")

    initialize_session_state()

    tab1, tab2 = st.tabs(["Bluetooth LE RID Scan", "WiFi Beacon RID Scan"])

    with tab1:
        st.header("Bluetooth LE Remote ID Scan")
        col1_ble, col2_ble = st.columns([1,2])

        with col1_ble:
            st.subheader("Scan-Steuerung (BLE)")
            scan_duration_ble = st.slider(
                "Scan-Dauer (Sekunden)", 5, 60, 15, key="scan_duration_ble"
            )
            if st.button(
                "Starte BLE RID Scan", 
                key="start_ble_scan_button", 
                disabled=st.session_state.ble_scanner_running
            ):
                st.session_state.ble_scanner_running = True
                st.session_state.ble_recent_raw_ads_preview = [] 
                with st.spinner(f"Logge BLE Daten & parse Remote ID für {scan_duration_ble} Sek..."):
                    ui_data_from_scan = asyncio.run(scan_ble_for_odid_async(scan_duration_ble))
                
                if ui_data_from_scan is not None:
                    st.session_state.processed_ble_devices_ui = ui_data_from_scan
                    st.session_state.ble_recent_raw_ads_preview = ble_collected_raw_advertisements[-10:]
                    log_message_ui(f"BLE UI aktualisiert mit {len(ui_data_from_scan)} einzigartigen Geräten.", "ble_scan_log_ui")
                else:
                    log_message_ui("BLE Scan fehlgeschlagen oder keine UI-Daten erhalten.", "ble_scan_log_ui")
                    st.session_state.processed_ble_devices_ui = {}
                st.session_state.ble_scanner_running = False
                st.rerun()

            if st.session_state.last_ble_log_file:
                st.success(f"Letzte BLE Log: {os.path.basename(st.session_state.last_ble_log_file)}")
                try:
                    with open(st.session_state.last_ble_log_file, "r", encoding='utf-8') as fp:
                        st.download_button("Download BLE Log (.jsonl)", fp, os.path.basename(st.session_state.last_ble_log_file), "application/jsonl")
                except Exception as e:
                    st.error(f"Fehler Download BLE Log: {e}")
            
            st.markdown("---")
            st.subheader("Wichtige Hinweise (BLE):")
            st.warning("BLE Parser ist EXPERIMENTELL. Basiert auf ASTM F3411-22a für BT Legacy. Keine Garantie für Korrektheit.")
            st.info("Bluetooth muss aktiviert sein. Unter Linux ggf. erweiterte Rechte für Python nötig.")

        with col2_ble:
            st.subheader("📜 BLE UI Scan Log & Status")
            st.text_area("BLE UI Log:", value="\n".join(reversed(st.session_state.ble_scan_log_ui)), height=100, disabled=True, key="ble_ui_log_area")
            
            st.subheader("📊 BLE Live-Analyse & Potentielle Remote ID")
            display_parsed_data_table_and_map(st.session_state.processed_ble_devices_ui, "ble")

            st.subheader("🔬 BLE Vorschau Roh-Advertisements (aus Log-Puffer)")
            if st.session_state.ble_recent_raw_ads_preview:
                for i, raw_ad in enumerate(reversed(st.session_state.ble_recent_raw_ads_preview)):
                    with st.expander(f"BLE Raw Ad #{len(st.session_state.ble_recent_raw_ads_preview)-i}: {raw_ad['device_address']}"):
                        st.json(raw_ad)
            else:
                st.info("Keine BLE Roh-Advertisements in Vorschau.")

    with tab2:
        st.header("WiFi Beacon Remote ID Scan (Experimentell & Erfordert Scapy + Root/Admin)")
        if not SCAPY_AVAILABLE:
            st.error("Scapy ist nicht verfügbar. Diese Funktion kann nicht genutzt werden.")
        else:
            col1_wifi, col2_wifi = st.columns([1,2])
            with col1_wifi:
                st.subheader("Scan-Steuerung (WiFi)")
                wifi_iface = st.text_input("WiFi Interface (leer für default, z.B. wlan0, en0)", help="Name des WiFi-Interfaces, das für das Sniffing verwendet werden soll. Leer lassen, um das Standard-Interface von Scapy zu verwenden. Das Interface muss den Monitor-Modus unterstützen.")
                scan_duration_wifi = st.slider(
                    "Scan-Dauer (Sekunden)", 10, 120, 20, key="scan_duration_wifi"
                )

                if st.button(
                    "Starte WiFi RID Scan", 
                    key="start_wifi_scan_button", 
                    disabled=st.session_state.wifi_scanner_running
                ):
                    st.session_state.wifi_scanner_running = True
                    st.session_state.wifi_recent_raw_packets_preview = []
                    global_wifi_scan_stop_event.clear() # Sicherstellen, dass der vorherige Scan gestoppt ist

                    with st.spinner(f"Sniffe WiFi Beacons für {scan_duration_wifi} Sek auf '{wifi_iface if wifi_iface else 'default'}'... (Erfordert Root/Admin)"):
                        # Convert iface to None if empty string for Scapy
                        effective_iface = wifi_iface if wifi_iface else None
                        ui_data_from_wifi_scan = asyncio.run(scan_wifi_for_odid_async(scan_duration_wifi, effective_iface))
                    
                    if ui_data_from_wifi_scan is not None:
                        st.session_state.processed_wifi_devices_ui = ui_data_from_wifi_scan
                        st.session_state.wifi_recent_raw_packets_preview = wifi_collected_odid_packets[-10:]
                        log_message_ui(f"WiFi UI aktualisiert mit {len(ui_data_from_wifi_scan)} MAC-Adressen mit pot. ODID.", "wifi_scan_log_ui")
                    else:
                        log_message_ui("WiFi Scan fehlgeschlagen oder keine UI-Daten erhalten.", "wifi_scan_log_ui")
                        st.session_state.processed_wifi_devices_ui = {}
                    st.session_state.wifi_scanner_running = False
                    st.rerun()
                
                if st.button("Stoppe WiFi Scan Manuell", key="stop_wifi_scan_button", disabled=not st.session_state.wifi_scanner_running):
                    log_message_ui("Manueller Stopp des WiFi Scans angefordert...", "wifi_scan_log_ui")
                    global_wifi_scan_stop_event.set()


                if st.session_state.last_wifi_log_file:
                    st.success(f"Letzte WiFi Log: {os.path.basename(st.session_state.last_wifi_log_file)}")
                    try:
                        with open(st.session_state.last_wifi_log_file, "r", encoding='utf-8') as fp:
                            st.download_button("Download WiFi ODID Log (.jsonl)", fp, os.path.basename(st.session_state.last_wifi_log_file), "application/jsonl")
                    except Exception as e:
                        st.error(f"Fehler Download WiFi Log: {e}")

                st.markdown("---")
                st.subheader("Wichtige Hinweise (WiFi):")
                st.error("**BENÖTIGT SCAPY & ROOT/ADMIN RECHTE!**")
                st.warning("""
                - **Experimentell:** WiFi Beacon Sniffing ist komplex und plattformabhängig.
                - **Interface:** Das angegebene WiFi-Interface muss den Monitor-Modus unterstützen (nicht alle tun das).
                - **Berechtigungen:** Die Anwendung muss mit Root-/Admin-Rechten ausgeführt werden.
                - **Störungen:** Kann das normale WiFi-Netzwerk beeinträchtigen.
                - **Genauigkeit:** Parsing basiert auf ASTM F3411-22a. Keine Garantie.
                """)
                st.info("Installiere Scapy mit `pip install scapy`. Stelle sicher, dass auch die Abhängigkeiten wie Npcap (Windows) oder libpcap (Linux/macOS) korrekt installiert sind.")


            with col2_wifi:
                st.subheader("📜 WiFi UI Scan Log & Status")
                st.text_area("WiFi UI Log:", value="\n".join(reversed(st.session_state.wifi_scan_log_ui)), height=100, disabled=True, key="wifi_ui_log_area")

                st.subheader("📊 WiFi Live-Analyse & Potentielle Remote ID (von Beacons)")
                display_parsed_data_table_and_map(st.session_state.processed_wifi_devices_ui, "wifi")

                st.subheader("🔬 WiFi Vorschau Roh-Pakete mit pot. ODID (aus Log-Puffer)")
                if st.session_state.wifi_recent_raw_packets_preview:
                    for i, raw_pkt in enumerate(reversed(st.session_state.wifi_recent_raw_packets_preview)):
                        with st.expander(f"WiFi Raw Pkt #{len(st.session_state.wifi_recent_raw_packets_preview)-i}: MAC {raw_pkt['source_mac']}"):
                            st.json(raw_pkt)
                else:
                    st.info("Keine WiFi Roh-Pakete mit pot. ODID in Vorschau.")

    st.markdown("---")
    st.caption("Entwickelt als experimentelles Tool. Keine Gewähr für Richtigkeit. Nutzung auf eigene Gefahr.")

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    run_app()
