import csv
import subprocess
from datetime import datetime

def listar_interfaces():
    """Lista las interfaces Wi-Fi disponibles y devuelve una lista de sus nombres."""
    try:
        print("[+] Listando interfaces Wi-Fi disponibles...")
        result = subprocess.check_output(["airmon-ng"], text=True).strip().split("\n")
        interfaces = []
        for line in result:
            if line.startswith("phy"):
                parts = line.split()
                if len(parts) >= 2:
                    interfaces.append(parts[1])  # Segundo elemento es el nombre de la interfaz
        return interfaces
    except Exception as e:
        print(f"[-] Error al listar interfaces: {e}")
        return []

def enable_monitor_mode(interface):
    """Habilita el modo monitor en la interfaz seleccionada."""
    try:
        print(f"[+] Habilitando modo monitor en {interface}...")
        subprocess.run(["airmon-ng", "start", interface], check=True)
        return f"{interface}mon"
    except subprocess.CalledProcessError:
        print("[-] Error al habilitar modo monitor.")
        return None

def disable_monitor_mode(interface):
    """Deshabilita el modo monitor en la interfaz."""
    try:
        print(f"[+] Deshabilitando modo monitor en {interface}...")
        subprocess.run(["airmon-ng", "stop", interface], check=True)
    except subprocess.CalledProcessError:
        print("[-] Error al deshabilitar modo monitor.")

def scan_wifi(interface, duration=10):
    """Escanea redes Wi-Fi y guarda los datos en un archivo CSV."""
    output_file = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    try:
        print("[+] Iniciando escaneo Wi-Fi...")
        subprocess.run(
            ["airodump-ng", "--output-format", "csv", "--write", output_file, interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=duration
        )
        print(f"[+] Escaneo completado. Resultados guardados en: {output_file}")
    except subprocess.TimeoutExpired:
        print("[+] Escaneo finalizado por tiempo.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error durante el escaneo: {e}")
    except Exception as e:
        print(f"[-] Error inesperado: {e}")
    return output_file

def parse_csv(input_csv, output_csv):
    """Procesa el archivo CSV de airodump-ng y guarda los datos relevantes en un nuevo archivo CSV."""
    try:
        print("[+] Procesando datos capturados...")
        with open(input_csv, "r") as infile:
            reader = csv.reader(infile)
            networks = []
            in_network_section = False
            for row in reader:
                if len(row) == 0:
                    continue
                if row[0] == "BSSID":
                    in_network_section = True
                    continue
                if in_network_section and row[0] == "":
                    break
                if in_network_section:
                    bssid = row[0].strip()
                    ssid = row[13].strip() if len(row) > 13 else "Desconocido"
                    auth = row[5].strip() if len(row) > 5 else "Desconocido"
                    networks.append({"BSSID": bssid, "SSID": ssid, "Autenticación": auth})
        
        with open(output_csv, "w", newline="") as outfile:
            writer = csv.DictWriter(outfile, fieldnames=["BSSID", "SSID", "Autenticación"])
            writer.writeheader()
            writer.writerows(networks)
        print(f"[+] Datos procesados y guardados en: {output_csv}")
    except Exception as e:
        print(f"[-] Error al procesar datos: {e}")

def main():
    interfaces = listar_interfaces()
    if not interfaces:
        print("[-] No se encontraron interfaces Wi-Fi disponibles.")
        return

    print("\n[+] Interfaces Wi-Fi disponibles:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    
    try:
        choice = int(input("\nSelecciona el número de la interfaz que deseas usar: "))
        if choice < 0 or choice >= len(interfaces):
            print("[-] Opción inválida.")
            return
        selected_interface = interfaces[choice]
    except ValueError:
        print("[-] Entrada inválida.")
        return

    output_csv = "wifi_networks.csv"
    
    monitor_interface = enable_monitor_mode(selected_interface)
    if monitor_interface:
        raw_csv = scan_wifi(monitor_interface)
        parse_csv(raw_csv, output_csv)
        disable_monitor_mode(monitor_interface)

if __name__ == "__main__":
    main()
