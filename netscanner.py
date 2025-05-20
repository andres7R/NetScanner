import asyncio
import json
import ipaddress
import httpx
import re
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Scapy puede requerir privilegios de root y puede no funcionar en todos los entornos (ej. algunos contenedores o WSL sin configuración especial)
# Se incluye como comentario para que el usuario sea consciente y lo habilite si su entorno lo permite.
# Si no se usa scapy, el descubrimiento de hosts y el escaneo de puertos necesitarán alternativas (ej. nmap en subprocess o socket a nivel de OS)
# from scapy.all import sr1, IP, ICMP, TCP, Ether, ARP, RandShort, conf

# --- Constantes y Configuraciones ---
USER_AGENT = "PythonNetworkScanner/1.0"
DEFAULT_TIMEOUT = 5
COMMON_WEB_PORTS = [80, 443, 8000, 8080, 8443]
SUSPICIOUS_PATHS = ["/admin", "/login", "/dashboard", "/phpmyadmin", "/.git/config", "/.env"]

# Cabeceras de seguridad importantes
SECURITY_HEADERS_CHECK = {
    "Content-Security-Policy": "CSP ayuda a prevenir XSS y otros ataques de inyección.",
    "Strict-Transport-Security": "HSTS previene ataques man-in-the-middle al forzar HTTPS.",
    "X-Content-Type-Options": "Previene que el navegador interprete archivos con un MIME type diferente al declarado.",
    "X-Frame-Options": "Protege contra clickjacking.",
    "Referrer-Policy": "Controla cuánta información de referente se incluye con las solicitudes.",
    "Permissions-Policy": "Controla qué características del navegador pueden ser usadas por la página."
    # "X-XSS-Protection": "Considerado obsoleto si CSP está bien implementado, pero su ausencia/valor '0' puede ser una señal."
}

# --- Base de Datos de Vulnerabilidades (Ejemplo Simple) ---
# Esto debería estar en un archivo JSON externo en una aplicación real
VULN_DB_FILE = "vuln_db.json"
VULN_DB = []

def load_vuln_db():
    global VULN_DB
    if os.path.exists(VULN_DB_FILE):
        try:
            with open(VULN_DB_FILE, 'r') as f:
                VULN_DB = json.load(f)
            print(f"[*] Base de datos de vulnerabilidades cargada desde {VULN_DB_FILE}")
        except Exception as e:
            print(f"[!] Error al cargar la base de datos de vulnerabilidades: {e}")
    else:
        print(f"[!] Archivo de base de datos de vulnerabilidades '{VULN_DB_FILE}' no encontrado. Creando ejemplo.")
        VULN_DB = [
            {
                "software_name": "Apache",
                "fingerprints": [
                    {"type": "header", "name": "Server", "pattern": r"Apache/([\d\.]+)"}
                ],
                "vulnerabilities": [
                    {"version_affected_regex": r"^2\.4\.(?:[0-9]|[1-4][0-9]|5[0-2])$", "cve": "CVE-2021-42013 (ejemplo)", "description": "Path Traversal and RCE in Apache HTTP Server 2.4.49-2.4.52 (ejemplo, verificar rangos)"}
                ]
            },
            {
                "software_name": "PHP",
                "fingerprints": [
                    {"type": "header", "name": "X-Powered-By", "pattern": r"PHP/([\d\.]+)"}
                ],
                "vulnerabilities": [
                    {"version_affected_regex": r"^[5-7]\..*", "cve": "Múltiples (EOL)", "description": "Versiones antiguas de PHP (5.x, 7.x < 7.4.z) están fuera de soporte y tienen vulnerabilidades conocidas."}
                ]
            }
        ]
        try:
            with open(VULN_DB_FILE, 'w') as f:
                json.dump(VULN_DB, f, indent=2)
        except Exception as e:
            print(f"[!] No se pudo guardar el ejemplo de vuln_db: {e}")


# --- Funciones de Red (Adaptadas para usar sockets si scapy no está disponible/permitido) ---
# Nota: El escaneo de puertos con sockets puros es más lento y menos sigiloso que con scapy (SYN scan)

async def is_host_alive_socket(target_ip: str, ping_ports: list = [80, 443]) -> bool:
    """Comprueba si un host está activo intentando conectar a puertos comunes."""
    # Esto no es un ping ICMP real, sino una prueba de conexión TCP.
    # Para ICMP puro sin scapy, se necesitarían raw sockets (generalmente root) o llamar al comando 'ping' del OS.
    for port in ping_ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=0.5 # Timeout corto para detección rápida
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            continue
    return False


async def scan_port_socket(target_ip: str, port: int, timeout: float = 1.0) -> bool:
    """Escanea un puerto TCP específico usando sockets."""
    try:
        conn = asyncio.open_connection(target_ip, port)
        _, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception: # Captura otras excepciones inesperadas
        return False

# --- Funciones de Análisis Web ---
async def fetch_http_info(session: httpx.AsyncClient, url: str, target_ip: str) -> dict:
    """Realiza una solicitud HTTP(S) y analiza la respuesta."""
    web_info = {
        "url": url,
        "status_code": None,
        "headers": {},
        "detected_technologies": [],
        "missing_security_headers": [],
        "security_warnings": [],
        "body_preview": "",
        "vulnerabilities_found": [] # Para la parte opcional
    }
    try:
        response = await session.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        web_info["status_code"] = response.status_code

        # Analizar cabeceras
        for key, value in response.headers.items():
            web_info["headers"][key.lower()] = value
            # Detección de tecnologías
            if key.lower() == "server":
                web_info["detected_technologies"].append(f"Server: {value}")
                check_vulnerabilities(web_info, "Server", value)
            elif key.lower() == "x-powered-by":
                web_info["detected_technologies"].append(f"X-Powered-By: {value}")
                check_vulnerabilities(web_info, "X-Powered-By", value)
            elif key.lower() == "set-cookie":
                if "wordpress_" in value.lower():
                    web_info["detected_technologies"].append("WordPress (deducido por cookie)")
                if "joomla_" in value.lower():
                    web_info["detected_technologies"].append("Joomla (deducido por cookie)")

        # Verificar cabeceras de seguridad faltantes
        for header, desc in SECURITY_HEADERS_CHECK.items():
            if header.lower() not in web_info["headers"]:
                web_info["missing_security_headers"].append(f"{header}: {desc}")

        # Fingerprinting básico del software web y contenido
        body_sample = response.text[:1024].lower() # Muestra pequeña del cuerpo para análisis
        web_info["body_preview"] = response.text[:200] + "..." if len(response.text) > 200 else response.text

        if "<meta name=\"generator\" content=\"WordPress" in body_sample:
            web_info["detected_technologies"].append("WordPress (detectado en meta tag)")
        if "wp-content/" in body_sample:
            web_info["detected_technologies"].append("WordPress (detectado por ruta wp-content/)")
        if "drupal" in body_sample:
            web_info["detected_technologies"].append("Drupal (posiblemente)")
        if "joomla" in body_sample:
            web_info["detected_technologies"].append("Joomla (posiblemente)")
        if "content=\"TYPO3 CMS\"" in response.text: # No en lower para preservar caso
            web_info["detected_technologies"].append("TYPO3 CMS (detectado en meta tag)")


        # OWASP - Advertencias
        if response.url.scheme == "http" and response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('location', '')
            if location and not location.startswith('https://'):
                web_info["security_warnings"].append(f"Redirección HTTP a HTTP: {url} -> {location}")

        # Detección pasiva XSS/SQLi (muy básica)
        if web_info["headers"].get("x-xss-protection") == "0":
            web_info["security_warnings"].append("X-XSS-Protection está deshabilitado (valor 0).")

        # Comprobar si hay Content-Security-Policy y si es restrictiva
        csp_header = web_info["headers"].get("content-security-policy")
        if csp_header:
            if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
                web_info["security_warnings"].append("CSP permite 'unsafe-inline' o 'unsafe-eval', lo que debilita la protección XSS.")
        else:
            # Ya se añade en missing_security_headers, pero podemos ser más específicos
            pass # web_info["security_warnings"].append("Content-Security-Policy no está presente, aumentando el riesgo de XSS.")

        # Para SQLi/LDAP pasivo: buscar mensajes de error genéricos en el cuerpo si el status code es 5xx
        # Esto es muy propenso a falsos positivos. Una prueba real requiere inyección.
        if 500 <= response.status_code < 600:
            error_patterns = [r"sqlstate", r"odbc driver", r"ora-\d{5}", r"unclosed quotation mark", r"ldap_search_ext"]
            for pattern in error_patterns:
                if re.search(pattern, body_sample, re.IGNORECASE):
                    web_info["security_warnings"].append(f"Posible exposición de error SQL/LDAP (patrón: {pattern}) en página de error.")
                    break

    except httpx.TimeoutException:
        web_info["security_warnings"].append(f"Timeout al conectar a {url}")
    except httpx.RequestError as e:
        web_info["security_warnings"].append(f"Error de solicitud para {url}: {type(e).__name__} - {str(e)}")
    except Exception as e:
        web_info["security_warnings"].append(f"Error inesperado procesando {url}: {e}")

    return web_info

async def check_suspicious_paths(session: httpx.AsyncClient, base_url: str, target_ip: str) -> list:
    """Comprueba rutas sospechosas y reporta si devuelven 200 OK."""
    warnings = []
    for path in SUSPICIOUS_PATHS:
        url_to_check = f"{base_url.rstrip('/')}{path}"
        try:
            response = await session.get(url_to_check, timeout=DEFAULT_TIMEOUT/2, follow_redirects=False) # No seguir redirecciones aquí
            if response.status_code == 200:
                warnings.append(f"Ruta sospechosa accesible '{path}' devolvió HTTP 200. Verificar manualmente.")
            # Podríamos añadir chequeos para 403 si no queremos que sean accesibles pero existen.
            # O si una página de login (ej. /admin/login) devuelve 200
            if (path.endswith("login") or path.endswith("admin")) and response.status_code == 200:
                warnings.append(f"Ruta '{path}' devolvió HTTP 200. Si es un panel administrativo, asegúrese que la autenticación es robusta.")

        except httpx.TimeoutException:
            # Silencioso para paths, ya que es común que no existan y den timeout o error
            pass
        except httpx.RequestError:
            # Silencioso
            pass
        except Exception:
            pass # Silencioso para errores en paths sospechosos
    return warnings

def check_vulnerabilities(web_info_dict: dict, header_type: str, header_value: str):
    """Comprueba el software detectado contra la base de datos de vulnerabilidades."""
    if not VULN_DB:
        return

    for entry in VULN_DB:
        for fingerprint in entry.get("fingerprints", []):
            if fingerprint["type"] == "header" and fingerprint["name"].lower() == header_type.lower():
                match = re.search(fingerprint["pattern"], header_value)
                if match:
                    version = match.group(1) if len(match.groups()) > 0 else "N/A"
                    software_full_name = f"{entry['software_name']} {version}"
                    if software_full_name not in web_info_dict["detected_technologies"]:
                        web_info_dict["detected_technologies"].append(software_full_name)

                    # Comprobar vulnerabilidades para esta versión
                    for vuln in entry.get("vulnerabilities", []):
                        if "version_affected_regex" in vuln and re.match(vuln["version_affected_regex"], version):
                            vuln_desc = f"Vulnerabilidad: {entry['software_name']} {version} - {vuln['cve']}: {vuln['description']}"
                            if vuln_desc not in web_info_dict["vulnerabilities_found"]:
                                web_info_dict["vulnerabilities_found"].append(vuln_desc)
                        # Se podrían añadir más tipos de comprobación de versiones (ej. start_including, end_excluding)


# --- Función Principal de Escaneo por Host ---
async def scan_host(target_ip: str, ports_to_scan: list, executor: ThreadPoolExecutor) -> dict:
    """Escanea un host individual: detecta si está activo, puertos abiertos y analiza servicios web."""
    host_report = {
        "ip": target_ip,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "down", # o "up"
        "open_ports": {},  # Cambiado a diccionario para almacenar servicio
        "web_services": [],
        "general_warnings": []
    }

    # 1. Comprobar si el host está activo
    # Usaremos el método de socket por defecto. Si scapy está disponible y se desea, se puede descomentar.
    # print(f"[*] Comprobando host: {target_ip}")
    # alive = await asyncio.to_thread(is_host_alive_scapy, target_ip) # Para scapy

    # Usando la alternativa de socket:
    if not await is_host_alive_socket(target_ip):
        # print(f"[-] Host {target_ip} parece estar inactivo o no responde a pruebas de conexión en puertos comunes.")
        host_report["status"] = "down or unresponsive"
        return host_report

    host_report["status"] = "up"
    # print(f"[+] Host {target_ip} está activo.")

    # 2. Escanear puertos
    open_ports_tasks = [scan_port_socket(target_ip, port) for port in ports_to_scan]
    results = await asyncio.gather(*open_ports_tasks)

    for port, is_open in zip(ports_to_scan, results):
        if is_open:
            service = "unknown"
            if port == 21: service = "ftp"
            elif port == 22: service = "ssh"
            elif port == 23: service = "telnet"
            elif port == 25: service = "smtp"
            elif port == 53: service = "dns"
            elif port == 80: service = "http"
            elif port == 110: service = "pop3"
            elif port == 139: service = "netbios-ssn"
            elif port == 143: service = "imap"
            elif port == 443: service = "https"
            elif port == 445: service = "microsoft-ds"
            elif port == 3306: service = "mysql"
            elif port == 3389: service = "ms-wbt-server"
            elif port == 5432: service = "postgresql"
            elif port == 5900: service = "vnc"
            elif port == 8000: service = "http-alt"
            elif port == 8080: service = "http-proxy"
            elif port == 8443: service = "https-alt"

            host_report["open_ports"][port] = service

    if not host_report["open_ports"]:
        # print(f"[*] Host {target_ip}: No se encontraron puertos abiertos de la lista especificada.")
        return host_report

    # print(f"[+] Host {target_ip}: Puertos abiertos -> {host_report['open_ports']}")

    # 3. Analizar servicios web en puertos abiertos comunes
    async with httpx.AsyncClient(verify=False, headers={"User-Agent": USER_AGENT}) as session: # verify=False para self-signed certs
        for port in host_report["open_ports"]:
            if port in COMMON_WEB_PORTS:
                scheme = "https" if port == 443 or port == 8443 else "http"
                base_url = f"{scheme}://{target_ip}:{port}"

                # print(f"[*] Analizando servicio web en {base_url}")
                web_analysis = await fetch_http_info(session, base_url, target_ip)

                # Comprobar rutas sospechosas
                suspicious_path_warnings = await check_suspicious_paths(session, base_url, target_ip)
                web_analysis["security_warnings"].extend(suspicious_path_warnings)

                # Si es puerto 80 (HTTP) y no hay redirección a HTTPS, o Strict-Transport-Security falta
                if scheme == "http" and "Strict-Transport-Security".lower() not in web_analysis["headers"]:
                    web_analysis["security_warnings"].append("Servicio en HTTP sin HSTS. Considerar HTTPS y HSTS.")
                if scheme == "http" and web_analysis["status_code"] and 200 <= web_analysis["status_code"] < 400:
                    # Comprobar si existe el mismo servicio en HTTPS
                    try:
                        https_url = f"https://{target_ip}:{443 if port == 80 else 8443 if port == 8080 else port}" # heurística simple
                        https_response = await session.head(https_url, timeout=2)
                        if https_response.status_code >= 200 and https_response.status_code < 400:
                            web_analysis["security_warnings"].append(f"Servicio HTTP en puerto {port}. Existe un servicio HTTPS ({https_url}). Asegurar redirección y HSTS.")
                        else:
                            web_analysis["security_warnings"].append(f"Servicio HTTP en puerto {port}. No se detectó un servicio HTTPS funcional en puerto estándar asociado.")
                    except httpx.RequestError:
                        web_analysis["security_warnings"].append(f"Servicio HTTP en puerto {port}. No se pudo comprobar servicio HTTPS. Asegurar que HTTPS esté disponible y sea preferido.")

                host_report["web_services"].append(web_analysis)

    return host_report

# --- Funciones de Scapy (requieren root, se dejan como referencia) ---
# Descomentar e instalar scapy si se desea usar.
# Asegurarse de ejecutar el script con sudo.
# conf.verb = 0 # Silenciar scapy

# def is_host_alive_scapy(target_ip: str, method: str = "icmp") -> bool:
#     """Comprueba si un host está vivo usando Scapy (ICMP o ARP)."""
#     try:
#         if method == "icmp":
#             pkt = IP(dst=target_ip)/ICMP()
#             resp = sr1(pkt, timeout=1, verbose=0)
#             return resp is not None
#         elif method == "arp": # Mejor para red local
#             ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=1, verbose=0)
#             return len(ans) > 0
#         else: # TCP SYN Ping a puerto 80
#             resp = sr1(IP(dst=target_ip)/TCP(dport=80, flags="S"), timeout=1, verbose=0)
#             if resp and resp.haslayer(TCP):
#                 if resp.getlayer(TCP).flags == 0x12: # SYN-ACK
#                     sr1(IP(dst=target_ip)/TCP(dport=resp.sport, flags="R"), timeout=1, verbose=0) # Reset connection
#                     return True
#                 elif resp.getlayer(TCP).flags == 0x14: # RST-ACK
#                     return True # Host está up, puerto cerrado
#             return False

#     except Exception as e:
#         print(f"[!] Scapy error en is_host_alive_scapy para {target_ip}: {e}")
#         return False


# def scan_port_scapy(target_ip: str, port: int, timeout: float = 1.0) -> bool:
#     """Escanea un puerto TCP usando Scapy (SYN Scan)."""
#     try:
#         src_port = RandShort()
#         p = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
#         resp = sr1(p, timeout=timeout, verbose=0)
#         if resp is not None and resp.haslayer(TCP):
#             if resp.getlayer(TCP).flags == 0x12: # SYN-ACK
#                 # Enviar RST para cerrar la conexión "abierta a medias"
#                 rst_pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
#                 send(rst_pkt, verbose=0)
#                 return True
#             # RST-ACK (0x14) significa puerto cerrado, no lo contamos como abierto.
#     except Exception as e:
#         print(f"[!] Scapy error en scan_port_scapy para {target_ip}:{port}: {e}")
#     return False

# --- Función Principal ---
async def main_scanner(network_segment: str, ports_str: str = "default", max_concurrent_hosts: int = 20, max_concurrent_ports_per_host: int = 10):
    try:
        # Parsear el segmento de red
        network, net_bits = network_segment.split('/')
        netmask = 32 - int(net_bits)
        if not (0 <= netmask <= 32):
            raise ValueError("Máscara de red inválida.")
        
        network_obj = ipaddress.ip_network(network_segment, strict=False)
    except ValueError as e:
        print(f"[-] Error: El segmento de red '{network_segment}' no tiene el formato CIDR válido (ej. 192.168.1.0/24) o es inválido. Detalle: {e}")
        sys.exit(1)

    # Parsear los puertos
    if ports_str.lower() == "default":
        ports_to_scan = COMMON_WEB_PORTS + [21, 22, 23, 25, 53, 110, 139, 143, 445, 3306, 3389, 5432, 5900]
    elif ports_str.lower() == "web":
        ports_to_scan = COMMON_WEB_PORTS
    elif ports_str.lower() == "all": # No recomendado para producción, muy lento
        ports_to_scan = list(range(1, 1025)) # Escanear primeros 1024 puertos
    else:
        try:
            ports_to_scan = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
            if not ports_to_scan:
                raise ValueError("No se especificaron puertos válidos.")
            if not all(0 < port < 65536 for port in ports_to_scan):
                raise ValueError("Puertos fuera de rango (1-65535).")
        except ValueError as e:
            print(f"[-] Error: Los puertos '{ports_str}' no tienen un formato válido (ej. '80,443,22'). Detalle: {e}")
            sys.exit(1)

    print(f"[*] Escaneando la red: {network_segment}")
    print(f"[*] Puertos a escanear: {ports_to_scan}\n")
    print(f"[*] Máxima concurrencia de hosts: {max_concurrent_hosts}")

    # Cargar base de datos de vulnerabilidades
    load_vuln_db()

    all_reports = []

    # Usar ThreadPoolExecutor para operaciones bloqueantes de Scapy si se usara Scapy
    # O para cualquier otra tarea que pueda ser intensiva en CPU o bloqueante y no sea async nativa.
    # Para las funciones de socket async, no es estrictamente necesario, pero puede ayudar si hay partes bloqueantes.
    executor = ThreadPoolExecutor(max_workers=max_concurrent_hosts) # Ajustar según sea necesario

    # Crear semáforo para limitar la concurrencia de hosts
    host_semaphore = asyncio.Semaphore(max_concurrent_hosts)

    tasks = []
    
    # Manejo de hosts a escanear
    hosts_to_scan = []
    if '/' in network_segment:
        network_obj = ipaddress.ip_network(network_segment, strict=False)
        if network_obj.prefixlen == 32: # Si es un /32, el propio network es el host
            hosts_to_scan = [str(network_obj.network_address)]
        else:
            hosts_to_scan = [str(ip) for ip in network_obj.hosts()]
    else: # Si es solo una IP sin CIDR, asumimos /32
        try:
            ipaddress.ip_address(network_segment)
            hosts_to_scan = [network_segment]
        except ValueError:
            print(f"[-] Error: La IP '{network_segment}' no es válida.")
            sys.exit(1)

    if not hosts_to_scan:
        print("[-] No se encontraron hosts válidos para escanear en el segmento de red proporcionado.")
        sys.exit(1)

    total_hosts = len(hosts_to_scan)
    processed_hosts = 0

    print(f"[*] Hosts a escanear ({total_hosts}): {', '.join(hosts_to_scan[:10])}{'...' if len(hosts_to_scan) > 10 else ''}\n")

    async def process_host_with_semaphore(ip, ports_to_scan, executor):
        nonlocal processed_hosts
        async with host_semaphore:
            # print(f"[*] Iniciando escaneo para {ip}...")
            report = await scan_host(str(ip), ports_to_scan, executor)
            processed_hosts += 1
            print(f"[*] Progreso: {processed_hosts}/{total_hosts} hosts procesados. Último: {ip} - Estado: {report.get('status', 'N/A')}")
            return report

    for ip in hosts_to_scan:
        tasks.append(process_host_with_semaphore(ip, ports_to_scan, executor))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    executor.shutdown(wait=True) # Limpiar el executor

    # Lista para almacenar los resultados filtrados
    scan_results = []
    for res in results:
        if isinstance(res, Exception):
            print(f"[!] Error durante el escaneo de un host: {res}")
        elif res and (res.get("open_ports") or res.get("web_services") or res.get("status") == "up"): # Solo guardar si hay info relevante o está up
            scan_results.append(res)
            
    # Guardar un reporte consolidado (opcional)
    try:
        consolidated_filename = f"consolidated_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        with open(consolidated_filename, 'w') as f:
            json.dump(scan_results, f, indent=4)
        print(f"[+] Reporte consolidado guardado en {consolidated_filename}")
    except Exception as e:
        print(f"[!] Error al guardar reporte consolidado: {e}")

    # --- Mostrar Resultados ---
    print("\n--- Resultados del Escaneo ---")
    if not scan_results:
        print("[-] No se encontraron hosts activos o puertos abiertos en el rango especificado.")
    else:
        for result in scan_results:
            print(f"\nHost: {result['ip']} (Estado: {result['status']})")
            if result['open_ports']:
                print("  Puertos abiertos:")
                for port, service in result['open_ports'].items():
                    print(f"    - {port}/tcp ({service})")
            else:
                print("  No se encontraron puertos abiertos conocidos.")

            if result['web_services']:
                print("  Servicios Web:")
                for service_info in result['web_services']:
                    print(f"    URL: {service_info['url']}")
                    print(f"    Estado HTTP: {service_info['status_code']}")
                    if service_info['detected_technologies']:
                        print(f"    Tecnologías detectadas: {', '.join(service_info['detected_technologies'])}")
                    if service_info['missing_security_headers']:
                        print("    Advertencias de seguridad (Cabeceras faltantes):")
                        for warning in service_info['missing_security_headers']:
                            print(f"      - {warning}")
                    if service_info['security_warnings']:
                        print("    Otras advertencias de seguridad:")
                        for warning in service_info['security_warnings']:
                            print(f"      - {warning}")
                    if service_info['vulnerabilities_found']:
                        print("    Vulnerabilidades detectadas:")
                        for vuln in service_info['vulnerabilities_found']:
                            print(f"      - {vuln}")
            
            if result['general_warnings']:
                print("  Advertencias generales del host:")
                for warning in result['general_warnings']:
                    print(f"    - {warning}")

    print("\n--- Fin del Escaneo ---")


if __name__ == "__main__":
    # --- Configuración ---
    # ADVERTENCIA: Escanear redes sin permiso es ilegal y no ético.
    # Asegúrate de tener autorización explícita para escanear el segmento de red objetivo.
    # Para probar localmente, puedes usar "127.0.0.1/32" o tu red local como "192.168.1.0/24".

    target_network = input("Introduce el segmento de red (ej. 192.168.1.0/24 o una IP 192.168.1.10/32): ")
    # Opciones de puertos: "default", "web", "all" (1-1024), o lista separada por comas (ej. "80,443,22")
    target_ports = input("Introduce los puertos a escanear ('default', 'web', 'all', o '80,443,22'): ") or "default"

    # ADVERTENCIA SOBRE SCAPY:
    # El siguiente código utiliza una alternativa basada en sockets para la detección de hosts y puertos
    # porque Scapy requiere privilegios de root y puede no ser universalmente compatible
    # o deseable para todos los usuarios. Si tienes Scapy instalado y deseas usar sus capacidades
    # (como SYN scans más sigilosos), deberás:
    # 1. Instalar scapy: pip install scapy
    # 2. Descomentar las importaciones de scapy y las funciones `*_scapy`.
    # 3. Modificar `scan_host` para llamar a las funciones de scapy (ej. usando `asyncio.to_thread`).
    # 4. Ejecutar el script con privilegios de administrador (ej. `sudo python tu_script.py`).
    print("\n[!] ADVERTENCIA: Este script realizará un escaneo de red.")
    print("    Asegúrate de tener autorización explícita para escanear el segmento de red objetivo.")
    print("    El escaneo de puertos y la detección de servicios pueden ser detectados por sistemas de seguridad.")
    print("    Actualmente se usan sockets estándar para detección. Scapy (requiere root) no está activo por defecto.\n")

    confirm = input("¿Continuar con el escaneo? (s/N): ")
    if confirm.lower() == 's':
        try:
            asyncio.run(main_scanner(target_network, target_ports))
        except KeyboardInterrupt:
            print("\n[!] Escaneo interrumpido por el usuario.")
        except Exception as e:
            print(f"\n[!] Error crítico durante la ejecución: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("[*] Escaneo cancelado.")
