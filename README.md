# NetScanner
Este script de Python, es una herramienta de escaneo de red asíncrono diseñada para descubrir hosts activos, identificar puertos abiertos y analizar servicios web. Utiliza asyncio para realizar operaciones de red concurrentes, lo que permite un escaneo eficiente de múltiples objetivos.

Características Principales
Detección de Hosts Activos: Comprueba si los hosts dentro de un segmento de red dado están activos, utilizando conexiones TCP a puertos comunes como una alternativa al ping ICMP (que a menudo requiere privilegios de root).
Escaneo de Puertos Concurrente: Identifica puertos TCP abiertos en los hosts activos, utilizando sockets estándar de Python para determinar si un puerto está escuchando conexiones.
Análisis de Servicios Web (HTTP/HTTPS): Para los puertos web comunes (80, 443, 8000, etc.), el script realiza solicitudes HTTP/HTTPS para:
Obtener el código de estado y las cabeceras de respuesta.
Detectar tecnologías web (servidor, lenguajes de programación como PHP, CMS como WordPress, etc.) basándose en cabeceras y contenido HTML.
Identificar la ausencia de cabeceras de seguridad importantes (como Content-Security-Policy, Strict-Transport-Security, X-Frame-Options), lo que indica posibles debilidades de seguridad.
Buscar rutas web "sospechosas" o comúnmente vulnerables (ej. /admin, /phpmyadmin).
Detectar posibles mensajes de error expuestos que podrían indicar vulnerabilidades de SQLi o LDAP.
Base de Datos de Vulnerabilidades Simple: Incluye una pequeña base de datos (vuln_db.json) para realizar una detección pasiva de vulnerabilidades. Compara las versiones de software detectadas (ej. Apache, PHP) con patrones conocidos para alertar sobre posibles CVEs o versiones obsoletas.
Generación de Reportes: Al finalizar el escaneo, el script consolida toda la información recopilada (hosts activos, puertos abiertos, detalles de servicios web y advertencias de seguridad) en un archivo JSON legible para un análisis posterior.
Flexibilidad en la Configuración: Permite al usuario especificar el segmento de red a escanear (en formato CIDR) y los puertos deseados (listas predefinidas como "default", "web", "all", o una lista personalizada de puertos).
Advertencia Importante
El script incluye una advertencia explícita sobre la ética y legalidad del escaneo de redes. Enfatiza que se requiere autorización explícita para escanear cualquier segmento de red que no se posea. También señala que, si bien utiliza sockets estándar, las herramientas de seguridad más avanzadas como Scapy podrían ofrecer un escaneo más sigiloso (pero requieren privilegios de root).

En esencia, PyScanNet es una herramienta básica pero funcional para realizar una evaluación inicial de la postura de seguridad de una red, identificando superficies de ataque y posibles configuraciones inseguras.
