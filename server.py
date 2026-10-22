import os
import sys
import json
import mimetypes
import socket
import subprocess
import time
import threading

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

from core.network_info import get_network_adapters, get_primary_adapter, get_all_network_scopes, calculate_network_scope, get_client_view_adapter
from core.arp_scanner import NetworkScanner
from core.db import set_custom_device, get_all_custom_devices
from core.wol import send_wake_on_lan

# Global scanner instance
scanner = NetworkScanner()
status_message = "Pronto para iniciar a varredura"

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class SolverNetworkHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress verbose HTTP access logs to keep console clean
        pass

    def send_json(self, data, status_code=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/network-info":
            client_ip = self.client_address[0] if (hasattr(self, 'client_address') and self.client_address) else "127.0.0.1"
            adapter = get_client_view_adapter(client_ip)
            self.send_json({
                "status": "success",
                "adapter": adapter,
                "client_ip": client_ip,
                "is_remote_client": bool(adapter and adapter.get("is_remote_client")),
                "hostname": socket.gethostname()
            })
            return

        elif path == "/api/adapters":
            adapters = get_network_adapters()
            self.send_json({
                "status": "success",
                "adapters": adapters
            })
            return

        elif path == "/api/scopes":
            scopes = get_all_network_scopes()
            self.send_json({
                "status": "success",
                "scopes": scopes
            })
            return

        elif path == "/api/scan-status":
            global status_message
            self.send_json({
                "status": "success",
                "is_scanning": scanner.is_scanning,
                "progress": scanner.progress,
                "status_text": status_message,
                "devices_count": len(scanner.devices),
                "stats": scanner.scan_stats,
                "devices": scanner.devices
            })
            return

        elif path == "/api/export":
            export_format = query.get("format", ["json"])[0]
            devices = scanner.devices
            stats = scanner.scan_stats

            if export_format == "csv":
                csv_lines = [
                    "IP,MAC,Nome,Categoria,Fabricante,Latencia (ms),Portas,Status,Notas"
                ]
                for d in devices:
                    ports = " ".join(str(p) for p in d.get("open_ports", []))
                    line = f'"{d.get("ip")}","{d.get("mac")}","{d.get("display_name")}","{d.get("category_label")}","{d.get("vendor")}","{d.get("latency_ms")}","{ports}","{d.get("status")}","{d.get("notes","")}"'
                    csv_lines.append(line)
                csv_data = "\n".join(csv_lines).encode("utf-8-sig")

                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="dispositivos_rede.csv"')
                self.send_header('Content-Length', str(len(csv_data)))
                self.end_headers()
                self.wfile.write(csv_data)
                return
            else:
                export_data = {
                    "rede": stats,
                    "dispositivos": devices,
                    "gerado_em": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                body = json.dumps(export_data, ensure_ascii=False, indent=2).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="relatorio_rede.json"')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

        # Static files serving
        if path == "/" or path == "":
            path = "/index.html"

        relative_path = path.lstrip("/")
        file_path = os.path.join(STATIC_DIR, relative_path)

        if os.path.isfile(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = "application/octet-stream"

            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", f"{content_type}; charset=utf-8" if "text" in content_type or "javascript" in content_type or "json" in content_type else content_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                self.send_json({"error": "Erro lendo arquivo estático"}, 500)
                return

        self.send_json({"error": "Rota não encontrada"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            body = json.loads(post_data.decode('utf-8'))
        except:
            body = {}

        if path == "/api/calculate-scope":
            ip = body.get("ip")
            netmask = body.get("netmask")
            prefix_len = body.get("prefix_len")
            cidr = body.get("cidr")

            if cidr and not ip:
                try:
                    parts = cidr.strip().split('/')
                    ip = parts[0]
                    prefix_len = int(parts[1]) if len(parts) > 1 else 24
                except Exception:
                    pass

            scope = calculate_network_scope(ip, netmask=netmask, prefix_len=prefix_len)
            if scope:
                self.send_json({"status": "success", "scope": scope})
            else:
                self.send_json({"status": "error", "message": "Parâmetros de rede ou máscara inválidos"}, 400)
            return

        elif path == "/api/scan":
            global status_message
            if scanner.is_scanning:
                self.send_json({"status": "already_scanning", "message": "Varredura já está em andamento"})
                return

            cidr = body.get("cidr")
            ip = body.get("ip")
            netmask = body.get("netmask")
            custom_range = body.get("custom_range")
            deep_scan = body.get("deep_scan", True)

            def progress_callback(pct, msg):
                global status_message
                status_message = msg

            def run_scan():
                global status_message
                status_message = "Iniciando varredura ARP da rede..."
                try:
                    scanner.scan(
                        target_cidr=cidr,
                        target_ip=ip,
                        target_netmask=netmask,
                        custom_range=custom_range,
                        deep_scan=deep_scan,
                        progress_cb=progress_callback
                    )
                    status_message = f"Varredura concluída! {len(scanner.devices)} dispositivos ativos encontrados."
                except Exception as e:
                    status_message = f"Erro na varredura: {str(e)}"

            t = threading.Thread(target=run_scan, daemon=True)
            t.start()

            self.send_json({"status": "started", "message": "Varredura iniciada com sucesso"})
            return

        elif path == "/api/scan-stop":
            scanner.stop()
            self.send_json({"status": "stopping", "message": "Interrupção solicitada"})
            return

        elif path == "/api/device/update":
            mac = body.get("mac")
            custom_name = body.get("custom_name")
            custom_category = body.get("custom_category")
            notes = body.get("notes")

            if not mac:
                self.send_json({"status": "error", "message": "Endereço MAC obrigatório"}, 400)
                return

            set_custom_device(mac, custom_name, custom_category, notes)

            # Update in current active devices list if present
            for d in scanner.devices:
                if d.get("mac") == mac:
                    if custom_name:
                        d["display_name"] = custom_name
                    if custom_category:
                        from core.device_classifier import CATEGORY_LABELS, CATEGORY_ICONS
                        d["category"] = custom_category
                        d["category_label"] = CATEGORY_LABELS.get(custom_category, custom_category.title())
                        d["icon"] = CATEGORY_ICONS.get(custom_category, "📦")
                    if notes is not None:
                        d["notes"] = notes
                    d["is_custom"] = True

            self.send_json({"status": "success", "message": "Dispositivo atualizado com sucesso"})
            return

        elif path == "/api/ping":
            ip = body.get("ip")
            if not ip:
                self.send_json({"status": "error", "message": "IP não informado"}, 400)
                return

            # Probe IP using ctypes SendARP and socket ping
            from core.arp_scanner import send_arp_probe
            t0 = time.time()
            arp_res = send_arp_probe(ip)
            dt = round((time.time() - t0) * 1000, 1)

            if arp_res:
                self.send_json({
                    "status": "online",
                    "ip": ip,
                    "latency_ms": arp_res.get("latency_ms", dt),
                    "mac": arp_res.get("mac")
                })
            else:
                self.send_json({
                    "status": "offline",
                    "ip": ip,
                    "latency_ms": None
                })
            return

        elif path == "/api/wol":
            mac = body.get("mac")
            if not mac:
                self.send_json({"status": "error", "message": "MAC não informado"}, 400)
                return
            try:
                send_wake_on_lan(mac)
                self.send_json({"status": "success", "message": f"Pacote Magic Packet Wake-on-LAN enviado para {mac}!"})
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)
            return

        self.send_json({"error": "Rota não encontrada"}, 404)

def run_server(host="0.0.0.0", port=5800, open_browser=True):
    # Register common MIME types
    mimetypes.add_type("text/css", ".css")
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("text/html", ".html")
    mimetypes.add_type("image/svg+xml", ".svg")

    # Try finding an open port if 5800 is busy
    actual_port = port
    httpd = None
    for p in range(port, port + 20):
        try:
            httpd = ThreadingSimpleServer((host, p), SolverNetworkHandler)
            actual_port = p
            break
        except OSError:
            continue

    if httpd is None:
        print(f"❌ Erro: Não foi possível vincular o servidor em nenhuma porta entre {port} e {port + 20}")
        return

    # Determine display URLs
    primary = None
    try:
        primary = get_primary_adapter()
    except Exception:
        pass

    local_ip = primary.get("ip") if primary else None
    local_url = f"http://localhost:{actual_port}"
    lan_url = f"http://{local_ip}:{actual_port}" if local_ip else None

    print("=" * 60)
    print(f"🚀 SOLVER NETWORK INICIADO COM SUCESSO!")
    print(f"💻 Acesso Local:          {local_url}")
    if lan_url and host == "0.0.0.0":
        print(f"🌐 Acesso na Rede Local:  {lan_url}")
    print(f"💡 Pressione Ctrl + C no terminal para encerrar.")
    print("=" * 60)

    if open_browser:
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(local_url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando Solver Network...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
