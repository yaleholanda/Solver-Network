"""
SOLVER NETWORK - Gerenciador Inteligente de Redes Locais
Autor: Yale / Solver Network
Identificação de rede, cálculo de IPs (livres/ocupados), mapeamento de dispositivos e categorização automática.
"""

import sys
import argparse

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from server import run_server

def main():
    parser = argparse.ArgumentParser(description="Solver Network - Gerenciador Inteligente de Redes")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Endereço IP de escuta (padrão: 0.0.0.0 para acesso em toda a rede local)")
    parser.add_argument("--port", type=int, default=5800, help="Porta HTTP do servidor web (padrão: 5800)")
    parser.add_argument("--no-browser", action="store_true", help="Não abrir o navegador automaticamente")
    parser.add_argument("--cli", action="store_true", help="Executar varredura rápida diretamente no terminal")
    parser.add_argument("--cidr", type=str, default=None, help="Definir bloco CIDR para varredura completa (ex: 172.16.0.0/16)")
    parser.add_argument("--mask", type=str, default=None, help="Definir máscara de sub-rede (ex: 255.255.0.0)")
    parser.add_argument("--range", type=str, nargs=2, metavar=('START', 'END'), help="Definir faixa manual (ex: 192.168.0.1 192.168.0.50)")
    
    args = parser.parse_args()

    if args.cli:
        from core.arp_scanner import NetworkScanner
        from core.network_info import get_primary_adapter
        
        adapter = get_primary_adapter()
        print("=" * 60)
        print("🔍 SOLVER NETWORK - VARREDURA VIA TERMINAL")
        print("=" * 60)
        if adapter:
            print(f"Adaptador:         {adapter['adapter_name']}")
            print(f"IP Local:          {adapter['ip']}")
            print(f"Máscara de Rede:   {adapter['netmask']} (/{adapter['prefix_len']})")
            print(f"Gateway Padrão:    {adapter['gateway']}")
            print(f"Escopo da Rede:    {adapter['cidr']}")
            print(f"Faixa de Hosts:    {adapter.get('first_usable_ip')} - {adapter.get('last_usable_ip')}")
            print(f"IPs Disponíveis:   {adapter['usable_ips']:,}".replace(",", "."))
        print("-" * 60)
        print("Iniciando varredura completa do escopo...")
        
        scanner = NetworkScanner()
        res = scanner.scan(
            target_cidr=args.cidr,
            target_netmask=args.mask,
            custom_range=args.range,
            deep_scan=True
        )
        stats = res["stats"]
        devices = res["devices"]
        
        print("\n" + "=" * 60)
        print(f"📊 RESUMO DO ESCOPO ({stats['scope']}):")
        print(f"Máscara:               {stats.get('netmask', 'N/A')}")
        print(f"Total de IPs da Rede:  {stats['total_ips']:,}".replace(",", "."))
        print(f"IPs Utilizáveis:       {stats.get('usable_ips', stats['total_ips']):,}".replace(",", "."))
        print(f"IPs Ocupados:          {stats['occupied_ips']} ({stats['occupancy_rate']}%)")
        print(f"IPs Livres/Disponíveis:{stats['free_ips']:,}".replace(",", "."))
        print(f"Tempo de execução:     {stats['duration_sec']}s")
        print("-" * 60)
        print(f"{'STATUS':<8} {'IP':<16} {'MAC':<18} {'CATEGORIA':<20} {'NOME / FABRICANTE'}")
        print("-" * 75)
        for d in devices:
            cat = f"{d['icon']} {d['category_label']}"
            name = d['display_name']
            if d.get('vendor') and d['vendor'] not in name:
                name += f" ({d['vendor']})"
            print(f"{'ONLINE':<8} {d['ip']:<16} {d['mac']:<18} {cat:<20} {name[:30]}")
        print("=" * 75)
        return

    # Default: Start Web Server and Dashboard
    run_server(host=args.host, port=args.port, open_browser=not args.no_browser)

if __name__ == "__main__":
    main()
