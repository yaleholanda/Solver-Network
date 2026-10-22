# 📡 Solver Network - Gerenciador Inteligente de Redes Locais

O **Solver Network** é uma aplicação completa de descoberta, inventário e gerenciamento de rede local (LAN / IPAM), projetada especificamente para ambientes Windows com máxima performance, zero dependências complexas e uma interface moderna e futurista.

---

## 🚀 Principais Funcionalidades

1. **Identificação Completa da Rede**:
   - Detecta o adaptador de rede ativo (Ethernet / Wi-Fi).
   - Identifica Endereço IPv4 local, Máscara de Sub-rede, Gateway Padrão (Roteador), Servidores DNS e DHCP.
   - Calcula o bloco CIDR (ex: `192.168.1.0/24` ou `172.16.0.0/16`).

2. **Cálculo de Capacidade de Endereçamento IP**:
   - **Total de IPs**: Capacidade total de endereços da faixa ou sub-rede.
   - **IPs Ocupados**: Dispositivos ativos respondendo na rede.
   - **IPs Livres**: Endereços disponíveis para alocação manual ou DHCP.
   - **Taxa de Ocupação (%)**: Barra de progresso e gauge de densidade de rede.

3. **Mapa Visual de Alocação de IPs (IPAM Matrix Grid)**:
   - Matriz interativa com visualização individual de cada endereço IP (de `.1` a `.254`).
   - Cores indicativas:
     - 🟢 **Verde**: IP Ocupado (dispositivo ativo).
     - ⚪ **Cinza**: IP Livre (clique para copiar o IP para a área de transferência).
     - 🔵 **Azul**: Este Computador (máquina local).
     - 🟠 **Laranja**: Gateway Padrão (Roteador).
   - Tooltip ao passar o mouse com detalhes do dispositivo.

4. **Categorização Inteligente de Dispositivos**:
   - 💻 **Computadores / Notebooks**: Identificados por portas SMB (445), NetBIOS (139), RDP (3389), hostnames Windows (`DESKTOP-`, `LAPTOP-`, etc.) e fabricantes de placas-mãe (Dell, Lenovo, Asus, MSI, etc.).
   - 📱 **Celulares / Tablets**: Identificados por fabricantes mobile (Apple, Samsung, Xiaomi, Motorola), detecção de MAC aleatório (*Private Wi-Fi Address*) e hostnames.
   - 🖨️ **Impressoras**: Identificadas por portas JetDirect (9100), IPP (631), LPD (515), web banners e fabricantes (HP, Epson, Canon, Brother, Xerox, Lexmark).
   - 🌐 **Roteadores / Equipamentos de Rede**: Gateway padrão, servidores DNS (53) e fabricantes de rede (Fortinet, Ubiquiti, Mikrotik, Cisco, TP-Link, Intelbras).
   - 📺 **Smart TVs / Mídia**: Portas de streaming (Chromecast 8008/8009, AirPlay 7000) e fabricantes (Roku, LG webOS, Samsung TV, Sony).
   - 💡 **IoT / Automação**: Módulos inteligentes (Espressif ESP32/ESP8266, Tuya, Sonoff, Shelly, câmeras IP).
   - ❓ **Desconhecidos**: Demais dispositivos com informações de IP, MAC e latência.

5. **Identificação de Hardware & Fabricantes (OUI Database)**:
   - Banco de dados embutido com centenas de prefixos OUI dos principais fabricantes.
   - Cache persistente em SQLite local (`data/solver_network.db`).
   - Fallback online automático para novos fabricantes com salvamento no cache.

6. **Gerenciamento e Customização**:
   - **Personalização de Dispositivos**: Permite definir Nome Amigável (ex: *"Impressora Financeiro"*), alterar categoria e adicionar notas.
   - **Diagnóstico Rápido (Ping)**: Mede a latência em tempo real de qualquer host.
   - **Wake-on-LAN (WOL)**: Envia pacote Magic Packet para ligar computadores remotamente.
   - **Exportação de Relatórios**: Download com um clique em **CSV** (planilhas Excel) ou **JSON**.

---

## 📂 Estrutura do Projeto

```
Solver Network/
├── app.py                      # Ponto de entrada (Web UI e CLI)
├── server.py                   # Servidor HTTP multithreaded e API REST
├── Iniciar_Solver_Network.bat  # Inicializador de um clique para Windows
├── core/
│   ├── network_info.py         # Detecção de adaptadores e cálculo de sub-rede
│   ├── arp_scanner.py          # Scanner de alta velocidade (SendARP multithreaded)
│   ├── device_classifier.py    # Algoritmo de classificação heurística
│   ├── port_scanner.py         # Scanner de portas e banners HTTP/NetBIOS/DNS
│   ├── vendor_lookup.py        # Resolução de fabricantes MAC (offline + online)
│   ├── db.py                   # Banco de dados SQLite local
│   └── wol.py                  # Emissor de pacotes Wake-on-LAN
├── data/
│   ├── top_ouis.json           # Dicionário de fabricantes de hardware
│   └── solver_network.db       # Banco de dados de customizações e histórico
└── static/
    ├── index.html              # Interface web responsiva
    ├── css/style.css           # Tema escuro futurista com glassmorphism
    └── js/app.js               # Lógica de interface, IPAM grid e filtros
```

---

## ⚡ Como Executar

### Opção 1: Inicializador Rápido (Recomendado)
Dê um duplo clique no arquivo:
```
Iniciar_Solver_Network.bat
```
O servidor será iniciado e seu navegador padrão abrirá automaticamente em `http://localhost:5800`.
Também estará acessível para outros dispositivos (celulares, notebooks, tablets) na mesma rede local em: `http://<SEU_IP_LOCAL>:5800`.

### Opção 2: Via Terminal (Painel Web)
```powershell
python app.py
```
O console exibirá tanto o endereço local quanto o link para acesso em outras máquinas na rede:
```text
💻 Acesso Local:          http://localhost:5800
🌐 Acesso na Rede Local:  http://192.168.1.100:5800
```

### Opção 3: Modo Linha de Comando (CLI Rápido)
Para uma varredura direta no prompt de comando:
```powershell
python app.py --cli
```

---

## 🛡️ Vantagens Técnicas
- **Sem Drivers Externos**: Não requer Npcap, WinPcap ou privilégios de administrador. Utiliza a API nativa do Windows (`iphlpapi.dll -> SendARP`).
- **Zero Instalações Extras**: Utiliza exclusivamente a biblioteca padrão do Python 3 (nenhum `pip install` obrigatório).
- **Altíssima Velocidade**: Escaneia uma sub-rede inteira de 254 IPs em 2 a 4 segundos com concorrência multithreaded.
