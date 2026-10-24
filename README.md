# Mapeador de rede local

Scanner IPv4 que detecta automaticamente a interface principal e sua máscara,
envia requisições ARP em broadcast e mostra IP, MAC e fabricante dos dispositivos
que responderem.

## Instalação

```powershell
python -m pip install -r requirements.txt
```

No Windows, o Scapy também precisa do [Npcap](https://npcap.com/) instalado.
Durante a instalação, habilite o modo compatível com a API do WinPcap.

## Execução

Abra o PowerShell **como Administrador** e execute:

```powershell
python network_mapper.py
```

Opções disponíveis:

```powershell
python network_mapper.py --timeout 3 --retry 1
```

Para informar manualmente a rede, a interface ou ambas:

```powershell
python network_mapper.py --rede 192.168.1.0/24
python network_mapper.py --interface "Wi-Fi"
python network_mapper.py --interface "Wi-Fi" --rede 192.168.1.0/24
```

Use `python network_mapper.py --help` para consultar todas as opções. Se o nome
amigável não for reconhecido pelo Npcap, utilize o identificador exibido pelo
Scapy, como `\Device\NPF_{...}`.

Em Linux/macOS, use `sudo python network_mapper.py`. Faça varreduras somente em
redes próprias ou nas quais você tenha autorização.
