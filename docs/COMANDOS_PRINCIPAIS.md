# Comandos principais do Network Mapper

Execute o PowerShell como Administrador e entre na pasta da aplicação:

```powershell
cd "C:\Users\mathe\Documents\Programação\aplicação redes"
```

## Instalação e ajuda

```powershell
python -m pip install -r requirements.txt
python network_mapper.py --help
```

## Varredura ARP

Detectar automaticamente a rede e a interface:

```powershell
python network_mapper.py
```

Informar a rede e salvar no MySQL:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --salvar-mysql
```

## Monitoramento

Monitoramento básico:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 --intervalo 60
```

Monitoramento com hostname, portas e serviços:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --intervalo 60
```

Interrompa com `Ctrl+C`.

## Hostname e portas TCP

```powershell
python network_mapper.py --rede 192.168.1.0/24 --resolver-hostname
python network_mapper.py --rede 192.168.1.0/24 --scan-portas
python network_mapper.py --rede 192.168.1.0/24 --scan-portas `
  --portas "22,80,443,445,3306,3389"
```

Scanner TCP separado da descoberta ARP:

```powershell
python network_mapper.py --rede 192.168.1.0/24 `
  --host 192.168.1.10 --portas "22,80,443"
```

## Histórico e consultas

```powershell
python network_mapper.py --historico AA:BB:CC:DD:EE:FF
python network_mapper.py --consultar inventario --status online
python network_mapper.py --consultar inventario --status offline
python network_mapper.py --consultar eventos --rede 192.168.1.0/24
python network_mapper.py --consultar alteracoes `
  --filtro-mac AA:BB:CC:DD:EE:FF
python network_mapper.py --consultar disponibilidade `
  --rede 192.168.1.0/24
python network_mapper.py --consultar desconexoes --limite 20
python network_mapper.py --consultar eventos --pagina 2 --por-pagina 100
```

## Relatórios

```powershell
python network_mapper.py --relatorio completo --formato pdf
python network_mapper.py --relatorio inventario --formato xlsx
python network_mapper.py --relatorio eventos --formato csv `
  --data-inicio "2026-10-01" --data-fim "2026-10-31"
python network_mapper.py --agendar-relatorios diario `
  --tipo-relatorio completo --formato pdf --gerar-agora
```

## API REST

Iniciar a API local, sem executar os scanners:

```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

Alternativa que utiliza host e porta das variáveis de ambiente:

```powershell
python api_server.py
```

Documentação:

```text
http://127.0.0.1:8000/docs
http://127.0.0.1:8000/redoc
```

Verificar a API e o MySQL:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/health"
```

Consultar dispositivos:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/devices?page=1&limit=50"
```

## Testes

```powershell
python -m pytest -q
python -m unittest discover -s tests -v
```

Para a lista completa de parâmetros e exemplos, consulte `COMANDOS.md`.
