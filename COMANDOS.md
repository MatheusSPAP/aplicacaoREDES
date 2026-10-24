# Comandos do Network Mapper

Execute o PowerShell como **Administrador** e entre na pasta da aplicação:

```powershell
cd "C:\Users\mathe\Documents\Programação\aplicação redes"
```

## Instalação

```powershell
python -m pip install -r requirements.txt
```

Exibir todas as opções disponíveis:

```powershell
python network_mapper.py --help
```

## Varredura ARP

Detecção automática da rede e interface:

```powershell
python network_mapper.py
```

Informar a rede manualmente:

```powershell
python network_mapper.py --rede 192.168.1.0/24
```

Informar rede e interface:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --interface "Wi-Fi"
```

Alterar timeout e tentativas:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --timeout 3 --retry 1
```

Salvar a varredura no MySQL:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --salvar-mysql
```

## Monitoramento

Monitoramento básico a cada 60 segundos:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 --intervalo 60
```

Com hostname, portas e serviços:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --intervalo 60
```

Monitoramento com portas específicas:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas `
  --portas "22,80,443,445,3389" `
  --max-conexoes 10 --intervalo 60
```

Executar o inventário avançado a cada dez varreduras ARP:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --inventario-cada 10
```

Monitorar várias redes sequencialmente:

```powershell
python network_mapper.py --monitorar --intervalo 60 `
  --alvo "192.168.1.0/24@Wi-Fi" `
  --alvo "10.0.0.0/24@Ethernet"
```

Interromper o monitoramento com segurança:

```text
Ctrl+C
```

## Hostname, portas e serviços

Resolver hostnames:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --resolver-hostname
```

Usar o perfil padrão de portas:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --scan-portas
```

Varredura completa e salvamento no MySQL:

```powershell
python network_mapper.py --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --salvar-mysql
```

Portas e faixas específicas:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --scan-portas `
  --portas "22,80,443,3306,8000-8005" `
  --port-timeout 0.5 --max-conexoes 16
```

Perfis disponíveis:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --scan-portas --perfil-portas common
python network_mapper.py --rede 192.168.1.0/24 --scan-portas --perfil-portas web
python network_mapper.py --rede 192.168.1.0/24 --scan-portas --perfil-portas database
python network_mapper.py --rede 192.168.1.0/24 --scan-portas --perfil-portas remote
```

Scanner TCP separado, sem descoberta ARP:

```powershell
python network_mapper.py --rede 192.168.1.0/24 `
  --host 192.168.1.10 --host 192.168.1.20 `
  --portas "22,80,443" --resolver-hostname
```

## Histórico de um dispositivo

Consultar todas as redes de um MAC:

```powershell
python network_mapper.py --historico AA:BB:CC:DD:EE:FF
```

Limitar a uma rede:

```powershell
python network_mapper.py --historico AA:BB:CC:DD:EE:FF --rede 192.168.1.0/24
```

## Consultas avançadas

Dispositivos online:

```powershell
python network_mapper.py --consultar inventario --status online
```

Dispositivos offline:

```powershell
python network_mapper.py --consultar inventario --status offline
```

Inventário de uma rede:

```powershell
python network_mapper.py --consultar inventario --rede 192.168.1.0/24
```

Eventos de uma rede:

```powershell
python network_mapper.py --consultar eventos --rede 192.168.1.0/24
```

Eventos de um IP:

```powershell
python network_mapper.py --consultar eventos --filtro-ip 192.168.1.10
```

Alterações de IP, hostname, portas e serviços de um MAC:

```powershell
python network_mapper.py --consultar alteracoes --filtro-mac AA:BB:CC:DD:EE:FF
```

Equipamentos com mais desconexões:

```powershell
python network_mapper.py --consultar desconexoes --limite 20
```

Disponibilidade medida e estimada:

```powershell
python network_mapper.py --consultar disponibilidade --rede 192.168.1.0/24
```

Filtrar por período:

```powershell
python network_mapper.py --consultar eventos `
  --data-inicio "2026-10-01" --data-fim "2026-10-31"
```

Filtros que podem ser combinados:

```text
--rede CIDR
--filtro-ip IP
--filtro-mac MAC
--status online|offline
--data-inicio "AAAA-MM-DD"
--data-fim "AAAA-MM-DD"
--limite N
--pagina N
--por-pagina N
```

Exemplo de paginação (segunda página, 100 registros):

```powershell
python network_mapper.py --consultar eventos --pagina 2 --por-pagina 100
```

## Relatórios imediatos

Relatório completo em PDF:

```powershell
python network_mapper.py --relatorio completo --formato pdf
```

Inventário em Excel:

```powershell
python network_mapper.py --relatorio inventario --formato xlsx `
  --rede 192.168.1.0/24
```

Eventos em CSV:

```powershell
python network_mapper.py --relatorio eventos --formato csv `
  --data-inicio "2026-10-01" --data-fim "2026-10-31"
```

Relatório de disponibilidade:

```powershell
python network_mapper.py --relatorio disponibilidade --formato pdf `
  --rede 192.168.1.0/24
```

Relatório das principais desconexões:

```powershell
python network_mapper.py --relatorio desconexoes --formato xlsx --limite 50
```

Tipos de relatório:

```text
inventario
eventos
alteracoes
desconexoes
disponibilidade
completo
```

Formatos disponíveis:

```text
csv
xlsx
pdf
```

Escolher outra pasta para os relatórios:

```powershell
python network_mapper.py --relatorio completo --formato pdf `
  --pasta-relatorios "C:\RelatoriosRede"
```

## Relatórios programados

Diário, com geração imediata inicial:

```powershell
python network_mapper.py --agendar-relatorios diario `
  --tipo-relatorio completo --formato pdf --gerar-agora
```

Semanal:

```powershell
python network_mapper.py --agendar-relatorios semanal `
  --tipo-relatorio disponibilidade --formato xlsx
```

Mensal:

```powershell
python network_mapper.py --agendar-relatorios mensal `
  --tipo-relatorio completo --formato pdf
```

## MySQL e reconexão

Alterar tentativas e atraso inicial de reconexão:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --mysql-retries 8 --mysql-retry-delay 2
```

Sobrescrever conexão por variáveis de ambiente:

```powershell
$env:NETWORK_MAPPER_DB_HOST = "localhost"
$env:NETWORK_MAPPER_DB_PORT = "3306"
$env:NETWORK_MAPPER_DB_USER = "root"
$env:NETWORK_MAPPER_DB_PASSWORD = "sua-senha"
$env:NETWORK_MAPPER_DB_NAME = "network_mapper"
```

## Logs e testes

Escolher o arquivo de log:

```powershell
python network_mapper.py --monitorar --log-file "logs\network_mapper.log"
```

Executar os testes automatizados:

```powershell
python -m unittest discover -s tests -v
```

## Observações

- Execute varreduras somente em redes próprias ou autorizadas.
- ARP normalmente funciona apenas no segmento local e não atravessa roteadores.
- Os relatórios são organizados em `relatorios\ANO\MÊS` por padrão.
- O monitoramento e os agendadores permanecem ativos até `Ctrl+C`.
