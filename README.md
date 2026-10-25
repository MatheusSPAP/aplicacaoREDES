# Mapeador de rede local

Scanner IPv4 que detecta automaticamente a interface principal e sua máscara,
envia requisições ARP em broadcast e mostra IP, MAC e fabricante dos dispositivos
que responderem.

Para uma referência rápida com todos os comandos, consulte `COMANDOS.md`.

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

## API REST

A API FastAPI é somente leitura e roda independentemente dos scanners:

```powershell
$env:NETWORK_MAPPER_DB_PASSWORD = "sua-senha"
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

A API não exige chave, portanto mantenha-a em `127.0.0.1` ou proteja-a no proxy
reverso antes de permitir acesso externo. Em desenvolvimento, a documentação
fica em `/docs`, `/redoc` e `/openapi.json`. Defina
`NETWORK_MAPPER_API_ENV=production` para desabilitá-la por padrão. Consulte
[COMANDOS.md](COMANDOS.md) para todos os endpoints, variáveis e exemplos.

## Histórico no MySQL

Edite `config.py` e informe os mesmos dados usados na conexão do MySQL Workbench:

```python
MYSQL_HOST = "localhost"
MYSQL_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASSWORD = "sua-senha"
MYSQL_DATABASE = "network_mapper"
```

Depois execute:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --salvar-mysql
```

O arquivo está listado no `.gitignore` porque contém a senha em texto puro. Como
alternativa, as variáveis de ambiente abaixo sobrescrevem os valores do arquivo:

```powershell
$env:NETWORK_MAPPER_DB_HOST = "localhost"
$env:NETWORK_MAPPER_DB_PORT = "3306"
$env:NETWORK_MAPPER_DB_USER = "root"
$env:NETWORK_MAPPER_DB_PASSWORD = "sua-senha"
$env:NETWORK_MAPPER_DB_NAME = "network_mapper"
```

O banco e as tabelas `scans` e `scan_devices` são criados automaticamente. O
usuário informado precisa ter permissão para criar o banco na primeira execução.
Depois de salvar, o programa compara os MACs com a varredura anterior da mesma
sub-rede e informa dispositivos novos ou ausentes.

## Monitoramento automático

O modo de monitoramento sempre grava no MySQL. Ele executa uma varredura
imediatamente e repete no intervalo informado:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --monitorar --intervalo 60
```

Para interromper com segurança, pressione `Ctrl+C`. Os eventos já confirmados
permanecem gravados. Um dispositivo passa para `OFFLINE` somente depois de três
varreduras consecutivas sem resposta; se voltar, é registrado como
`RECONNECTED`. Mudanças de IP também geram eventos.

Uma rodada sem nenhuma resposta ARP, erro do Npcap ou perda da interface é
registrada como scan com falha e **não** incrementa as ausências dos dispositivos.
O intervalo é contado entre os inícios das rodadas; portanto, a duração do scan é
descontada da espera. Execução e erros são gravados em `network_mapper.log`, com
rotação automática.

Para monitorar mais de uma rede sequencialmente no mesmo processo:

```powershell
python network_mapper.py --monitorar --intervalo 60 `
  --alvo "192.168.1.0/24@Wi-Fi" `
  --alvo "10.0.0.0/24@Ethernet"
```

Cada `--alvo` aceita `REDE` ou `REDE@INTERFACE`. A mesma rede não pode aparecer
duas vezes. Além disso, um lock no MySQL impede duas instâncias do programa de
varrerem simultaneamente a mesma sub-rede.

ARP só alcança o segmento Ethernet local. A aplicação rejeita uma rede fora da
faixa diretamente conectada à interface; para redes atrás de um roteador, execute
o agente em uma máquina pertencente àquela rede.

O esquema é atualizado automaticamente ao conectar. Além dos snapshots em
`scans` e `scan_devices`, são usadas estas tabelas:

- `devices`: identidade global e datas gerais do MAC, mantida compatível;
- `device_ips`: histórico legado, preservado para compatibilidade;
- `device_events`: entradas, desconexões, reconexões e mudanças de IP.

As tabelas anteriores são preservadas. As migrações aditivas também criam:

- `network_device_state`: estado independente pela chave `(rede, MAC)`;
- `network_device_ips`: IPs históricos separados por rede;
- `scans.scan_key`: UUID único usado para retries idempotentes;
- campos de saúde, erro e duração em `scans`;
- a rede de origem em `device_events`.

As migrações são aplicadas automaticamente na conexão usando somente operações
aditivas e `INSERT IGNORE`; tabelas existentes não são apagadas nem recriadas.

Se o MySQL cair, o monitor usa reconexão progressiva. O scan pendente permanece
em memória e é reenviado com o mesmo UUID, evitando duplicação se a conexão tiver
caído depois do commit. Os padrões podem ser alterados em `config.py`:

```python
MYSQL_RECONNECT_ATTEMPTS = 5
MYSQL_RECONNECT_BASE_DELAY = 1.0
```

Ou na linha de comando:

```powershell
python network_mapper.py --monitorar --mysql-retries 8 --mysql-retry-delay 2
```

## Consultar histórico por MAC

A consulta não executa uma varredura e não precisa dos parâmetros de rede:

```powershell
python network_mapper.py --historico AA:BB:CC:DD:EE:FF
```

Para limitar a consulta a uma rede:

```powershell
python network_mapper.py --historico AA:BB:CC:DD:EE:FF --rede 192.168.1.0/24
```

Ela mostra o status atual, primeira e última detecção, todos os IPs utilizados e
os eventos anteriores. Também aceita MAC com hífens ou sem separadores.

## Descoberta avançada

Os recursos são opcionais e independentes. Para acrescentar hostname à varredura:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --resolver-hostname
```

Para verificar o perfil padrão de portas e identificar serviços:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --scan-portas
```

Para executar os dois recursos e salvar o inventário:

```powershell
python network_mapper.py --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --salvar-mysql
```

Portas específicas e faixas são aceitas:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --scan-portas `
  --portas "22,80,443,8000-8005" --port-timeout 0.5 --max-conexoes 16
```

Perfis disponíveis:

- `common`: serviços frequentes de rede;
- `web`: HTTP/HTTPS e portas web alternativas;
- `database`: bancos de dados comuns;
- `remote`: SSH, Telnet, RDP e VNC.

Exemplo:

```powershell
python network_mapper.py --rede 192.168.1.0/24 `
  --scan-portas --perfil-portas web
```

### Scanner TCP separado

O parâmetro `--host` não executa ARP e verifica somente os IPs informados. Cada
host deve pertencer à rede local autorizada indicada por `--rede`:

```powershell
python network_mapper.py --rede 192.168.1.0/24 `
  --host 192.168.1.10 --host 192.168.1.20 `
  --portas "22,80,443" --resolver-hostname
```

Os estados exibidos são `open`, `closed` e `no_response`. Timeout/filtro não é
tratado como prova de fechamento de uma porta anteriormente aberta.

Os serviços SSH, FTP, HTTP, HTTPS e MySQL podem ser confirmados por banner ou
handshake curto, sem autenticação. Outros serviços são marcados como `inferred`
com base na porta. Nenhuma credencial é enviada.

### Descoberta avançada no monitoramento

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --perfil-portas common
```

Por padrão, hostname e portas são atualizados a cada cinco scans ARP, evitando
consultas e conexões excessivas. Para mudar:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24 `
  --resolver-hostname --scan-portas --inventario-cada 10
```

As configurações padrão ficam em `config.py`:

```python
PORT_SCAN_TIMEOUT = 0.5
PORT_SCAN_MAX_CONNECTIONS = 32
PORT_SCAN_DEFAULT_PROFILE = "common"
INVENTORY_EVERY_N_SCANS = 5
```

Falhas de DNS, sockets ou identificação de serviço são registradas no log e não
invalidam nem interrompem a descoberta ARP.

### Histórico avançado no MySQL

As migrações automáticas adicionam, sem remover dados:

- `device_hostnames`: nomes já observados, fonte e datas;
- `device_ports`: estado atual, último resultado e serviço por rede/MAC/porta;
- `inventory_events`: hostname alterado, porta aberta/fechada e serviço alterado;
- `inventory_applied`: marcador idempotente por scan para retries seguros.

O comando existente de histórico também exibe esses dados:

```powershell
python network_mapper.py --historico AA:BB:CC:DD:EE:FF
```

## Testes simulados

Os testes não enviam ARP e não acessam o MySQL real:

```powershell
python -m unittest discover -s tests -v
```

## Histórico avançado e relatórios

### Consultas no terminal

Inventário online ou offline:

```powershell
python network_mapper.py --consultar inventario --status online
python network_mapper.py --consultar inventario --status offline
```

Eventos e alterações:

```powershell
python network_mapper.py --consultar eventos --rede 192.168.1.0/24
python network_mapper.py --consultar alteracoes --filtro-mac AA:BB:CC:DD:EE:FF
python network_mapper.py --consultar eventos --filtro-ip 192.168.1.10
```

Filtro por período:

```powershell
python network_mapper.py --consultar eventos `
  --data-inicio "2026-10-01" --data-fim "2026-10-31"
```

Equipamentos com mais desconexões e disponibilidade:

```powershell
python network_mapper.py --consultar desconexoes --limite 20
python network_mapper.py --consultar disponibilidade --rede 192.168.1.0/24
```

A disponibilidade mostra dois indicadores distintos: `response_percent` é o
percentual de respostas nas varreduras saudáveis, enquanto
`estimated_availability_percent` reconstrói o estado somente nos intervalos com
cobertura conhecida. `monitoring_coverage_percent` informa quanto do período foi
monitorado; lacunas ficam em `unknown_seconds` e não são presumidas como online.

Filtros disponíveis para consultas e relatórios:

- `--rede CIDR`;
- `--filtro-ip IP`;
- `--filtro-mac MAC`;
- `--status online|offline`;
- `--data-inicio` e `--data-fim`;
- `--limite` (mantido por compatibilidade);
- `--pagina` e `--por-pagina` para paginação.

### Relatórios imediatos

PDF completo:

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

Tipos: `inventario`, `eventos`, `alteracoes`, `desconexoes`,
`disponibilidade` e `completo`. Os arquivos ficam automaticamente em
`relatorios/ANO/MÊS`. Use `--pasta-relatorios CAMINHO` para trocar a pasta.

### Relatórios programados

Agendador diário com geração imediata inicial:

```powershell
python network_mapper.py --agendar-relatorios diario `
  --tipo-relatorio completo --formato pdf --gerar-agora
```

Também são aceitos `semanal` e `mensal`. O processo permanece ativo até
`Ctrl+C`. Quando nenhuma data é informada, cada execução usa o período anterior
correspondente: último dia, última semana ou último mês.

Em Linux/macOS, use `sudo python network_mapper.py`. Faça varreduras somente em
redes próprias ou nas quais você tenha autorização.
