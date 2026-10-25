# API REST do Network Mapper

Este documento descreve os caminhos da API, os parâmetros aceitos e o que cada
requisição consulta no MySQL.

## Endereço base

Ao iniciar localmente na porta padrão, o endereço base é:

```text
http://127.0.0.1:8000
```

Todos os endpoints de dados utilizam o prefixo:

```text
/api/v1
```

A versão atual é somente leitura. Todos os endpoints utilizam `GET`; não existem
rotas para executar scanners, alterar dispositivos ou administrar o MySQL.

## Iniciar a API

```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

A API atual não exige chave. Por isso, mantenha o host em `127.0.0.1` ou coloque
autenticação em um proxy reverso antes de permitir acesso por outras máquinas.

## Parâmetros comuns

As rotas paginadas reutilizam os filtros de `QueryFilters`:

| Parâmetro | Exemplo | Função |
|---|---|---|
| `ip` | `192.168.1.10` | Filtra pelo IP atual ou histórico. |
| `mac` | `AA:BB:CC:DD:EE:FF` | Filtra pelo endereço MAC. |
| `network` | `192.168.1.0/24` | Filtra pela rede monitorada. |
| `status` | `online` | Aceita `online` ou `offline`. |
| `start_date` | `2026-10-01` | Início do período consultado. |
| `end_date` | `2026-10-31` | Final do período consultado. |
| `page` | `1` | Página, começando em 1. |
| `limit` | `100` | Registros por página, entre 1 e 1000. |

Datas podem utilizar os formatos:

```text
AAAA-MM-DD
AAAA-MM-DD HH:MM:SS
AAAA-MM-DDTHH:MM:SS
```

Ao informar uma rede em URL, a barra pode ser codificada como `%2F`:

```text
network=192.168.1.0%2F24
```

## Formato das respostas paginadas

As listagens paginadas retornam:

```json
{
  "data": [],
  "pagination": {
    "page": 1,
    "limit": 100,
    "returned": 0
  }
}
```

`returned` é a quantidade de registros presentes na página atual. Ele não é uma
contagem total de todos os registros do banco.

## Dispositivos

### `GET /api/v1/devices`

Lista o inventário de dispositivos. Consulta estado atual, IP, MAC, fabricante,
hostname, primeira detecção, última detecção e verificações sem resposta.

Aceita todos os parâmetros comuns.

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/devices?page=1&limit=50&status=online"
```

Resposta simplificada:

```json
{
  "data": [
    {
      "network": "192.168.1.0/24",
      "mac": "AA:BB:CC:DD:EE:FF",
      "ip": "192.168.1.10",
      "vendor": "Fabricante",
      "status": "online",
      "hostname": "servidor.local",
      "missing_checks": 0
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "returned": 1
  }
}
```

### `GET /api/v1/devices/{mac}`

Retorna os detalhes e o histórico completo de um dispositivo:

- fabricante;
- primeira e última detecção;
- estado em cada rede;
- IPs utilizados;
- eventos de presença;
- hostnames conhecidos;
- portas e serviços;
- eventos de inventário.

Parâmetro de caminho:

| Parâmetro | Função |
|---|---|
| `mac` | MAC do dispositivo, com ou sem separadores. |

Parâmetro opcional de query:

| Parâmetro | Função |
|---|---|
| `network` | Limita o histórico a uma rede CIDR. |

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/devices/AA:BB:CC:DD:EE:FF"
```

Se o MAC não existir, retorna HTTP `404`.

### `GET /api/v1/devices/{mac}/ports`

Retorna as portas e os serviços já armazenados para o dispositivo. Essa rota não
executa um novo scanner TCP.

Campos retornados incluem:

- rede e MAC;
- número da porta;
- estado atual e último resultado;
- serviço identificado;
- confiança e evidência;
- primeira detecção;
- última verificação;
- última detecção aberta.

Aceita o parâmetro opcional `network`.

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/devices/AA:BB:CC:DD:EE:FF/ports"
```

Se o dispositivo não existir, retorna HTTP `404`. Um dispositivo existente sem
portas verificadas retorna `data` como lista vazia.

## Redes

### `GET /api/v1/networks`

Lista as redes presentes no inventário e resume o estado atual.

Para cada rede, retorna:

- quantidade total de dispositivos;
- quantidade online;
- quantidade offline;
- primeira detecção;
- última detecção.

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/networks"
```

Resposta simplificada:

```json
{
  "data": [
    {
      "network": "192.168.1.0/24",
      "devices": 12,
      "online": 9,
      "offline": 3
    }
  ]
}
```

## Histórico e eventos

### `GET /api/v1/events`

Consulta eventos de presença e inventário em ordem decrescente de data.

Aceita todos os parâmetros comuns e também:

| Parâmetro | Função |
|---|---|
| `event_type` | Retorna somente um tipo específico de evento. |

Tipos aceitos:

```text
NEW
OFFLINE
RECONNECTED
IP_CHANGED
HOSTNAME_DISCOVERED
HOSTNAME_CHANGED
PORT_OPENED
PORT_CLOSED
SERVICE_CHANGED
```

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/events?event_type=OFFLINE&page=1&limit=100"
```

Cada evento informa categoria, tipo, rede, MAC, IP, porta, valor anterior, novo
valor e data da ocorrência.

### `GET /api/v1/availability`

Retorna as estatísticas de disponibilidade dos dispositivos.

Aceita todos os parâmetros comuns. Os campos principais são:

| Campo | Significado |
|---|---|
| `healthy_samples` | Quantidade de varreduras saudáveis no período. |
| `response_samples` | Quantidade de respostas do dispositivo. |
| `response_percent` | Percentual de respostas às varreduras. |
| `estimated_availability_percent` | Estimativa baseada nas mudanças de estado. |
| `monitoring_coverage_percent` | Parte do período com monitoramento conhecido. |
| `unknown_seconds` | Tempo sem informação suficiente. |

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/availability?network=192.168.1.0%2F24"
```

Períodos sem monitoramento não são presumidos como online.

### `GET /api/v1/disconnections`

Lista os dispositivos com mais eventos de desconexão no período consultado.

Aceita todos os parâmetros comuns.

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/disconnections?limit=20"
```

Retorna rede, MAC, quantidade de desconexões e data da desconexão mais recente.

## Relatórios

### `GET /api/v1/reports`

Reutiliza as consultas e os exportadores de `network_mapper_core/reporting.py`.

Aceita todos os parâmetros comuns e também:

| Parâmetro | Valores | Função |
|---|---|---|
| `report_type` | `inventario`, `eventos`, `alteracoes`, `desconexoes`, `disponibilidade`, `completo` | Conteúdo do relatório. |
| `format` | `json`, `csv`, `xlsx`, `pdf` | Formato da resposta. |
| `event_type` | tipos de eventos | Filtra eventos quando aplicável. |

O padrão é:

```text
report_type=completo
format=json
```

Request JSON:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/reports?report_type=inventario&format=json"
```

Download de arquivo:

```powershell
Invoke-WebRequest `
  -Uri "http://127.0.0.1:8000/api/v1/reports?report_type=inventario&format=xlsx" `
  -OutFile "inventario.xlsx"
```

Comportamento dos formatos:

- `json`: retorna os dados diretamente no corpo da resposta;
- `csv`: retorna CSV ou ZIP quando o relatório produz vários arquivos;
- `xlsx`: retorna uma planilha Excel;
- `pdf`: retorna o relatório PDF existente, sem alterar seu design.

Os arquivos temporários da requisição são removidos após o envio.

## Sistema

### `GET /api/v1/health`

Verifica se a aplicação está respondendo e se consegue executar uma consulta
simples no MySQL.

Request:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/health"
```

Resposta saudável:

```json
{
  "status": "ok",
  "database": "connected"
}
```

Uma falha de conexão retorna HTTP `503` sem expor a senha ou os detalhes da
configuração do MySQL.

## Documentação automática

### `GET /docs`

Abre o Swagger UI. Permite visualizar e testar as rotas pelo navegador.

```text
http://127.0.0.1:8000/docs
```

### `GET /redoc`

Abre a documentação ReDoc:

```text
http://127.0.0.1:8000/redoc
```

### `GET /openapi.json`

Retorna a especificação OpenAPI em JSON, útil para gerar clientes e integrar
outras aplicações.

```text
http://127.0.0.1:8000/openapi.json
```

Em produção, essas três rotas são desabilitadas por padrão quando
`NETWORK_MAPPER_API_ENV=production`.

## Códigos HTTP

| Código | Significado |
|---|---|
| `200` | Requisição concluída. |
| `404` | Dispositivo solicitado não encontrado. |
| `422` | IP, MAC, rede, data, paginação ou outro parâmetro inválido. |
| `503` | MySQL indisponível ou falha interna temporária. |

## Exemplos com curl e Python

curl:

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/devices?page=1&limit=10"
```

Python:

```python
import httpx

response = httpx.get(
    "http://127.0.0.1:8000/api/v1/events",
    params={"event_type": "OFFLINE", "page": 1, "limit": 100},
    timeout=10,
)
response.raise_for_status()
print(response.json())
```

## Mapa resumido

| Método | Caminho | Finalidade |
|---|---|---|
| `GET` | `/api/v1/devices` | Listar e filtrar dispositivos. |
| `GET` | `/api/v1/devices/{mac}` | Detalhes e histórico de um dispositivo. |
| `GET` | `/api/v1/devices/{mac}/ports` | Portas e serviços armazenados. |
| `GET` | `/api/v1/networks` | Resumo das redes monitoradas. |
| `GET` | `/api/v1/events` | Eventos de presença e inventário. |
| `GET` | `/api/v1/availability` | Disponibilidade e cobertura. |
| `GET` | `/api/v1/disconnections` | Dispositivos com mais desconexões. |
| `GET` | `/api/v1/reports` | Dados JSON ou exportação de relatórios. |
| `GET` | `/api/v1/health` | Saúde da API e do MySQL. |
| `GET` | `/docs` | Swagger UI. |
| `GET` | `/redoc` | ReDoc. |
| `GET` | `/openapi.json` | Especificação OpenAPI. |
