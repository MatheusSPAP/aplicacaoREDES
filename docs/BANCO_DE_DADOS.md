# Banco de dados do Network Mapper

Este documento explica como o Network Mapper cria, atualiza e utiliza o banco
de dados MySQL.

## Visão geral

O Network Mapper utiliza o MySQL para armazenar:

- varreduras executadas e possíveis falhas;
- dispositivos encontrados por rede;
- estado atual de cada dispositivo;
- primeira e última detecção;
- endereços IP utilizados por cada MAC;
- conexões, desconexões e reconexões;
- alterações de IP e hostname;
- portas TCP, serviços e alterações de inventário;
- informações usadas no cálculo de disponibilidade e nos relatórios.

O código responsável pela persistência está em
`network_mapper_core/storage.py`. As consultas históricas estão em
`network_mapper_core/analytics.py`.

## O código cria o banco automaticamente?

Sim. Quando a aplicação de terminal precisa acessar o MySQL, ela executa as
seguintes etapas:

1. Conecta ao servidor MySQL configurado.
2. Cria o banco `network_mapper`, caso ainda não exista.
3. Seleciona o banco criado.
4. Cria somente as tabelas ausentes.
5. Aplica migrações aditivas necessárias.
6. Preserva todos os dados existentes.
7. Executa a operação solicitada.

O processo utiliza instruções equivalentes a:

```sql
CREATE DATABASE IF NOT EXISTS network_mapper;
CREATE TABLE IF NOT EXISTS ...;
```

O código não remove nem recria tabelas que já contenham históricos.

## O que precisa existir antes

A aplicação não instala o MySQL Server e não cria automaticamente o usuário do
servidor. Antes de utilizar o banco, é necessário ter:

- MySQL Server instalado e em execução;
- host e porta acessíveis, normalmente `localhost:3306`;
- usuário MySQL existente;
- senha correta;
- permissão para criar e utilizar o banco configurado.

As configurações locais ficam em `config.py`:

```python
MYSQL_HOST = "localhost"
MYSQL_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASSWORD = "sua-senha"
MYSQL_DATABASE = "network_mapper"
```

Também é possível substituir esses valores pelas variáveis de ambiente:

```text
NETWORK_MAPPER_DB_HOST
NETWORK_MAPPER_DB_PORT
NETWORK_MAPPER_DB_USER
NETWORK_MAPPER_DB_PASSWORD
NETWORK_MAPPER_DB_NAME
```

Variáveis de ambiente têm prioridade na API. Nos comandos de terminal, host,
porta, usuário e banco também podem ser informados pelos parâmetros documentados
em `COMANDOS.md`.

## Inicialização do banco

Uma varredura salva inicializa o banco automaticamente:

```powershell
python network_mapper.py --rede 192.168.1.0/24 --salvar-mysql
```

O monitoramento também inicializa e utiliza o banco:

```powershell
python network_mapper.py --monitorar --rede 192.168.1.0/24
```

No monitoramento não é necessário acrescentar `--salvar-mysql`, pois o banco é
necessário para comparar estados e preservar o histórico.

## Tabelas principais

### `scans`

Representa cada tentativa de varredura.

Armazena, entre outras informações:

- identificador da varredura;
- chave idempotente da operação;
- data e horário;
- interface utilizada;
- rede monitorada;
- quantidade de dispositivos;
- estado da varredura (`success` ou `failed`);
- mensagem de erro;
- duração.

Uma varredura com falha pode ser registrada, mas não altera o estado dos
dispositivos. Isso evita falsos alertas de desconexão.

### `scan_devices`

Contém os dispositivos que responderam em uma varredura saudável.

Cada registro relaciona:

- varredura;
- endereço IP;
- endereço MAC;
- fabricante.

### `devices`

Mantém o cadastro geral de dispositivos identificados pelo MAC.

Essa tabela é mantida por compatibilidade e para informações gerais, como o
fabricante. O estado separado por rede fica em `network_device_state`.

### `network_device_state`

Mantém o estado atual de cada dispositivo dentro de cada rede.

A chave principal é composta por:

```text
(network_cidr, mac_address)
```

Isso impede que um dispositivo de uma rede seja marcado offline durante a
varredura de outra rede. Também permite tratar o mesmo MAC separadamente em
segmentos diferentes.

Campos importantes:

- status atual (`online` ou `offline`);
- IP atual;
- primeira detecção;
- última detecção;
- quantidade de verificações consecutivas sem resposta.

O dispositivo somente passa para `offline` depois de três verificações
saudáveis consecutivas sem resposta.

### `network_device_ips`

Mantém todos os IPs utilizados por um MAC em cada rede.

Armazena:

- rede;
- MAC;
- IP;
- primeira utilização;
- última utilização;
- quantidade de detecções.

### `device_events`

Registra os eventos de presença:

- `NEW`: dispositivo detectado pela primeira vez;
- `OFFLINE`: dispositivo considerado desconectado;
- `RECONNECTED`: dispositivo voltou a responder;
- `IP_CHANGED`: alteração de endereço IP.

Os eventos permanecem armazenados mesmo quando o dispositivo está offline.

### `device_hostnames`

Mantém o histórico de hostnames encontrados por DNS reverso ou outro método de
resolução utilizado pela descoberta avançada.

Registra primeira detecção, última detecção, origem e quantidade de ocorrências.

### `device_ports`

Mantém o estado mais recente das portas verificadas:

- porta TCP;
- estado atual;
- último resultado;
- serviço identificado;
- nível de confiança;
- evidência leve utilizada na identificação;
- primeira detecção;
- última verificação;
- última vez em que a porta foi encontrada aberta.

### `inventory_events`

Registra mudanças do inventário avançado:

- hostname descoberto ou alterado;
- porta aberta;
- porta fechada;
- serviço alterado.

### `inventory_applied`

Controla quais inventários já foram processados. Essa tabela auxilia a evitar
que uma tentativa repetida grave as mesmas alterações novamente.

## Relacionamentos simplificados

```text
scans
  ├── scan_devices
  ├── device_events
  ├── inventory_events
  └── inventory_applied

devices
  └── network_device_state
        ├── network_device_ips
        ├── device_hostnames
        └── device_ports
```

As chaves estrangeiras preservam a consistência entre varreduras, dispositivos,
redes e históricos.

## Fluxo de gravação de uma varredura

```text
Scanner ARP
    ↓
Validação da saúde da varredura
    ↓
Registro em scans
    ↓
Registro dos dispositivos encontrados
    ↓
Comparação com network_device_state
    ↓
Atualização de status, IP e contadores
    ↓
Criação de eventos quando houver mudança
    ↓
Commit da transação
```

Caso ocorra um erro durante uma gravação transacional, a operação pode executar
`rollback`, evitando dados parcialmente atualizados.

## Prevenção de duplicações

A aplicação utiliza diferentes mecanismos de consistência:

- chave única por varredura;
- chaves primárias compostas por rede e MAC;
- índices únicos para eventos de inventário;
- `INSERT IGNORE` em migrações compatíveis;
- `ON DUPLICATE KEY UPDATE` para atualizar registros existentes;
- reutilização da mesma chave durante uma tentativa de reconexão ao MySQL.

Isso permite repetir uma operação após uma falha temporária sem criar uma nova
varredura ou evento equivalente desnecessariamente.

## Migrações seguras

Ao conectar pela aplicação de terminal, o código verifica se determinadas
colunas e índices existem antes de criá-los.

As migrações atuais são aditivas:

- adicionam colunas ausentes;
- adicionam índices para consultas históricas;
- copiam estados legados quando necessário;
- não executam `DROP TABLE`;
- não apagam históricos.

Mesmo assim, recomenda-se manter cópias de segurança regulares do banco em
ambientes importantes.

## Reconexão automática

Durante monitoramentos, falhas temporárias do MySQL não encerram imediatamente a
aplicação. O gerenciador resiliente:

1. identifica erros de conexão recuperáveis;
2. fecha a conexão inválida;
3. aguarda um intervalo progressivo;
4. abre uma nova conexão;
5. repete a operação usando a mesma chave idempotente.

O número de tentativas e o atraso inicial podem ser configurados conforme os
comandos descritos em `COMANDOS.md`.

## Funcionamento da API REST

A API usa um pool de conexões MySQL. Cada requisição recebe uma conexão própria,
que é devolvida ao pool ao final do processamento.

A API é somente leitura:

- consulta dispositivos, redes, eventos e disponibilidade;
- consulta portas e serviços armazenados;
- gera respostas JSON e arquivos de relatório;
- não executa varreduras;
- não cria dispositivos ou eventos;
- não administra o esquema do banco.

Por isso, o banco deve ser inicializado anteriormente pela aplicação de
terminal. Depois disso, a API pode ser iniciada de forma independente:

```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

## Consultas e disponibilidade

O módulo `network_mapper_core/analytics.py` executa consultas parametrizadas,
reduzindo o risco de injeção SQL.

O cálculo de disponibilidade diferencia:

- percentual de respostas às varreduras saudáveis;
- disponibilidade estimada a partir dos eventos;
- cobertura efetiva do monitoramento;
- períodos desconhecidos sem medições suficientes.

Períodos sem monitoramento não são considerados automaticamente como tempo
online.

## Segurança

- Evite compartilhar o arquivo `config.py` quando ele contiver uma senha real.
- Prefira fornecer a senha por `NETWORK_MAPPER_DB_PASSWORD`.
- Para a API, prefira um usuário MySQL com permissão somente de leitura.
- Não exponha diretamente o MySQL na internet.
- A API sem autenticação deve permanecer em `127.0.0.1` ou protegida por proxy.
- Execute varreduras somente em redes próprias ou autorizadas.

## Arquivos relacionados

- `config.py`: configurações locais do MySQL.
- `network_mapper_core/storage.py`: criação, migração e persistência.
- `network_mapper_core/analytics.py`: consultas e disponibilidade.
- `network_mapper_core/reporting.py`: relatórios baseados nos dados armazenados.
- `api_modules/database.py`: pool de conexões utilizado pela API.
- `API_REST.md`: endpoints, parâmetros, requests e respostas da API.
- `COMANDOS.md`: lista completa de comandos.
- `COMANDOS_PRINCIPAIS.md`: resumo operacional.
