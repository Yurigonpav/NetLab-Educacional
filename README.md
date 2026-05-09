<div align="center">

# NetLab Educacional — v5.0

**Plataforma desktop para ensino de redes de computadores, análise de tráfego em tempo real e segurança web em ambiente controlado.**

[![Download](https://img.shields.io/badge/Download-Instalador%20Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://yurigonpav.github.io/NetLab-Site/#download)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt6-Interface%20Qt-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![Scapy](https://img.shields.io/badge/Scapy-Captura%20de%20Pacotes-FF6B35?style=for-the-badge)](https://scapy.net/)

**Trabalho de Conclusão de Curso — Curso Técnico em Informática**
**Instituto Federal Farroupilha, Campus Avançado Uruguaiana**

</div>

---

> [!TIP]
> **Procurando o instalador pronto?** Se você deseja apenas usar o software sem mexer no código, baixe a versão estável em nossa [Página Oficial](https://yurigonpav.github.io/NetLab-Site/#download). Este repositório é destinado ao desenvolvimento e estudo do código-fonte.

---

## Sumário

- [Sobre o Projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Requisitos do Sistema](#requisitos-do-sistema)
- [Instalação](#instalação)
- [Executável (Build sem Python)](#executável-build-sem-python)
- [Como Executar](#como-executar)
- [Fluxo de Uso Recomendado](#fluxo-de-uso-recomendado)
- [Protocolos Analisados](#protocolos-analisados)
- [Servidor de Laboratório](#servidor-de-laboratório)
- [Diagnóstico do Sistema](#diagnóstico-do-sistema)
- [Persistência e Dados Gerados](#persistência-e-dados-gerados)
- [Limitações Conhecidas](#limitações-conhecidas)
- [Escopo Ético e Segurança](#escopo-ético-e-segurança)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Autor](#autor)

---

## Sobre o Projeto

O **NetLab Educacional** é uma aplicação desktop desenvolvida em Python para apoiar aulas práticas de redes de computadores e segurança da informação no ensino técnico. O sistema captura pacotes de rede em tempo real, organiza o tráfego em eventos compreensíveis, exibe uma topologia interativa da rede local e gera automaticamente explicações pedagógicas sobre protocolos, riscos e evidências técnicas.

A proposta central é aproximar conceitos normalmente abstratos — como handshake TCP, envenenamento ARP, credenciais em texto claro, SQL Injection e XSS — de uma experiência **diretamente observável** em sala de aula. O projeto combina captura real de pacotes com um servidor HTTP intencionalmente vulnerável, permitindo demonstrar o ciclo completo:

```
ação do usuário → tráfego de rede → captura → interpretação técnica → explicação didática
```

> O software foi construído para uso local, em laboratório ou sala de aula. O servidor vulnerável incluído é intencionalmente inseguro e deve ser usado **exclusivamente** em redes controladas.

---

## Funcionalidades

### Captura de Pacotes em Tempo Real

- Captura em thread dedicada com `AsyncSniffer` do Scapy, sem bloquear a interface gráfica.
- Filtro de captura cirúrgico: TCP (flags de controle), UDP, DNS, DHCP, ICMP e ARP.
- Limite de taxa configurável: **800 pacotes/s** em Ethernet, **400 pacotes/s** em Wi-Fi.
- Fila de entrada de até **20.000 pacotes** e fila de saída de até **5.000 eventos**.
- Seleção de interface pela interface gráfica, com detecção automática de IP e CIDR.
- Reinício controlado do sniffer em caso de falha do socket.

### Topologia da Rede

A aba **Topologia** exibe um mapa interativo e animado dos dispositivos detectados.

- Nós com tamanho proporcional ao volume de tráfego do host.
- Zoom com scroll do mouse e pan por arraste.
- **Clique** em um nó abre painel lateral com IP, MAC, fabricante, tipo e portas.
- **Duplo clique** permite definir um apelido personalizado persistido em JSON.
- Identificação de fabricante por OUI via biblioteca `manuf` (base Wireshark), com cache local de 30 dias e atualização automática em background.
- Diferenciação entre hosts **CONFIRMADOS** (vistos via ARP) e **OBSERVADOS** (inferidos por tráfego).
- Limite visual de **50 dispositivos**: nós menos ativos são removidos automaticamente ao atingir a capacidade.
- Timeout de inatividade de **30 minutos** para hosts não confirmados.
- Detecção e agrupamento por sub-rede com contornos coloridos (total / parcial / inferida).
- Importação da tabela ARP do Windows a cada 60 s.
- ARP sweep na rede local logo após iniciar a captura.

### Tráfego em Tempo Real

A aba **Tráfego** combina visualização ao vivo com navegação pelo histórico da sessão.

- Buffer histórico com até **7.200 amostras** (~2 horas a 1 amostra/segundo).
- Suavização por **Média Móvel Exponencial (EMA)** com fator α ajustável de 0,05 a 0,50 via slider.
- Duas curvas sobrepostas: bruta (cinza-azul, fina) e EMA (azul brilhante, com preenchimento).
- **Navegação temporal**: botões `|<`, `<30s`, `<10s`, `|| Pausar`, `10s>`, `30s>`, `>> Ao Vivo`.
- Ao pausar ou navegar, a captura continua em segundo plano sem interrupção.
- **Crosshair** e tooltip com valor EMA exato ao passar o mouse sobre o gráfico.
- Transição suave do teto do eixo Y sem saltos bruscos.
- Cards de resumo: pacotes capturados, dados transmitidos e dispositivos ativos.
- Tabela de protocolos por volume e top dispositivos por tráfego.

### Modo Análise

A aba **Modo Análise** converte eventos técnicos em explicações didáticas com três profundidades.

Cada evento exibe três abas:

| Aba | Conteúdo |
|---|---|
| **ANÁLISE** | O que aconteceu, explicação acessível, seção "Como Funciona" com dados reais do pacote |
| **EVIDÊNCIAS** | Campos técnicos brutos: IP, porta, MAC, tamanho, headers HTTP, formulários decodificados |
| **NA PRÁTICA** | Significado operacional, riscos reais, comandos de diagnóstico, vetores de ataque |

Recursos do painel:

- Histórico de até **1.500 eventos** por sessão.
- Filtro por protocolo via badges com contagem ao vivo.
- Busca textual por IP, domínio ou protocolo com debounce de 100 ms.
- Três níveis de alerta: **INFO**, **AVISO** e **CRÍTICO**.
- Detecção automática de **dados sensíveis** em requisições HTTP (mais de 50 nomes de campo, incluindo `password`, `token`, `api_key`, `cpf`, `credit_card`).
- Detecção de padrões de **SQL Injection** e **XSS** no tráfego capturado.
- Exibição de headers HTTP e formulários POST decodificados.
- **Hexdump** parcial dos primeiros 1.024 bytes do payload para eventos relevantes.

### Motor Pedagógico

O `motor_pedagogico.py` gera explicações contextualizadas para cada protocolo usando os dados reais do pacote capturado (IP, porta, domínio, tamanho, TTL).

- Suporte a **13 protocolos** com análise individualizada: HTTP, HTTPS, DNS, TCP SYN, TCP FIN, TCP RST, ICMP, ARP, DHCP, SSH, FTP, SMB, RDP, Novo Dispositivo.
- Análise completa de DPI para HTTP: método, caminho, versão, headers, cookies e corpo.
- Estimativa de sistema operacional pelo valor de **TTL** do pacote.
- Identificação de fabricante pelo OUI integrada às explicações.
- Processamento em pool de threads (`QThreadPool`, máx. 4 workers) para não travar a interface.

### Diagnóstico do Sistema

O painel de diagnóstico (botão **Diagnóstico** na barra de ferramentas) verifica:

- Privilégios de administrador.
- Versão do **Npcap** (lida do registro do Windows).
- Versão do **Scapy** e do **PyQt6**.
- Ping real ao **gateway local** com latência média e percentual de perda.
- Resolução **DNS** de `google.com` com tempo de resposta em ms.
- **Sinal Wi-Fi** via `netsh wlan show interfaces`: SSID, BSSID, sinal em %, canal e velocidade.
- **Drops e erros** de interface de rede via `psutil`.
- **Pontuação de saúde** de 0 a 10 com barra de progresso colorida.
- Seções colapsáveis para organização.
- Botão **Atualizar** para re-executar todos os testes.

### Servidor de Laboratório

Veja a [seção dedicada](#servidor-de-laboratório) para detalhes completos.

---

## Arquitetura

```
NetLab Educacional
│
├── main.py                      ← Inicializa QApplication e abre a janela principal
│
├── interface/
│   ├── janela_principal.py      ← Orquestra captura, timers, menus e abas
│   ├── painel_topologia.py      ← Topologia interativa com zoom, pan e detalhes
│   ├── painel_trafego.py        ← Gráfico EMA + navegação temporal + tabelas
│   └── painel_eventos.py        ← Modo análise, filtros e explicações didáticas
│
├── analisador_pacotes.py        ← Parse e classificação de pacotes em thread dedicada
├── motor_pedagogico.py          ← Gerador de explicações por protocolo e risco
├── netlab_core.py               ← Buffer circular de métricas thread-safe
├── painel_servidor.py           ← Servidor HTTP vulnerável + painel Qt
├── diagnostico.py               ← Diagnóstico autônomo de interfaces (standalone)
│
├── utils/
│   ├── constantes.py            ← Cores, portas e classificações compartilhadas
│   ├── rede.py                  ← IP local, CIDR, validação e formatação
│   ├── gerenciador_subredes.py  ← Sub-redes, visibilidade e rotas
│   └── identificador.py        ← Fabricantes OUI, aliases e tipos de dispositivo
│
└── recursos/estilos/
    └── tema_escuro.qss          ← Tema visual da aplicação (Qt Style Sheet)
```

### Fluxo de Captura

```
Npcap (driver)
    │
    ▼
Scapy / AsyncSniffer
    │
    ▼
_CapturadorPacotesThread  ←── limite: 800 pps (Ethernet) / 400 pps (Wi-Fi)
    │
    ▼
fila_pacotes_global (deque maxlen=20.000)
    │
    ▼
ThreadAnalisador  ←── lotes de 200 pacotes
    │
    ▼
eventos estruturados
    │
    ├──▶ PainelTopologia    (registro de hosts e conexões)
    ├──▶ PainelTrafego      (métricas de banda e protocolos)
    └──▶ MotorPedagógico    (pool de workers Qt)
                │
                ▼
          PainelEventos   (até 1.500 eventos por sessão)
```

---

## Requisitos do Sistema

### Sistema Operacional

- **Windows 10** ou **Windows 11** (64-bit).

> O código possui caminhos auxiliares para Linux, mas o fluxo principal foi projetado e testado para Windows.

### Software Obrigatório

| Componente | Versão mínima | Como verificar |
|---|---|---|
| Python | 3.11+ | `python --version` |
| Npcap | 1.70+ | [Baixar no site oficial](https://npcap.com/) |
| PowerShell | 5.1+ | Disponível por padrão no Windows 10/11 |
| Execução como Admin | — | Botão direito → "Executar como administrador" |

> **Dica:** O instalador oficial do NetLab já oferece a opção de baixar e configurar o Npcap automaticamente para você. Se estiver instalando manualmente, certifique-se de marcar a opção **"Install Npcap in WinPcap API-compatible Mode"**.

### Dependências Python

```
PyQt6
scapy
pyqtgraph
cryptography
manuf
```

| Pacote | Função |
|---|---|
| `PyQt6` | Interface gráfica desktop |
| `scapy` | Captura, parsing e envio de pacotes |
| `pyqtgraph` | Gráfico de tráfego em tempo real |
| `cryptography` | Recursos criptográficos disponíveis ao projeto |
| `manuf` | Identificação de fabricantes por OUI/MAC (base Wireshark) |

---

## Instalação

### Configuração do ambiente de desenvolvimento

Abra o PowerShell **como Administrador** e execute:

```powershell
git clone https://github.com/Yurigonpav/netlab-educacional.git
cd netlab-educacional

python -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

> Se a política de execução do PowerShell bloquear a ativação do ambiente virtual:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
> ```
> Depois ative novamente com `.\venv\Scripts\Activate.ps1`.

---

## Executável (Build sem Python)

O NetLab pode ser empacotado em um único arquivo `.exe` com **PyInstaller**, permitindo distribuição sem instalação de Python ou dependências.

### Pré-requisito

```powershell
pip install pyinstaller
```

### Gerando o executável

```powershell
# Ative o ambiente virtual primeiro
.\venv\Scripts\Activate.ps1

# Build com o spec oficial do projeto
pyinstaller NetLab.spec
```

O executável será gerado em `dist\NetLab Educacional.exe`.

### O que o spec inclui

O arquivo `NetLab.spec` configura o PyInstaller para:

- Incluir automaticamente a pasta `recursos/` (tema visual e assets).
- Esconder as importações necessárias do Scapy e PyQt6.
- Gerar um executável de janela sem console (`console=False`) com o nome **NetLab Educacional**.
- Comprimir com UPX para reduzir o tamanho final.

### Executando o .exe gerado

O executável deve ser iniciado **como Administrador**, pois a captura de pacotes exige privilégios elevados:

```
Botão direito em dist\NetLab Educacional.exe → Executar como administrador
```

> O Npcap precisa estar instalado na máquina de destino mesmo ao usar o executável.

---

## Como Executar

### No ambiente de desenvolvimento

```powershell
# Abra o PowerShell como Administrador
.\venv\Scripts\Activate.ps1
python main.py
```

### Diagnóstico autônomo de interfaces

Para identificar qual interface captura tráfego real antes de abrir o NetLab:

```powershell
.\venv\Scripts\Activate.ps1
python diagnostico.py
```

O script testa cada interface por 4 segundos e exibe quantos pacotes cada uma capturou. Copie o nome exato da interface ativa e selecione-a no combo do NetLab.

---

## Fluxo de Uso Recomendado

```
1. Abrir PowerShell como Administrador
2. Ativar venv e executar python main.py
3. Selecionar a interface de rede correta no combo
4. Clicar em "Iniciar Captura"
5. Abrir o navegador e acessar qualquer site
6. Observar dispositivos aparecendo na aba Topologia
7. Observar eventos na aba Modo Análise
8. (Opcional) Abrir a aba Servidor → Iniciar Servidor → acessar pelo navegador
9. Executar ataques didáticos → observar o NetLab detectar e explicar cada um
```

### Demonstração completa com a turma (Wi-Fi)

Ative o **Hotspot Móvel** do Windows no computador com o NetLab (Configurações → Rede → Hotspot Móvel). Conecte os dispositivos dos alunos nesse hotspot. O adaptador em modo AP captura todo o tráfego que passa por ele, tornando visível o tráfego de todos os dispositivos conectados.

```
Alunos conectam ao hotspot
    │
    ▼
NetLab captura o tráfego de todos
    │
    ▼
Topologia exibe os dispositivos da turma
    │
    ▼
Modo Análise explica cada protocolo em tempo real
```

### Ciclo didático completo com o servidor vulnerável

```
Iniciar captura → Iniciar servidor → Executar ataque no navegador
    → NetLab captura o tráfego HTTP
    → Motor pedagógico gera explicação
    → Painel de Alertas do Servidor registra o ataque
    → Discussão com a turma
```

---

## Protocolos Analisados

| Protocolo | Tratamento | Evidências extraídas |
|---|---|---|
| **HTTP** | DPI completa | Método, host, caminho, headers, cookies, corpo, formulários, campos sensíveis, SQL Injection, XSS |
| **HTTPS** | Classificação + explicação TLS | IPs, porta, SNI (Server Name Indication) do ClientHello |
| **DNS** | Identificação de consulta | Domínio consultado, servidor DNS, tamanho |
| **ARP** | Descoberta local | MAC de origem, operação (request/reply), fabricante OUI |
| **ICMP** | Diagnóstico | Origem, destino, TTL, estimativa de SO, saltos percorridos |
| **DHCP** | Configuração dinâmica | Tipo DHCP (discover/offer/request/ack/nak), XID |
| **TCP SYN** | Nova conexão | IPs, portas, início de handshake, TTL, estimativa de SO |
| **TCP FIN** | Encerramento ordenado | Contexto de finalização da sessão |
| **TCP RST** | Reset abrupto | Porta recusada ou firewall |
| **SSH** | Acesso remoto cifrado | IPs, portas, risco operacional |
| **FTP** | Transferência insegura | Exposição de credenciais e arquivos |
| **SMB** | Compartilhamento de arquivos | Versão, risco de relay NTLM |
| **RDP** | Desktop remoto | Exposição de serviço remoto, risco de brute force |

---

## Servidor de Laboratório

O NetLab inclui um servidor HTTP educacional em `painel_servidor.py`, projetado para demonstrar vulnerabilidades web reais em ambiente controlado.

### Características técnicas

- Servidor HTTP multithread (`ThreadingMixIn + HTTPServer`).
- Banco de dados **SQLite exclusivamente em memória** — todos os dados são destruídos ao parar o servidor.
- Nenhum acesso ao sistema operacional (sem `subprocess`, `os.system`, `eval` ou `exec`).
- Nenhuma persistência em disco de dados de usuários ou sessões.

### Iniciando o servidor

1. Acesse a aba **Servidor**.
2. Ajuste a porta (padrão: `8080`) com os botões +/−.
3. Clique em **Iniciar Servidor**.
4. Acesse o endereço exibido de qualquer dispositivo na mesma rede:

```
http://<ip-do-computador>:8080/
```

### Credenciais padrão

| Usuário | Senha | Papel |
|---|---|---|
| `admin` | `123456` | admin |
| `alice` | `alice123` | user |
| `bob` | `bob456` | user |
| `carlos` | `senha123` | user |

### Rotas disponíveis

| Rota | Método | Vulnerabilidade demonstrada |
|---|---|---|
| `/` | GET | Página inicial — estado da sessão ativa |
| `/login` | GET / POST | SQL Injection (concatenação direta) + força bruta sem limite de tentativas |
| `/register` | GET / POST | SQL Injection no INSERT + tokens de sessão previsíveis (sequenciais) |
| `/logout` | GET | Encerramento de sessão |
| `/produtos` | GET | SQL Injection no parâmetro `id` (UNION SELECT funcional) |
| `/busca` | GET | XSS Refletido no parâmetro `q` (sem escape HTML) |
| `/comentarios` | GET / POST | XSS Armazenado + CSRF (sem token de proteção) |
| `/pedidos` | GET | IDOR — acessa pedido de qualquer usuário por troca do parâmetro `id` |
| `/usuarios` | GET | Exposição de todos os usuários e senhas em texto puro sem autenticação |
| `/perfil` | GET | XSS Refletido no parâmetro `nome` |
| `/api/dados` | GET | API pública sem autenticação |
| `/api/usuarios` | GET | JSON com todos os usuários e senhas sem autenticação |

### Vulnerabilidades implementadas

| Classe | Onde aparece | Objetivo pedagógico |
|---|---|---|
| **SQL Injection** | `/login`, `/produtos`, `/register`, `/comentarios` | Risco de concatenação direta de strings em queries SQL |
| **XSS Refletido** | `/busca`, `/perfil` | Injeção de HTML/JavaScript refletido imediatamente na resposta |
| **XSS Armazenado** | `/comentarios` | Payload persistido no banco e executado em todo acesso à página |
| **IDOR** | `/pedidos?id=` | Acesso indevido a recursos de outros usuários por troca de identificador |
| **CSRF** | Todos os formulários | Ausência de token de validação de origem da requisição |
| **Força Bruta** | `/login` | Ausência de rate limiting ou bloqueio de conta |
| **Sessão Previsível** | Tokens sequenciais | Tokens de sessão adivinháveis (`token1`, `token2`...) |
| **Divulgação de Dados** | `/usuarios`, `/api/usuarios` | Exposição de credenciais sem qualquer controle de acesso |

### Heurísticas de usabilidade nos formulários

Os formulários do servidor incluem melhorias de UX para demonstração mais realista:

- Botão **Mostrar/Ocultar** senha com `aria-pressed` e foco automático.
- Campos `<label>` associados a cada `<input>`.
- Validação em tempo real no cadastro (senha apenas números, confirmação de senha).
- `aria-live` para feedback acessível a leitores de tela.
- Foco visível por teclado (`focus-visible`).
- Link "pular ao conteúdo principal" para acessibilidade.
- Prevenção de envio duplicado por mudança de estado e `aria-busy` no botão.

### Painel de controle do servidor

A aba Servidor exibe em tempo real:

- **Tabela de requisições**: hora, IP do cliente, método, endpoint, tamanho, tempo de resposta.
- **Log de alertas**: cada ataque detectado (SQLi, XSS, IDOR, CSRF) com timestamp e payload.
- **Métricas**: total de requisições, dados transmitidos, clientes únicos e barra de carga.

---

## Diagnóstico do Sistema

Acesse via botão **Diagnóstico** na barra de ferramentas.

### Verificações realizadas

| Seção | O que verifica |
|---|---|
| **Checklist Rápido** | Admin, Npcap, Scapy, DNS, gateway em uma visão consolidada |
| **Interface e Estatísticas** | Interface selecionada, IP local, pacotes, drops e erros via `psutil` |
| **Sinal Wi-Fi** | SSID, BSSID, sinal em %, canal, velocidade de recepção |
| **Versões dos Componentes** | Python, Npcap, Scapy, PyQt6 e versão do Windows |
| **Conectividade de Rede** | Ping real ao gateway (latência e % perda) + DNS com tempo de resposta |
| **Pendências Detectadas** | Lista automática de problemas e avisos encontrados |

### Pontuação de saúde

| Pontuação | Status |
|---|---|
| 8–10 | Sistema saudável |
| 5–7 | Atenção necessária |
| 0–4 | Problemas encontrados |

### Script standalone

Para diagnóstico sem abrir a interface principal:

```powershell
python diagnostico.py
```

Testa cada interface por **4 segundos** e mostra quantos pacotes foram capturados em cada uma. Útil para identificar a interface correta em um ambiente desconhecido.

---

## Persistência e Dados Gerados

O NetLab minimiza intencionalmente a persistência de dados capturados. A maioria das informações existe apenas em memória durante a sessão.

| Dado | Local | Finalidade |
|---|---|---|
| Apelidos de dispositivos | `dados/aliases.json` | Manter nomes personalizados de hosts entre sessões |
| Cache OUI do Wireshark | `~/.cache/manuf/manuf` | Acelerar a identificação de fabricantes por MAC |

**Dados que existem apenas em memória (perdidos ao fechar):**

- Pacotes e eventos capturados.
- Métricas agregadas por protocolo e dispositivo.
- Sessões de usuário do servidor de laboratório.
- Usuários, produtos, pedidos e comentários do servidor de laboratório.
- Banco de dados SQLite do servidor (destruído ao parar o servidor).

---

## Limitações Conhecidas

- Foco principal em **Windows 10/11**; Linux não é um alvo documentado de suporte estável.
- Captura de tráfego de **terceiros em Wi-Fi** é limitada pelos drivers do sistema operacional no Windows. Recomendado: usar o Hotspot do Windows.
- Conteúdo de **HTTPS não é decriptado**; apenas metadados observáveis (IPs, porta, SNI) são analisados.
- O analisador prioriza **IPv4**.
- A topologia visual suporta até **50 dispositivos simultâneos** para preservar o desempenho.
- A identificação de fabricante depende da qualidade e atualização da base OUI local.
- Em redes com volume muito alto, eventos podem ser agregados ou limitados pela fila interna.

---

## Escopo Ético e Segurança

O NetLab Educacional foi desenvolvido para **ensino, demonstração e pesquisa em ambientes autorizados**.

**Uso permitido:**

- Laboratórios e salas de aula.
- Redes próprias e de teste.
- Demonstrações com consentimento dos participantes.
- Estudos de protocolos e segurança defensiva.

**Uso não permitido:**

- Capturar tráfego de terceiros sem autorização.
- Expor o servidor vulnerável na internet.
- Aplicar as técnicas demonstradas contra sistemas reais sem permissão explícita.
- Coletar, armazenar ou divulgar credenciais reais de terceiros.

> O servidor vulnerável implementa falhas reais com finalidade didática. Mantenha-o sempre restrito à rede local de teste.

---

## Estrutura do Projeto

```
netlab-educacional/
├── main.py                          ← Ponto de entrada da aplicação
├── analisador_pacotes.py            ← Parser de pacotes com thread dedicada
├── motor_pedagogico.py              ← Gerador de explicações didáticas
├── netlab_core.py                   ← Métricas e buffer circular thread-safe
├── painel_servidor.py               ← Servidor HTTP vulnerável + painel Qt
├── diagnostico.py                   ← Diagnóstico autônomo de interfaces
├── requirements.txt                 ← Dependências Python
├── NetLab.spec                      ← Configuração PyInstaller (build .exe)
├── README.md
│
├── interface/
│   ├── __init__.py
│   ├── janela_principal.py          ← Janela principal e orquestração geral
│   ├── painel_eventos.py            ← Modo análise com filtros e explicações
│   ├── painel_topologia.py          ← Topologia interativa da rede
│   └── painel_trafego.py            ← Gráfico EMA e tabelas de tráfego
│
├── utils/
│   ├── __init__.py
│   ├── caminhos.py                  ← Resolução de paths (compatível com PyInstaller)
│   ├── constantes.py                ← Cores, portas e classificações
│   ├── gerenciador_subredes.py      ← Descoberta e classificação de sub-redes
│   ├── identificador.py             ← Fabricantes OUI, aliases e tipos de dispositivo
│   └── rede.py                      ← IP local, CIDR, validação e formatação
│
├── recursos/
│   └── estilos/
│       └── tema_escuro.qss          ← Tema visual Qt (dark theme)
│
└── dados/
    └── aliases.json                 ← Criado automaticamente ao salvar apelidos
```

---

## Verificação de Integridade

Para verificar se o projeto está em estado executável sem abrir a interface:

```powershell
# Compilar todos os módulos (detecta erros de sintaxe)
.\venv\Scripts\python.exe -m compileall -q . -x "venv|__pycache__|\.git"

# Testar interfaces disponíveis
.\venv\Scripts\python.exe diagnostico.py

# Iniciar a aplicação
.\venv\Scripts\python.exe main.py
```

---

## Autor

**Yuri Gonçalves Pavão**

Curso Técnico em Informática Integrado ao Ensino Médio
Instituto Federal Farroupilha — Campus Avançado Uruguaiana

Orientador: Prof. João Carlos
Co-orientador: Prof. Michel Michelon

- GitHub: [@Yurigonpav](https://github.com/Yurigonpav)
- Instagram: [@yuri_g0n](https://instagram.com/yuri_g0n)

---

<div align="center">

**Desenvolvido com finalidade educacional. Use exclusivamente em ambientes autorizados.**

</div>
