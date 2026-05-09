<div align="center">

# NetLab Educacional

**Plataforma desktop para ensino de redes de computadores, análise de tráfego e segurança web em ambiente controlado.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt6-Interface%20Qt-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![Scapy](https://img.shields.io/badge/Scapy-Captura%20de%20Pacotes-FF6B35?style=for-the-badge)](https://scapy.net/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)

Trabalho de Conclusão de Curso - Curso Técnico em Informática  
Instituto Federal Farroupilha, Campus Uruguaiana

</div>

---

## Sumário

- [Resumo](#resumo)
- [Objetivos](#objetivos)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como executar](#como-executar)
- [Fluxo de uso recomendado](#fluxo-de-uso-recomendado)
- [Servidor de laboratório](#servidor-de-laboratório)
- [Protocolos analisados](#protocolos-analisados)
- [Persistência e dados gerados](#persistência-e-dados-gerados)
- [Diagnóstico e solução de problemas](#diagnóstico-e-solução-de-problemas)
- [Escopo ético e segurança](#escopo-ético-e-segurança)
- [Limitações conhecidas](#limitações-conhecidas)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Autor](#autor)

---

## Resumo

O **NetLab Educacional** é uma aplicação desktop desenvolvida em Python para apoiar aulas práticas de redes de computadores e segurança da informação. O sistema captura tráfego de rede em tempo real, organiza os pacotes em eventos compreensíveis, apresenta topologia interativa da rede local e gera explicações pedagógicas sobre protocolos, riscos e evidências técnicas.

A proposta é aproximar conceitos normalmente abstratos, como DNS, ARP, TCP, HTTP, TLS, dados sensíveis em texto claro, SQL Injection e XSS, de uma experiência observável. O projeto combina captura real de pacotes com um servidor HTTP vulnerável controlado, permitindo demonstrar o ciclo completo:

```text
ação do usuário -> tráfego de rede -> captura -> interpretação técnica -> explicação didática
```

O software foi construído para uso local, em laboratório ou sala de aula. O servidor vulnerável incluído é intencionalmente inseguro e deve ser usado apenas em redes controladas.

---

## Objetivos

### Objetivo geral

Fornecer uma ferramenta educacional para visualização, interpretação e experimentação prática de tráfego de rede, com foco na aprendizagem de protocolos e fundamentos de segurança.

### Objetivos específicos

- Capturar pacotes em tempo real usando Scapy e Npcap.
- Classificar eventos por protocolo e comportamento observado.
- Exibir topologia de rede com dispositivos, conexões e sub-redes.
- Traduzir dados técnicos em explicações didáticas.
- Evidenciar riscos como credenciais em texto claro, cookies via HTTP, SQL Injection e XSS.
- Oferecer um servidor web vulnerável em ambiente controlado para demonstração prática.
- Apoiar diagnóstico de interface, permissões, Npcap, DNS, gateway e qualidade da captura.

---

## Funcionalidades

### 1. Captura de pacotes em tempo real

- Captura em thread dedicada com `AsyncSniffer`, evitando bloqueio da interface gráfica.
- Filtro de captura para tráfego IPv4, ARP e ICMP.
- Seleção de interface de rede pela interface gráfica.
- Detecção de IP, máscara e CIDR da interface selecionada.
- Validação prévia de execução com privilégios de administrador.
- Reinício controlado da captura em caso de falha do socket.
- Filas com capacidade definida para evitar crescimento ilimitado de memória.

### 2. Analisador de pacotes

O módulo `analisador_pacotes.py` transforma pacotes brutos em eventos estruturados.

Funcionalidades implementadas:

- Parse de pacotes TCP, UDP, ICMP e ARP.
- Identificação de protocolos por porta e conteúdo.
- Deep Packet Inspection para HTTP.
- Extração de método HTTP, caminho, host, headers e corpo textual.
- Detecção de requisições POST e formulários.
- Contabilização de pacotes por protocolo.
- Contabilização de bytes por protocolo.
- Ranking de dispositivos por tráfego.
- Ranking de consultas DNS.
- Processamento em lote por thread de análise.

### 3. Topologia da rede

A aba **Topologia da Rede** representa dispositivos e conexões observadas.

Funcionalidades:

- Nós para dispositivos locais, gateway, computador atual e internet.
- Conexões registradas a partir de tráfego capturado.
- Zoom pelo scroll do mouse.
- Pan por arraste.
- Clique em nó para abrir painel de detalhes.
- Apelidos personalizados para dispositivos.
- Persistência de apelidos em `dados/aliases.json`.
- Identificação de fabricante por OUI/MAC usando a base do Wireshark via biblioteca `manuf`.
- Cache local da base OUI em `~/.cache/manuf/manuf`.
- Classificação aproximada de tipo de dispositivo.
- Diferenciação entre hosts confirmados por ARP e hosts apenas observados por tráfego.
- Detecção e agrupamento de sub-redes por CIDR.
- Remoção de nós inativos quando a capacidade visual é excedida.

### 4. Tráfego em tempo real

A aba **Tráfego em Tempo Real** apresenta métricas de banda e estatísticas agregadas.

Funcionalidades:

- Gráfico de KB/s ao longo do tempo.
- Curva bruta e curva suavizada por média móvel exponencial.
- Controle de suavização via slider.
- Pausa da visualização sem interromper a captura.
- Navegação pelo histórico.
- Retorno rápido ao modo ao vivo.
- Crosshair e tooltip com valor do ponto no gráfico.
- Cards de resumo com pacotes, dados transferidos e dispositivos ativos.
- Tabela de protocolos por volume.
- Tabela de dispositivos por tráfego.

### 5. Modo Análise

A aba **Modo Análise** converte eventos técnicos em explicações didáticas.

Cada evento pode apresentar:

- **Análise:** explicação em linguagem acessível sobre o que ocorreu.
- **Evidências:** campos técnicos reais extraídos do pacote.
- **Na prática:** significado operacional, riscos e comandos úteis.

Recursos:

- Filtro por protocolo.
- Busca textual por IP, domínio, protocolo ou conteúdo do evento.
- Badges com contagem de eventos por tipo.
- Histórico limitado para preservar desempenho da UI.
- Classificação de severidade em `INFO`, `AVISO` e `CRITICO`.
- Detecção de dados sensíveis em HTTP.
- Detecção de padrões compatíveis com SQL Injection e XSS.
- Exibição de headers HTTP e formulários decodificados quando disponíveis.
- Hexdump parcial para payloads relevantes.

### 6. Diagnóstico do sistema

O NetLab possui diagnóstico integrado pela interface e um script autônomo.

Verificações realizadas:

- Privilégios de administrador.
- Versão do Npcap.
- Versão do Scapy.
- Versão do PyQt6.
- Interface selecionada, IP local e estatísticas.
- Drops e erros de interface quando disponíveis.
- Gateway local e latência por ping.
- Resolução DNS e tempo de resposta.
- Sinal Wi-Fi via `netsh wlan show interfaces`.
- Estado das filas internas e eventos pendentes.
- Pontuação geral de saúde do ambiente.
- Exportação de relatório em `.txt`.

Também existe o script:

```powershell
python diagnostico.py
```

Ele testa interfaces disponíveis por alguns segundos e ajuda a identificar qual interface captura tráfego real.

### 7. Servidor de laboratório

O projeto inclui um servidor HTTP educacional em `painel_servidor.py`. Ele foi feito para demonstrar vulnerabilidades web em ambiente local.

Características:

- Servidor HTTP multithread.
- Banco SQLite em memória.
- Dados descartados ao parar o servidor.
- Painel Qt com status, endereço, métricas, requisições e alertas.
- Rotas vulneráveis intencionais para SQL Injection, XSS, IDOR, CSRF, força bruta e divulgação de dados.
- Formulários web com melhorias de usabilidade: mostrar/ocultar senha, rótulos acessíveis, validação visual e prevenção de clique duplo.

---

## Arquitetura

### Visão geral

```text
NetLab Educacional
|
|-- main.py
|   |-- inicializa QApplication
|   |-- carrega tema Qt
|   |-- abre JanelaPrincipal
|
|-- interface/
|   |-- janela_principal.py      -> orquestra captura, timers, menus e abas
|   |-- painel_topologia.py      -> visualização gráfica da rede
|   |-- painel_trafego.py        -> gráficos e tabelas de tráfego
|   |-- painel_eventos.py        -> modo análise e explicações
|
|-- analisador_pacotes.py        -> parse e classificação de pacotes
|-- motor_pedagogico.py          -> explicações por protocolo e risco
|-- netlab_core.py               -> métricas e buffer circular thread-safe
|-- painel_servidor.py           -> servidor HTTP vulnerável e painel Qt
|-- diagnostico.py               -> diagnóstico autônomo de interfaces
|
|-- utils/
|   |-- constantes.py            -> cores, portas e classificações
|   |-- rede.py                  -> IP local, CIDR, validação e formatação
|   |-- gerenciador_subredes.py  -> sub-redes e visibilidade
|   |-- identificador.py         -> fabricantes, OUI e aliases
|
|-- recursos/estilos/
|   |-- tema_escuro.qss          -> tema visual da aplicação
```

### Fluxo operacional da captura

```text
Npcap
  |
  v
Scapy / AsyncSniffer
  |
  v
_CapturadorPacotesThread
  |
  v
fila global de pacotes
  |
  v
ThreadAnalisador
  |
  v
eventos estruturados
  |
  +--> PainelTopologia
  +--> PainelTrafego
  +--> MotorPedagogico
             |
             v
       PainelEventos
```

### Fluxo pedagógico

```text
Pacote capturado
  |
  v
Extração de campos técnicos
  |
  v
Classificação por protocolo e risco
  |
  v
Geração de explicação didática
  |
  v
Exibição em Análise, Evidências e Na prática
```

---

## Requisitos

### Sistema operacional

- Windows 10 ou Windows 11.
- O código possui alguns caminhos auxiliares compatíveis com Linux, mas o fluxo principal foi projetado para Windows.

### Software

- Python 3.11 ou superior.
- Npcap instalado.
- PowerShell disponível.
- Acesso de administrador para captura de pacotes.

### Instalação recomendada do Npcap

Durante a instalação do Npcap, marque:

- **Install Npcap in WinPcap API-compatible Mode**

Sem essa opção, o Scapy pode não conseguir abrir as interfaces de rede corretamente.

### Dependências Python

O arquivo `requirements.txt` contém:

```text
PyQt6
scapy
pyqtgraph
cryptography
manuf
```

Finalidade das dependências:

| Pacote | Finalidade |
|---|---|
| `PyQt6` | Interface gráfica desktop |
| `scapy` | Captura, parsing e envio de pacotes |
| `pyqtgraph` | Gráficos de tráfego em tempo real |
| `cryptography` | Dependência disponível para recursos criptográficos |
| `manuf` | Identificação de fabricantes por OUI/MAC |

---

## Instalação

No PowerShell:

```powershell
git clone https://github.com/Yurigonpav/netlab-educacional.git
cd netlab-educacional
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Se a política de execução do PowerShell bloquear a ativação do ambiente virtual:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Depois, ative novamente:

```powershell
.\venv\Scripts\Activate.ps1
```

---

## Como executar

Execute o PowerShell como administrador e rode:

```powershell
.\venv\Scripts\Activate.ps1
python main.py
```

Também é possível testar interfaces sem abrir a interface principal:

```powershell
python diagnostico.py
```

---

## Fluxo de uso recomendado

1. Abra o PowerShell como administrador.
2. Ative o ambiente virtual.
3. Execute `python main.py`.
4. Escolha a interface de rede correta.
5. Clique em **Iniciar Captura**.
6. Gere tráfego simples, por exemplo abrindo uma página web.
7. Observe a aba **Topologia da Rede**.
8. Observe a aba **Tráfego em Tempo Real**.
9. Acesse a aba **Modo Análise** e selecione eventos.
10. Para aulas de segurança web, abra a aba **Servidor**, inicie o servidor local e acesse o endereço mostrado.

Fluxo didático completo:

```text
iniciar captura -> iniciar servidor -> executar ação no navegador -> observar evento -> discutir evidência
```

---

## Servidor de laboratório

### Finalidade

O servidor de laboratório foi construído para demonstrar vulnerabilidades web reais de forma controlada. Ele não deve ser exposto à Internet.

### Ciclo de vida

- O banco de dados é criado em memória ao iniciar o servidor.
- Usuários, produtos, pedidos e comentários são recriados a cada inicialização.
- Ao parar o servidor, todos os dados e sessões são descartados.

### Como iniciar

1. Abra a aba **Servidor**.
2. Escolha a porta, se necessário.
3. Clique em **Iniciar Servidor**.
4. Acesse o endereço exibido, por exemplo:

```text
http://192.168.0.10:8080/
```

### Usuários iniciais

| Usuário | Senha | Papel |
|---|---|---|
| `admin` | `123456` | `admin` |
| `alice` | `alice123` | `user` |
| `bob` | `bob456` | `user` |
| `carlos` | `senha123` | `user` |

### Rotas implementadas

| Rota | Método | Função | Comportamento didático |
|---|---:|---|---|
| `/` | GET | Página inicial | Navegação principal do laboratório |
| `/login` | GET/POST | Login | SQL Injection intencional e força bruta sem limite |
| `/register` | GET/POST | Cadastro | Inserção vulnerável por concatenação direta |
| `/logout` | GET | Encerrar sessão | Remove sessão em memória |
| `/produtos` | GET | Lista e detalhe de produtos | SQL Injection no parâmetro `id` |
| `/busca` | GET | Busca por nome | XSS refletido no termo pesquisado |
| `/comentarios` | GET/POST | Mural | XSS armazenado e ausência de CSRF |
| `/pedidos` | GET | Detalhe de pedido | IDOR por alteração do parâmetro `id` |
| `/usuarios` | GET | Tabela de usuários | Exposição de usuários e senhas |
| `/perfil` | GET | Perfil por nome | XSS refletido |
| `/api/dados` | GET | JSON de status | API sem autenticação |
| `/api/usuarios` | GET | JSON de usuários | Exposição de senhas em texto puro |

### Vulnerabilidades intencionais

| Classe | Onde aparece | Objetivo pedagógico |
|---|---|---|
| SQL Injection | `/login`, `/produtos`, `/register`, comentários | Mostrar risco de concatenação direta em SQL |
| XSS refletido | `/busca`, `/perfil` | Demonstrar injeção de HTML/JavaScript em resposta imediata |
| XSS armazenado | `/comentarios` | Demonstrar persistência de payload no banco |
| IDOR | `/pedidos?id=` | Demonstrar acesso indevido por troca de identificador |
| CSRF | Formulários sem token | Demonstrar ausência de validação de origem |
| Força bruta | `/login` | Demonstrar ausência de rate limit |
| Sessão previsível | Tokens sequenciais | Demonstrar risco de tokens adivinháveis |
| Divulgação de dados | `/usuarios`, `/api/usuarios` | Demonstrar exposição indevida de credenciais |

### Heurísticas de usabilidade aplicadas

Os formulários do servidor web incluem recursos de interação voltados a reduzir erro do usuário:

- Botão **Mostrar/Ocultar** senha.
- Campos com `label` associado.
- Uso de `autocomplete` apropriado.
- Validação visual em tempo real no cadastro.
- Mensagens com `aria-live` para leitores de tela.
- Foco visível por teclado.
- Link para pular ao conteúdo principal.
- Prevenção de envio duplicado por mudança de estado do botão.

---

## Protocolos analisados

| Protocolo | Tratamento no NetLab | Evidências extraídas |
|---|---|---|
| HTTP | Análise completa por DPI | Método, host, caminho, headers, corpo, formulários e campos sensíveis |
| HTTPS | Classificação e explicação de tráfego cifrado | IPs, portas e contexto TLS quando disponível |
| DNS | Identificação de consulta | Domínio consultado |
| ARP | Descoberta local | IP/MAC de origem, IP de destino e operação request/reply |
| ICMP | Diagnóstico de conectividade | Origem, destino, TTL e contexto de ping |
| DHCP | Configuração dinâmica | Portas, tipo DHCP quando disponível e identificador de transação |
| TCP SYN | Nova conexão | IPs, portas e início de handshake |
| TCP FIN | Encerramento ordenado | Contexto de finalização da conexão |
| TCP RST | Encerramento abrupto | Indício de reset ou recusa |
| SSH | Acesso remoto cifrado | IPs, portas e risco operacional |
| FTP | Transferência insegura | Potencial exposição de credenciais |
| SMB | Compartilhamento de arquivos | Risco operacional em redes locais |
| RDP | Desktop remoto | Exposição de serviço remoto |

---

## Persistência e dados gerados

O NetLab evita persistência desnecessária de dados capturados. A maior parte dos dados de captura fica apenas em memória durante a sessão.

Persistências existentes:

| Dado | Local | Finalidade |
|---|---|---|
| Apelidos de dispositivos | `dados/aliases.json` | Manter nomes personalizados de hosts |
| Cache OUI do Wireshark | `~/.cache/manuf/manuf` | Acelerar identificação de fabricantes |
| Banco do servidor vulnerável | Memória RAM | Recriado ao iniciar e destruído ao parar |

Dados em memória:

- Pacotes e eventos recentes.
- Métricas agregadas.
- Sessões do servidor de laboratório.
- Comentários do servidor de laboratório.
- Usuários cadastrados durante a execução do servidor.

---

## Diagnóstico e solução de problemas

### Nenhum pacote é capturado

Possíveis causas:

- Aplicação não foi executada como administrador.
- Npcap não está instalado.
- Npcap foi instalado sem modo compatível com WinPcap.
- Interface errada foi selecionada.
- Interface sem tráfego no momento do teste.

Procedimento recomendado:

```powershell
python diagnostico.py
```

Depois selecione no NetLab a interface que capturou pacotes no teste.

### A topologia está vazia

Possíveis causas:

- A captura acabou de iniciar e ainda não há tráfego suficiente.
- O Windows bloqueia captura promíscua em muitos adaptadores Wi-Fi.
- A rede não respondeu ao ARP sweep.

Soluções:

- Aguarde de 5 a 10 segundos.
- Gere tráfego abrindo uma página web.
- Use a tabela ARP do sistema como fallback.
- Para atividades com turma em Wi-Fi, considere usar o Hotspot do Windows.

### O servidor de laboratório não abre no navegador

Verifique:

- Se o botão da aba Servidor mostra **Parar Servidor**.
- Se a porta escolhida não está em uso por outro processo.
- Se o endereço acessado corresponde ao IP exibido no painel.
- Se o firewall permite conexões locais nessa porta.
- Se o dispositivo cliente está na mesma rede.

### O gráfico não atualiza

Verifique:

- Se a captura está ativa.
- Se há tráfego real na interface.
- Se o painel não está pausado.
- Se a interface selecionada é a interface conectada à rede.

---

## Escopo ético e segurança

O NetLab Educacional foi desenvolvido para ensino, demonstração e pesquisa em ambiente autorizado.

Uso permitido:

- Laboratórios escolares.
- Redes próprias.
- Ambientes de teste.
- Demonstrações com consentimento dos participantes.
- Estudos de protocolos e segurança defensiva.

Uso não permitido:

- Capturar tráfego de terceiros sem autorização.
- Expor o servidor vulnerável na Internet.
- Usar as técnicas demonstradas contra sistemas reais sem permissão.
- Coletar, armazenar ou divulgar credenciais reais.

O servidor vulnerável implementa falhas reais por finalidade didática. Ele deve permanecer restrito à rede local de teste.

---

## Limitações conhecidas

- O fluxo principal é voltado para Windows 10/11.
- Captura de tráfego de terceiros em Wi-Fi é limitada por drivers e pelo sistema operacional.
- O conteúdo de HTTPS não é descriptografado; apenas metadados observáveis podem ser analisados.
- O analisador prioriza IPv4.
- A identificação de fabricante depende da qualidade da base OUI.
- Eventos de alto volume podem ser agregados ou descartados para preservar desempenho.
- O servidor de laboratório não implementa controles de segurança reais por projeto.

---

## Estrutura do projeto

```text
NetLab Educacional/
|-- main.py
|-- analisador_pacotes.py
|-- motor_pedagogico.py
|-- netlab_core.py
|-- painel_servidor.py
|-- diagnostico.py
|-- requirements.txt
|-- README.md
|
|-- interface/
|   |-- __init__.py
|   |-- janela_principal.py
|   |-- painel_eventos.py
|   |-- painel_topologia.py
|   |-- painel_trafego.py
|
|-- utils/
|   |-- __init__.py
|   |-- constantes.py
|   |-- gerenciador_subredes.py
|   |-- identificador.py
|   |-- rede.py
|
|-- recursos/
|   |-- estilos/
|       |-- tema_escuro.qss
|
|-- dados/
|   |-- aliases.json        # criado quando houver apelidos persistidos
```

---

## Critérios de verificação técnica

Para verificar se o projeto está em estado executável:

```powershell
.\venv\Scripts\python.exe -m compileall -q . -x "venv|__pycache__|\.git"
```

Para verificar o diagnóstico de captura:

```powershell
.\venv\Scripts\python.exe diagnostico.py
```

Para iniciar a aplicação:

```powershell
.\venv\Scripts\python.exe main.py
```

---

## Autor

**Yuri Gonçalves Pavão**

Curso Técnico em Informática  
Instituto Federal Farroupilha, Campus Uruguaiana

- GitHub: [@Yurigonpav](https://github.com/Yurigonpav)
- Instagram: [@yuri_g0n](https://instagram.com/yuri_g0n)

---

<div align="center">

**Desenvolvido com finalidade educacional. Use apenas em ambientes autorizados.**

</div>
