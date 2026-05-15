# 🔍 Diagnóstico e Exportação — NetLab Educacional

## O Que Foi Melhorado?

### ✅ Nova Funcionalidade: Exportar Diagnóstico para TXT

Agora você pode salvar um relatório completo do diagnóstico do sistema em arquivo `.txt` para:
- **Análise detalhada** de problemas
- **Compartilhamento** com suporte técnico
- **Comparação** antes/depois ao resolver problemas
- **Documentação** do estado do sistema

---

## 🚀 Como Usar

### 1️⃣ Abrir o Diagnóstico

1. Clique no botão **"Diagnóstico"** na barra de ferramentas do NetLab
2. Aguarde alguns segundos enquanto o sistema verifica tudo

### 2️⃣ Revisar o Diagnóstico Visual

Na janela do diagnóstico você verá:
- **Barra de Saúde** (verde/amarelo/vermelho) indicando status geral
- **Checklist Rápido** com status de componentes essenciais
- **Seções Colapsáveis** com detalhes sobre:
  - Interface e Estatísticas de Rede
  - Conectividade e DNS
  - Sinal Wi-Fi (se aplicável)
  - Versões dos Componentes
  - Pendências Detectadas

### 3️⃣ Exportar para TXT

1. Clique no botão **"📋 Exportar TXT"** no rodapé
2. Escolha onde salvar o arquivo
3. O arquivo será criado com nome como: `NetLab-Diagnostico-20260515_143045.txt`

### 4️⃣ Abrir o TXT

Abra o arquivo em qualquer editor de texto (Notepad, VS Code, etc.)

---

## 📋 O Que o TXT Contém?

### Estrutura do Relatório

```
RELATÓRIO DE DIAGNÓSTICO — NETLAB EDUCACIONAL
└─ Timestamp (data/hora gerado)
└─ Sistema Operacional
└─ CHECKLIST RÁPIDO
   ├─ Privilégios de Administrador
   ├─ Versão do Npcap
   ├─ Versão do Scapy
   ├─ Teste de DNS
   └─ Teste de Gateway
└─ INTERFACE DE REDE
   ├─ Interface selecionada
   ├─ IP local
   ├─ Pacotes capturados
   ├─ Volume total
   ├─ Pacotes descartados (Drops)
   └─ Erros de recepção
└─ CONECTIVIDADE
   ├─ Gateway e latência
   └─ DNS com tempo de resposta
└─ WI-FI (se aplicável)
   ├─ SSID e força do sinal
   ├─ Canal e velocidade
   └─ Avisos sobre limitações
└─ VERSÕES DOS COMPONENTES
└─ RECOMENDAÇÕES
   ├─ Problemas encontrados com dicas
   ├─ Avisos com ações recomendadas
   └─ Status final
```

---

## ⚠️ Indicadores de Problema

### 🔴 Problemas Críticos (Vermelho)

| Problema | O que significa | Solução |
|----------|-----------------|---------|
| **Sem Privilégios Admin** | NetLab não pode criar regras de firewall | Execute NetLab com "Executar como Administrador" |
| **Npcap não instalado** | Não consegue capturar pacotes | Instale em https://npcap.com (marque "WinPcap API-compatible mode") |
| **Scapy não encontrado** | Biblioteca Python faltando | `pip install scapy` |
| **Gateway inacessível** | Sem conexão com roteador | Verifique conexão de rede |
| **DNS não funciona** | Sem Internet | Verifique conexão / DNS do roteador |

### 🟡 Avisos (Amarelo)

| Aviso | O que significa | Solução |
|-------|-----------------|---------|
| **Drops detectados** | Pacotes perdidos na captura | Aumentar buffer Npcap em `constantes.py`: `conf.bufsize = 1024 * 1024 * 32` |
| **Erros de recepção** | Problemas na placa de rede | Atualizar driver da placa de rede |
| **Sinal Wi-Fi fraco** | Conexão pode cair | Mover mais perto do roteador / usar cabeado |
| **DNS lento** | Resposta acima de 150ms | Trocar DNS (ex: 8.8.8.8 ou 1.1.1.1) |

### 🟢 OK (Verde)

Tudo está funcionando normalmente e o NetLab pode capturar tráfego.

---

## 📊 Exemplo de Saída

### ✓ Sistema Saudável

```
RECOMENDAÇÕES
================================================================================

✓ Nenhum problema detectado!

Seu sistema está pronto para:
  • Capturar tráfego de rede com sucesso
  • Analisar dispositivos na topologia
  • Acessar o servidor de outros dispositivos (inicie o servidor)
```

### ✗ Com Problemas

```
RECOMENDAÇÕES
================================================================================

PROBLEMAS ENCONTRADOS:
  ✗ Npcap não instalado
  ✗ Gateway inacessível

AVISOS:
  ⚠ Detectados 3300 pacotes descartados
  ⚠ Sinal Wi-Fi fraco

➜ Ações recomendadas:
  1. Instale Npcap em https://npcap.com
  2. Verifique conexão com roteador
  3. Abra "Configurações" → "Rede" e verifique status
```

---

## 🔧 Fluxo de Troubleshooting

### Problema: "Não está capturando pacotes"

1. **Abrir Diagnóstico**
2. **Exportar TXT**
3. **Procurar por**: 
   - ✗ Npcap não instalado? → Instalar
   - ✗ Drops > 0? → Aumentar buffer
   - ✗ Erro de recepção? → Atualizar driver

### Problema: "Servidor inacessível de outro PC"

1. **Abrir Diagnóstico**
2. **Verificar**: "Privilégios de Administrador: ✓"
3. **Iniciar Servidor** (aba Servidor → "Iniciar Servidor")
4. **Exportar TXT** → procurar por avisos de firewall

### Problema: "Latência Alta"

1. **Abrir Diagnóstico**
2. **Procurar por**: Latência do gateway
3. **Se > 100ms**: Problema de rede
4. **Se latência OK mas DNS lento**: Trocar DNS

---

## 💾 Compartilhando Diagnósticos

### Para Suporte Técnico

1. Clique "📋 Exportar TXT"
2. Salve o arquivo
3. **Renomeie** para deixar mais descritivo:
   ```
   NetLab-Diagnostico-SEUNOME-PROBLEMA.txt
   Exemplo: NetLab-Diagnostico-JoaoSilva-DropsPerdidos.txt
   ```
4. Envie por email/Discord/chat

### Para Comparação Antes/Depois

1. Faça diagnóstico **antes** de resolver problema
2. Salve com nome: `diagnostico-ANTES.txt`
3. Resolva o problema
4. Faça diagnóstico **depois**
5. Salve com nome: `diagnostico-DEPOIS.txt`
6. Compare as diferenças

---

## 🔄 Atualizar Diagnóstico

Clique no botão **"🔄 Atualizar"** para re-executar todos os testes sem fechar a janela.

Útil para:
- Verificar se problema foi resolvido
- Monitorar mudanças ao longo do tempo
- Testar conectividade após reiniciar roteador

---

## ❓ Dúvidas Frequentes

**P: Com que frequência devo fazer diagnóstico?**  
R: Uma vez ao abrir o NetLab é suficiente. Faça diagnóstico novamente se tiver problemas de captura.

**P: Posso ignorar avisos amarelos?**  
R: Depende. "Drops detectados" é importante em redes institucionais. "Sinal Wi-Fi fraco" pode ser tolerável se a captura funciona.

**P: O diagnóstico consome recursos?**  
R: Não, ele apenas lê configurações e faz pings rápidos. Não afeta a captura de tráfego.

**P: Arquivo TXT ficou muito grande?**  
R: Normal, ele contém todas as informações do sistema. Pode enviar via email normalmente.

---

## 📞 Suporte

Se o diagnóstico mostrar problemas que você não conseguir resolver:

1. **Exporte o TXT**
2. **Verifique**: "Problemas encontrados" e "Avisos"
3. **Consulte**: README.md principal para mais ajuda
4. **Compartilhe** o TXT com seu professor/suporte técnico

---

**Última atualização**: Maio 2026  
**Versão**: NetLab Educacional v5.0+

