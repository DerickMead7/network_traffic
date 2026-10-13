# SOC Pipeline Lab: Suricata, ThreatFox & Zabbix

Este repositório contém a implementação de um laboratório de Security Operations Center (SOC) focado em monitoramento de rede, ingestão de Cyber Threat Intelligence (CTI) e geração de alertas em tempo real.

## Arquitetura do Projeto

O pipeline de detecção atua ponta a ponta e é composto por quatro camadas principais:

1. **Suricata (Network IDS):** Monitoramento de tráfego de rede em tempo real e geração de eventos estruturados (eve.json).
2. **ThreatFox API (Abuse.ch):** Fonte de CTI para ingestão contínua de Indicadores de Comprometimento (IoCs), focada em botnets e malwares.
3. **Motor de Correlação (Python):** Script analítico baseado em Pandas que cruza o tráfego interceptado pelo Suricata com a base de IoCs da ThreatFox.
4. **Zabbix (Docker):** Plataforma de monitoramento que recebe os alertas validados e os disponibiliza em um dashboard executivo via Zabbix Agent.

## Stack Tecnológico

* Python 3 (Pandas, Requests, Python-dotenv)
* Suricata IDS
* Zabbix (Server, Web, Agent)
* Docker & Docker Compose

## Pré-requisitos

* Python 3.x
* Docker e Docker Compose
* Suricata instalado e configurado para a interface de rede em uso
* Chave de API ativa da ThreatFox

## Instruções de Uso

### 1. Preparação do Ambiente

Clone o repositório e configure o ambiente virtual:

```bash
git clone [https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git](https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git)
cd SEU_REPOSITORIO

# Criação e ativação do ambiente virtual (Windows)
python -m venv venv
.\venv\Scripts\activate

# Instalação das dependências
pip install -r requirements.txt
```
2. Configuração de Credenciais
Crie um arquivo .env no diretório raiz do projeto e insira as credenciais de API:
```bash
Snippet de código
THREATFOX_API_KEY=sua_chave_de_api_aqui
```
3. Execução da Infraestrutura
Provisione o servidor Zabbix e o banco de dados via Docker:

```bash
docker-compose up -d
```
Nota: Acesse a interface web do Zabbix (http://localhost:8080) e adicione o host local apontando para o IP da máquina na porta 10050.

4. Inicialização do Pipeline
Com o Suricata em execução na máquina local (gerando o arquivo eve.json), inicie o motor de correlação:
```bash
python correlacionador.py
```
O sistema passará a inspecionar os pacotes e reportar correspondências com os IoCs diretamente para o servidor Zabbix.

Segurança e Boas Práticas
Arquivos sensíveis e de volume local estão excluídos do versionamento via .gitignore. Isso inclui:

Credenciais de API (.env)

Ambiente virtual Python (venv/)

Logs de tráfego de rede (*.log, eve.json)

Próximos Passos (Roadmap)

[ ] Integração de script para bloqueio automatizado de IPs no Firewall local (Windows Defender/Iptables).

[ ] Suporte à ingestão de regras YARA personalizadas.
