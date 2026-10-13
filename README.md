SOC pipeline Lab: Suricata, ThreatFox & Zabbix

Este projeto é um laboratório completo de **Security Operations Center (SOC)** construído para monitoramento de rede, ingestão de Cyber Threat Intelligence (CTI) e geração de alertas em tempo real. Ele integra um IDS de rede com inteligência de ameaças global e um dashboard de monitoramento executivo.

##Arquitetura do Projeto

O pipeline funciona de ponta a ponta cruzando tráfego local com indicadores de comprometimento (IoCs) ativos no mundo:

1. **Suricata (Network IDS):** Escuta a placa de rede em tempo real e estrutura os eventos de tráfego em logs no formato JSON (`eve.json`).
2. **ThreatFox API (Abuse.ch):** Fonte de Threat Intelligence. O sistema se autentica na API e consome feeds de IPs e domínios maliciosos (Botnets, C&C, Malware).
3. **Motor de Correlação (Python & Pandas):** Script que atua como o "cérebro" do pipeline. Ele cruza o tráfego de rede capturado pelo Suricata com a base de IoCs da ThreatFox.
4. **Zabbix & Docker:** Servidor de monitoramento rodando em containers. Recebe os alertas validados via Zabbix Agent e exibe os incidentes num dashboard executivo.

##Tecnologias Utilizadas

* **Linguagem:** Python 3 (Pandas, Requests, Python-dotenv)
* **Segurança de Rede:** Suricata IDS
* **Monitoramento & SIEM:** Zabbix (Server, Web, Agent)
* **Infraestrutura:** Docker & Docker Compose
* **Threat Intelligence:** API ThreatFox (Abuse.ch STIX/JSON)

## Pré-requisitos

Para rodar este laboratório na sua máquina local, você precisará de:
* [Python 3.x](https://www.python.org/) instalado.
* [Docker e Docker Compose](https://www.docker.com/) rodando na máquina.
* [Suricata](https://suricata.io/) instalado e configurado para a sua placa de rede.
* Uma chave de API gratuita da [ThreatFox](https://threatfox.abuse.ch/).

##Como Configurar e Executar

### 1. Clonar o Repositório e Preparar o Ambiente Python
```bash
git clone [https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git](https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git)
cd SEU_REPOSITORIO

# Criar e ativar o ambiente virtual (Windows)
python -m venv venv
.\venv\Scripts\activate

# Instalar as dependências
pip install -r requirements.txt
