import pandas as pd
import json

def extrair_logs_suricata(caminho_arquivo):
    dados_extraidos = []
    
    # Lemos o arquivo linha a linha para não sobrecarregar a memória
    with open(caminho_arquivo, 'r', encoding='utf-8') as ficheiro:
        for linha in ficheiro:
            try:
                evento = json.loads(linha)
                tipo = evento.get('event_type')
                
                # Focamos apenas nos protocolos que ativamos no suricata.yaml
                if tipo not in ['dns', 'http', 'tls', 'flow']:
                    continue
                
                # Estrutura base que queremos analisar
                registro = {
                    'timestamp': evento.get('timestamp'),
                    'ip_origem': evento.get('src_ip'),
                    'ip_destino': evento.get('dest_ip'),
                    'porta_destino': evento.get('dest_port'),
                    'protocolo': tipo,
                    'dominio_acessado': None
                }
                
                # Extraímos o domínio com base na camada de aplicação (App Layer)
                if tipo == 'dns' and 'dns' in evento:
                    dns_data = evento['dns']
                    
                    # 1. Tenta formato direto (Suricata antigo ou consulta simples)
                    if 'rrname' in dns_data:
                        registro['dominio_acessado'] = dns_data['rrname']
                    # 2. Tenta procurar na lista de 'queries' (Suricata 8)
                    elif 'queries' in dns_data and isinstance(dns_data['queries'], list) and len(dns_data['queries']) > 0:
                        registro['dominio_acessado'] = dns_data['queries'][0].get('rrname')
                    # 3. Tenta procurar na lista de 'answers' (Respostas do servidor)
                    elif 'answers' in dns_data and isinstance(dns_data['answers'], list) and len(dns_data['answers']) > 0:
                        registro['dominio_acessado'] = dns_data['answers'][0].get('rrname')
                        
                elif tipo == 'http' and 'http' in evento:
                    registro['dominio_acessado'] = evento['http'].get('hostname')
                    
                elif tipo == 'tls' and 'tls' in evento:
                    # SNI (Server Name Indication) revela o domínio no tráfego HTTPS
                    registro['dominio_acessado'] = evento['tls'].get('sni')
                
                dados_extraidos.append(registro)
                
            except json.JSONDecodeError:
                # Ignora linhas corrompidas ou mal formatadas
                continue
                
    # Converte a lista de dicionários num DataFrame do Pandas
    df = pd.DataFrame(dados_extraidos)
    
    # Limpeza e formatação
    if not df.empty:
        # Remove pacotes sem IP de destino válido
        df = df.dropna(subset=['ip_destino'])
        
        # Remove linhas onde não foi possível identificar nenhum domínio
        df = df.dropna(subset=['dominio_acessado'])
        
        # Converte a coluna de tempo para o formato datetime do Pandas
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
    return df

# --- Área de Teste do Script ---
if __name__ == "__main__":
    # Caminho onde o Suricata está a gravar o log no Windows
    caminho_log = r"C:\Program Files\Suricata\log\eve.json"
    
    print("A extrair dados do Suricata. Isto pode demorar alguns segundos...")
    df_trafego = extrair_logs_suricata(caminho_log)
    
    if not df_trafego.empty:
        print(f"\nSucesso! {len(df_trafego)} registros extraídos com domínio válido.")
        print("\nAmostra dos dados capturados:")
        # Mostra as primeiras 15 linhas para visualizar melhor
        print(df_trafego[['timestamp', 'ip_origem', 'ip_destino', 'protocolo', 'dominio_acessado']].head(15))
    else:
        print("Nenhum tráfego com domínio encontrado ou o ficheiro eve.json está vazio.")