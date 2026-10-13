import pandas as pd
import json

def extrair_logs_suricata(caminho_arquivo):
    dados_extraidos = []
    
    with open(caminho_arquivo, 'r', encoding='utf-8') as ficheiro:
        for linha in ficheiro:
            try:
                evento = json.loads(linha)
                tipo = evento.get('event_type')
                
                if tipo not in ['dns', 'http', 'tls', 'flow']:
                    continue
                
                registro = {
                    'timestamp': evento.get('timestamp'),
                    'ip_origem': evento.get('src_ip'),
                    'ip_destino': evento.get('dest_ip'),
                    'porta_destino': evento.get('dest_port'),
                    'protocolo': tipo,
                    'dominio_acessado': None
                }
                
                if tipo == 'dns' and 'dns' in evento:
                    dns_data = evento['dns']
                    
                    if 'rrname' in dns_data:
                        registro['dominio_acessado'] = dns_data['rrname']
                    elif 'queries' in dns_data and isinstance(dns_data['queries'], list) and len(dns_data['queries']) > 0:
                        registro['dominio_acessado'] = dns_data['queries'][0].get('rrname')
                    elif 'answers' in dns_data and isinstance(dns_data['answers'], list) and len(dns_data['answers']) > 0:
                        registro['dominio_acessado'] = dns_data['answers'][0].get('rrname')
                        
                elif tipo == 'http' and 'http' in evento:
                    registro['dominio_acessado'] = evento['http'].get('hostname')
                    
                elif tipo == 'tls' and 'tls' in evento:
                    registro['dominio_acessado'] = evento['tls'].get('sni')
                
                dados_extraidos.append(registro)
                
            except json.JSONDecodeError:
                continue
                
    df = pd.DataFrame(dados_extraidos)
    
    if not df.empty:
        df = df.dropna(subset=['ip_destino'])
        
        df = df.dropna(subset=['dominio_acessado'])
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
    return df

if __name__ == "__main__":
    caminho_log = r"C:\Program Files\Suricata\log\eve.json"
    
    print("A extrair dados do Suricata. Isto pode demorar alguns segundos...")
    df_trafego = extrair_logs_suricata(caminho_log)
    
    if not df_trafego.empty:
        print(f"\nSucesso! {len(df_trafego)} registros extraídos com domínio válido.")
        print("\nAmostra dos dados capturados:")
        print(df_trafego[['timestamp', 'ip_origem', 'ip_destino', 'protocolo', 'dominio_acessado']].head(15))
    else:
        print("Nenhum tráfego com domínio encontrado ou o ficheiro eve.json está vazio.")