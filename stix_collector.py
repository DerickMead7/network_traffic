import pandas as pd
import requests
import os
import re
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

def obter_feed_stix_simulado():
    print("A ligar à API global da ThreatFox (Abuse.ch)...")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    
    CHAVE_API = os.getenv("API_KEY")
    
    if not CHAVE_API:
        print("[ERRO] Chave da API não encontrada no ficheiro .env!")
        return pd.DataFrame()
        
    payload = {"query": "get_iocs", "days": 1}
    headers = {"Auth-Key": CHAVE_API}
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        dados = response.json()
        
        if dados.get("query_status") != "ok":
            print(f"[ERRO] A API recusou. Motivo: {dados.get('query_status')}")
            return pd.DataFrame()
            
        iocs_extraidos = []
        
        for item in dados.get("data", []):
            tipo = item.get("ioc_type")
            valor = item.get("ioc") 
            ameaca = f"{item.get('threat_type')} ({item.get('malware_printable')})"
            
            if not valor:
                continue
                
            if tipo in ["ipv4:port", "ip:port"]:
                valor = valor.split(":")[0] 
                tipo_limpo = "ip"
            elif tipo == "domain":
                tipo_limpo = "dominio"
            elif tipo == "ipv4":
                tipo_limpo = "ip"
            elif tipo == "url":
                try:
                    parsed = urlparse(valor)
                    valor = parsed.hostname
                    if not valor:
                        continue
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", valor):
                        tipo_limpo = "ip"
                    else:
                        tipo_limpo = "dominio"
                except:
                    continue
            else:
                continue 
                
            iocs_extraidos.append({
                "tipo_ioc": tipo_limpo,
                "valor": valor,
                "nome_ameaca": ameaca
            })
            
        iocs_extraidos.extend([
            {"tipo_ioc": "dominio", "valor": "uol.com", "nome_ameaca": "Teste STIX - UOL"},
            {"tipo_ioc": "dominio", "valor": "g1.com", "nome_ameaca": "Teste STIX - G1"},
            {"tipo_ioc": "dominio", "valor": "netflix.com", "nome_ameaca": "Teste STIX - Netflix"}
        ])
        
        df = pd.DataFrame(iocs_extraidos)
        df = df.drop_duplicates(subset=['valor'])
        
        print(f"[OK] {len(df)} ameaças (reais + testes) carregadas na memória!")
        return df
        
    except Exception as e:
        print(f"[ERRO] Falha na ligação à API: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    df_iocs = obter_feed_stix_simulado()
    print("\nAmostra das ameaças ativas neste momento no mundo:")
    if not df_iocs.empty:
        print(df_iocs.head(10))