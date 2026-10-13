import pandas as pd
import re

def obter_feed_stix_simulado():
    print("A simular ligação a servidor TAXII e a carregar Bundle STIX...")
    
    # Simulação do payload exato em JSON que um servidor TAXII nos devolveria
    objetos_stix = [
        {
            "type": "indicator",
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "name": "Botnet de Teste (DNS)",
            "pattern": "[ipv4-addr:value = '181.213.132.2']" # IP que capturou no Suricata
        },
        {
            "type": "indicator",
            "id": "indicator--4a78c187-5f72-4d57-9d11-66774642ab74",
            "name": "Domínio Phishing Simulado",
            "pattern": "[domain-name:value = 'ab.chatgpt.com']" # Domínio que capturou no TLS
        },
        {
            "type": "indicator",
            "id": "indicator--00000000-0000-0000-0000-000000000000",
            "name": "Servidor C&C Real",
            "pattern": "[ipv4-addr:value = '203.0.113.50']"
        }
    ]
    
    indicadores_extraidos = []
    
    # Regex para capturar os valores dentro do padrão STIX
    padrao_ip = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'")
    padrao_dominio = re.compile(r"domain-name:value\s*=\s*'([^']+)'")
    
    for obj in objetos_stix:
        pattern = obj.get("pattern", "")
        nome = obj.get("name", "Sem nome")
        
        match_ip = padrao_ip.search(pattern)
        if match_ip:
            indicadores_extraidos.append({
                "tipo_ioc": "ip", 
                "valor": match_ip.group(1), 
                "nome_ameaca": nome
            })
            
        match_dominio = padrao_dominio.search(pattern)
        if match_dominio:
            indicadores_extraidos.append({
                "tipo_ioc": "dominio", 
                "valor": match_dominio.group(1), 
                "nome_ameaca": nome
            })
            
    # Converte para DataFrame
    return pd.DataFrame(indicadores_extraidos)

if __name__ == "__main__":
    df_iocs = obter_feed_stix_simulado()
    print(f"\nSucesso! {len(df_iocs)} IoCs processados.")
    print("\nTabela de Inteligência de Ameaças:")
    print(df_iocs)