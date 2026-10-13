import pandas as pd
import os

from extractor import extrair_logs_suricata
from stix_collector import obter_feed_stix_simulado

def cruzar_dados():
    
    caminho_log_suricata = r"C:\Program Files\Suricata\log\eve.json" 
    df_trafego = extrair_logs_suricata(caminho_log_suricata)
    
    df_iocs = obter_feed_stix_simulado()
    
    if df_trafego.empty or df_iocs.empty:
        print("Dados insuficientes para realizar a correlação.")
        return
        
    print("\n2. A procurar ameaças no tráfego de rede...")
    
    alertas_ip = pd.merge(df_trafego, df_iocs[df_iocs['tipo_ioc'] == 'ip'], left_on='ip_destino', right_on='valor', how='inner')
    alertas_dominio = pd.merge(df_trafego, df_iocs[df_iocs['tipo_ioc'] == 'dominio'], left_on='dominio_acessado', right_on='valor', how='inner')
    
    alertas_finais = pd.concat([alertas_ip, alertas_dominio], ignore_index=True)
    
    if not alertas_finais.empty:
        print(f"\n{len(alertas_finais)} tráfegos suspeitos detetados!")
        tabela_final = alertas_finais[['timestamp', 'ip_origem', 'ip_destino', 'dominio_acessado', 'nome_ameaca']]
        
        print("-" * 90)
        print(tabela_final.to_string(index=False))
        print("-" * 90)
        
        caminho_alerta = "alertas_stix.log"
        print(f"\n3. A exportar alertas para {caminho_alerta} para leitura do Zabbix...")
        
        with open(caminho_alerta, "a", encoding="utf-8") as f:
            for _, linha in tabela_final.iterrows():
                log_line = f"{linha['timestamp']} | ALERTA_STIX | Origem: {linha['ip_origem']} | Destino: {linha['ip_destino']} | Dominio: {linha['dominio_acessado']} | Ameaça: {linha['nome_ameaca']}\n"
                f.write(log_line)
                
if __name__ == "__main__":
    cruzar_dados()