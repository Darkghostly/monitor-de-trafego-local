# Netwatch - Egress Monitor 🌐

Netwatch é um script em Python focado em monitoramento de tráfego de rede (egress). Ele utiliza a biblioteca `scapy` para inspecionar pacotes em tempo real e emite alertas caso detecte tráfego com destino a endereços IP fora de uma lista de blocos CIDR predefinida (por padrão, ranges do Brasil).

## 🚀 Funcionalidades

* **Seleção de Interface:** Lista e permite a seleção interativa da interface de rede a ser monitorada.
* **Filtro por Geolocalização (Baseado em CIDR):** Compara IPs de destino com blocos de rede conhecidos.
* **Alertas em Tempo Real:** Exibe no terminal quando um tráfego para IP estrangeiro é detectado.
* **Registro de Logs:** Salva detalhes completos dos pacotes suspeitos em um arquivo local (`suspicious_packets.log`).
* **Resumo Operacional:** Exibe estatísticas de pacotes processados e erros ao encerrar a execução.

## 📋 Pré-requisitos

Para rodar este projeto, você precisará de:

* Python 3.7 ou superior.
* Privilégios de Administrador / Root (necessário para colocar a placa de rede em modo promíscuo).
* **No Windows:** É necessário ter o [Npcap](https://npcap.com/) instalado (normalmente instalado junto com o Wireshark).
* **No Linux:** É necessário ter o `tcpdump` / `libpcap` instalado no sistema.

## 🔧 Instalação

1. Clone o repositório:
   ```bash
   git clone [https://github.com/SEU_USUARIO/netwatch.git](https://github.com/SEU_USUARIO/netwatch.git)
   cd netwatch
