/*******************************************************************
 * Arquivo: srchost.h
 * Data: 25/09/2012
 * Autor: Lucas Vasconcelos Santana
 * Ultima modificacao: 31/10/2012
 *
 * Descricao:
 * Arquivo de cabecalho do sistema IDS desenvolvido como trabalho de conclusao
 * de curso por Lucas Vasconcelos Santana.
 * Contem as estruturas utilizadas para geracao das lista de pacotes recentes e ameacas detectadas
 *
 *******************************************************************/

#define MAXHOSTS 20
#define MAXTHREATLIST 10

/* Struct responsavel por armazenar a lista dos ultimos hosts */
struct srchost {
	struct in_addr ip_src; // IP de origem
	u_short dport;	       // Porta de destino
};

/* Estrutura para ameacas detectadas */
struct threat {
	struct in_addr ip_src; // IP de origem
	int type; // 1 -> PortScan / 2 -> SYN Flood
	time_t date; // Timestamp
};
