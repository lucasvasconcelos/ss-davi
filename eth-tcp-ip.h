/*******************************************************************
 * Arquivo: eth-tcp-ip.h
 * Data: 25/09/2012
 * Autor: Lucas Vasconcelos Santana
 * Ultima modificacao: 31/10/2012
 *
 * Descricao:
 * Arquivo de cabecalho do sistema IDS desenvolvido como trabalho de conclusao
 * de curso por Lucas Vasconcelos Santana.
 * Contem as estruturas utilizadas para obtencao de informacoes sobre os pacotes capturados
 *
 *******************************************************************/

/* Tamanho padrao em bytes de cada pacote capturado */
#define SNAP_LEN 1518 

/* Cabecalhos ethernet -> 14 bytes for Ethernet and 16 bytes for PPPoE */
#define SIZE_ETHERNET 14

/* Enderecos ethernet de 6 bytes */
#define ETHER_ADDR_LEN	6

/* Estrutura que define o cabelho Ethernet */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Endereco de destino */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Endereco de origem */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* Estrutura que define o cabecalho IP */
struct sniff_ip {
	u_char ip_vhl;		/* versao << 4 | tamanho do cabecalho >> 2 */
	u_char ip_tos;		/* tipo de servico (TOS) */
	u_short ip_len;		/* tamanho total */
	u_short ip_id;		/* identificacao */
	u_short ip_off;		/* offset  */
	#define IP_RF 0x8000		/* reservado para flag */
	#define IP_DF 0x4000		/* nao ha flag */
	#define IP_MF 0x2000		/* ha mais flags */
	#define IP_OFFMASK 0x1fff	/* mascara para os bits fragmentados */
	u_char ip_ttl;		/* tempo de vida */
	u_char ip_p;		/* protocolo */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* endereco de origem e destino */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* Cabecalho TCP */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* porta de origem */
	u_short th_dport;	/* porta de destino */
	tcp_seq th_seq;		/* numero de sequencia */
	tcp_seq th_ack;		/* numero do ACK */
	u_char th_offx2;	/* offset */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* ponteiro para urgente */
};

