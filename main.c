/*******************************************************************
 * Arquivo: main.c
 * Data: 25/09/2012
 * Autor: Lucas Vasconcelos Santana
 * Ultima modificacao: 31/10/2012
 *
 * Descricao:
 * Programa principal do sistema IDS desenvolvido como trabalho de conclusao
 * de curso por Lucas Vasconcelos Santana.
 *
 * Compilar usando:
 * gcc main.c -lpcap -o ss-davi
 *
 * Uso:
 * ./ss-davi [DEV]
 *
 * e.g.
 * ./ss-davi eth0
 *
 *
 *******************************************************************/

/* Incluindo as bibliotecas necessarias */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include "eth-tcp-ip.h"
#include "srchost.h"

/* Defines */
#define HOSTNAME "192.168.0.1" // Definindo o IP ou nome do host em que o IDS sera executado

/* Prototipos das funcoes do sistema */
struct in_addr get_interface_info(char *dev, int type);
int interface_info(char *dev, char *filtro);
void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int detecta_portscan(const struct sniff_ip *ip, const struct sniff_tcp *tcp);
int detecta_synflood(const struct sniff_ip *ip, const struct sniff_tcp *tcp);
int write_threat(const struct sniff_ip *ip, const struct sniff_tcp *tcp, time_t tv_sec, int type);

struct srchost hostlist[MAXHOSTS]; // Lista com os ultimos hosts que tentaram/fizeram conexoes
struct threat threatlist[MAXTHREATLIST]; // Lista com informacoes de hosts que fizeram ataques
int hostcount = 0; // Contador para a lista de hosts
int threatcount = 0; // Contador para a lista de ameacas detectadas

/* funcao main */
int main(int argc, char *argv[]) {

	/* Declaracao de variaveis globais: */
	char *dev; // Nome da interface de rede utilizada pelo programa
	char errbuf[PCAP_ERRBUF_SIZE]; // String para receber os erros retornados pelas funcoes pcap
	pcap_t *package; // Recebera o pacote recebido pela interface
	const u_char *packet; // Pacote atual, consta a informacoes do pacote que esta sendo 'atualmente' escutado
	struct pcap_pkthdr header; // Header que eh recebido do pcap
	struct bpf_program fp; // Necessario para aplicar o filtro padrao
	char filtro[] = "dst host 192.168.0.1 and src host 192.168.0.200 or src host 192.168.0.3"; // Filtro padrao aplicado na 'escuta' da interface
	bpf_u_int32 ip; // Variavel pra receber o IP da interface 
	bpf_u_int32 mask; // Variavel para receber a mascara da interface


	/* Verifica os argumentos passados para o programa
	* Se nao foi passado um argumento informando qual interface de rede sera utilizada, 
	* o pcap tenta encontrar a interface padrao utilizada pelo sistema. Caso contrario,
	* a interface que sera 'escutada' sera a passada como parametro pelo usuario. */
	if (argc != 2) {
		dev = pcap_lookupdev(errbuf);	
		/* Caso seja encontrado um erro, fazemos o print do erro */
		if (dev == NULL) {
			printf("%s\n",errbuf); 
			exit(1);
		}

	}
	else {
		dev = argv[1];
	}

	/* Imprimindo as informacoes da interface */
	if (interface_info(dev, filtro) == -1) { 
		printf("Erro na obtencao das informacoes da interface.\n");
		exit(1);
	}

	/* Recebendo as informacoes da interface de maneira nao humana */
	if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
		printf("Erro na hora de obter as informacoes da interface.\n");
		exit(1);
	}

	/* Preparando a interface para a escuta dos pacotes entrantes */	
	package = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (package == NULL) {
		printf("Erro ao acessar a interface: %s\n", errbuf);
		exit(1);
	}

	/* "Compilando" o filtro que eh aplicado de acordo com a sintaxe da libpcap */
	/* Para mais informacoes sobre a sintaxe, verificar as man pages do tcpdump */
	if (pcap_compile(package, &fp, filtro, 0, mask) == -1) {
		printf("Erro ao aplicar o filtro: %s\n", pcap_geterr(package));
	}	
	
	/* Aplicando o filtro ja "compilado" */
	if (pcap_setfilter(package, &fp) == -1) {
		printf("Nao foi possivel aplicar o filtro %s: %s\n", filtro, pcap_geterr(package));
	}
	
	/* Utilizando a funcao pcap_loop(), que escuta um pacote e chama a funcao callback pcap_callback(); */
	pcap_loop(package, -1, pcap_callback, NULL); 

	/* Fecha a sessao */
	pcap_freecode(&fp);
	pcap_close(package);

	printf("Done.\n");
	return(0);
}

/* Funcao get_interface_info */
/* A funcao retorna o endereco IP ou a Mascara de uma determinada interface */
/* O endereco retornado nao eh em forma humana. Caso o usuario a forma huamana, ele pode transformar */
/* o retorno utilizando a funcao inet_ntoa() */
/* int type -> 1 para IP e 2 para Mascara */
struct in_addr get_interface_info(char *dev, int type) {
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 ip;
	bpf_u_int32 mask;
	struct in_addr addr;

	/* Pre-verificacao se a interface passada eh valida e obtencao da mascara */
	if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
		printf("Erro ao obter as informacoes da interface.\n");
		exit(1);
	}

	else {
		/* Retornar o IP */
		if (type == 1) {
			
			/* Para obter o endereco de uma interface eh necessario o uso da funcao pcap_findalldevs() */
			pcap_if_t *devs;
			pcap_if_t *if_t;
			pcap_addr_t *addr_t;
			
			/* Executando a funcao pcap_findalldevs() */
			int status = pcap_findalldevs(&devs, errbuf);

			/* Verificando se houve algum erro */
			if (status != 0) { 
				printf("%s\n", errbuf);
				exit(1);
			}
			
			/* Percorrendo a lista de interfaces */
			for (if_t=devs; if_t != NULL; if_t = if_t->next) {	

				/* Verificando se a interface passada realmente existe */
				if ( strcmp(if_t->name, dev) == 0 ) {

					/* Percorrendo a lista de enderecos da interface */
					for ( addr_t = if_t->addresses; addr_t != NULL; addr_t = addr_t->next) {
						
						/* Eh retornado o primeiro endereco valido encontrado */
						if ( addr_t->addr != NULL ) { 
							if ( addr_t->addr->sa_family == AF_INET) {
								return(((struct sockaddr_in*)addr_t->addr)->sin_addr);
							}
						}	
					}
				}
			}
		
			/* Caso haja algum erro na obtencao do endereco IP da interface */
			pcap_freealldevs(devs);
			printf("A interface nao possui IP definido!\n");
			exit(1);
			
		}
	
		/* Retornar a mascara */
		else if (type == 2) {
			addr.s_addr = mask;
			return(addr);
		}
		
	}

}

/* Funcao interface_info */
/* Apenas imprime na saida padrao informacoes sobre a interface utilizada */
int interface_info(char *dev, char *filtro) {
	char *ipaddr;  // Endereco IP da interface em notacao humana
	char *mask;    // netmask da interface em notacao humana
	int flag;      // flag para controle de erros
	char errbuf[PCAP_ERRBUF_SIZE]; // String para receber os erros retornados pelas funcoes pcap
	bpf_u_int32 ipaddrp; // Endereco IP
	bpf_u_int32 maskp; // Mascara
	struct in_addr addr; // Struct que recebera os dados da interface

		printf("Interface: %s\n", dev);

		/* Recebendo o endereco IP da interface e transformando em notacao humana */	
		ipaddr = inet_ntoa(get_interface_info(dev,1));
		printf("IP: %s\n", ipaddr);

		/* Recebendo mascara da interface e transformando em notacao humana */	
		mask = inet_ntoa(get_interface_info(dev,2));
		printf("Mascara: %s\n", mask);

		printf("Filtro aplicado na captura: %s\n\n\n", filtro);		

		return(0);

}

/* Funcao detecta_portscan() */
/* Funcao para detectar tentativas de portscan */
int detecta_portscan(const struct sniff_ip *ip, const struct sniff_tcp *tcp) {
 	int i;	
	short scanning = 0;
	for (i = 0; i < MAXHOSTS; i++) {
		if ( ntohs(hostlist[i].dport) != 0) {
		if ( inet_ntoa(hostlist[i].ip_src) == inet_ntoa(ip->ip_src) && ( ntohs(hostlist[i].dport)==ntohs(tcp->th_dport)-1 || ntohs(hostlist[i].dport)==ntohs(tcp->th_dport)+1 )) {
		scanning = 1;
		break;
		}
		}
	}

	return scanning;	
}

/* Funcao detecta_synflood() */
/* Funcao para detectar tentativas de ataques DDoS do tipo SYN FLOOD */
int detecta_synflood(const struct sniff_ip *ip, const struct sniff_tcp *tcp) {
 	int i;	
	short scanning = 0;
	for (i = 0; i < MAXHOSTS; i++) {
		if ( ntohs(hostlist[i].dport) != 0) {
		if ( inet_ntoa(hostlist[i].ip_src) == inet_ntoa(ip->ip_src) && ntohs(hostlist[i].dport) == ntohs(tcp->th_dport) && tcp->th_flags == 2 ) {
		scanning++;
		}
		}
	}

	if (scanning >= 5) return 1;
	else return 0;	
}

/* Funcao write_threat() */
/* Funcao responsavel por guardar registros das amaecas detectadas e fazer os alertas necessarios*/
int write_threat(const struct sniff_ip *ip, const struct sniff_tcp *tcp, time_t tv_sec,  int type) {
	int i;	
	int already_threat = 0;
	char *c, *date, *email;
	time_t date_t;
	FILE *fp;
	
	/* Informacoes sobre o email de alerta */
	char *email_address;
	email_address = "luksvs@gmail.com";

	date_t = tv_sec;
	date = ctime((const time_t*)&tv_sec);

	/* Define o tipo de ataque de acordo com o parametro passado */
	switch (type) {	
		case 1:
			c = "PORT SCAN";
			break;
		case 2:
			c = "SYN FLOOD";
  			break;
	}
	
	/* Verifica se a ameaca ja foi registrada */
	for (i=0; i <= threatcount; i++) {
		if ( inet_ntoa(threatlist[i].ip_src) == inet_ntoa(ip->ip_src) && threatlist[i].type == type && threatlist[i].date == date_t) already_threat = 1;
	}	

	/* Se a ameaca ja for registrada, retorna */
	if (already_threat == 1) return 0;

	/* Senao faz o registro da ameaca */
	else {
		fp = fopen("detected_portscan.txt", "a+"); // Abre o arquivo para escrita dos logs
		if (fp != NULL)  {
			
			/* Executa o registro na lista de amecas */
		  	threatlist[threatcount].ip_src = ip->ip_src;
			threatlist[threatcount].type = type;
			threatlist[threatcount].date = date_t;
			threatcount++;	
			
			/* Imprime no arquivo a saida no padrao para ser lido pelo AfterGlow */
			fprintf(fp,"%s - %.*s,%s,%s\n", inet_ntoa(ip->ip_src), strlen(date) - 1, date, c, HOSTNAME);

			/* Imprime na saida padrao as informacoes sobre a ameaca detectada */
			printf("Detectamos uma ameaca do IP %s, em  %.*s, do tipo %s, com destino ao IP %s\n", inet_ntoa(ip->ip_src), strlen(date) - 1, date, c, HOSTNAME);

			/* Gera a string que eh passada para o sistema para o envio do email de alerta */
			sprintf(email,"/bin/echo \"Detectamos uma ameaca do IP %s, em  %.*s, do tipo %s, com destino ao IP %s\n\" | /usr/local/bin/email -s \"[IDS] Ameaca detectada\" %s", inet_ntoa(ip->ip_src), strlen(date) - 1, date, c, HOSTNAME, email_address);

			fclose(fp); // Fecha o arquivo

			/* Executa a linha de comando para o envio do email */
			system(email);
		}

	}
	return 1;
}

/* Funcao pcap_callback */
/* Funcao callback que a funcao pcap_loop() da libpcap chama ao receber um pacote */
void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	const struct sniff_ethernet *ethernet; // Ponteiro para o cabecalho ethernet
	const struct sniff_ip *ip; // Ponteiro para o cabecalho IP
	const struct sniff_tcp *tcp; // Ponteiro para o cabecalho TCP

	int size_ip;
	int size_tcp;
	int size_pppoe;

	char *date;
	if (hostcount == MAXHOSTS) hostcount = 0;

	/* Cast para o cabecalho ethernet */
	ethernet = (struct sniff_ethernet*)(packet);

	/* Pegando o cabecalho IP */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4; 

	/* Verifica se o cabecalho IP eh valido */
	if (size_ip < 20) {
		//printf("Tamanho do cabecalho IP invalido: %u bytes.\n", size_ip);
		return;
	}
	
	/* Verificacao de protocolo (apenas TCP eh aceito) */
	if (ip->ip_p != IPPROTO_TCP) return;
	

 	/* Obtendo o cabecalho TCP */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	/* Verifica se o cabecalho TCP eh valido */
	if (size_tcp < 20) {
		//printf("Tamanho do cabecalho TCP invalido: %u bytes.\n", size_tcp);
		return;
	}

	/* Imprimindo IP de origem e porta de destino*/
	//printf("%s,", inet_ntoa(ip->ip_src));
	//printf("%d\n", ntohs(tcp->th_dport));
	//printf("IP: %s - Porta: %d\n", inet_ntoa(hostlist[hostcount].ip_src), ntohs(hostlist[hostcount].dport));

	/* Adicionando o pacote na lista das conexoes recentes */
	hostlist[hostcount].ip_src = ip->ip_src;
	hostlist[hostcount].dport = tcp->th_dport;

	/* Chama a funcao para deteccao de PortScan */
	if (detecta_portscan(ip,tcp) == 1) {
		write_threat(ip, tcp, header->ts.tv_sec, 1);
	}

	/* Chama a funcao para deteccao de SYN Flood */
	if (detecta_synflood(ip,tcp) == 1) {
		write_threat(ip, tcp, header->ts.tv_sec, 2);
	}

	hostcount++;
	return;	
}

