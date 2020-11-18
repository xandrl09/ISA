/************************************/
// SSL sniffer
// Autor: Ondrej Andrla
// Mail: xandrl09@stud.fit.vutbr.cz
// Datum: 18.11.2020
/************************************/

#include <iostream>
#include <getopt.h>

#include <stdio.h>
#include <time.h>
#include <math.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>


using namespace std;


// globalni konstanty
#define PROMISCOUS 1
#define EHL 14 // Ethernet Header Length
#define SIXMIN 360000 //milisekundy

// globalni promene //
char *device; // rozhrani
char *file; //soubor

bool syn = false; // byl zazlan prvni syn
bool clients_hello = false; // bylo zaslano client hello
bool timestamp_used = false; // zmeni se na true po prijeti prvniho packetu
long int milisec; //vypis milisekund prvniho paketu
char buffer[32]; //vypis sekund prvniho peketu
long int sec; // sekundy prvniho paketu
long int last_milisec; //vypis milisukund posledniho packetu
long int last_sec; //vypis sekund posledniho packetu

bool port_used = false; // je jiz zaznamenan port klienta
int port; // port klienta
string klient_ip = ""; 
string server_ip = ""; 

int number_of_fins = 0; // pocet fin paketu
int packet_counter = 0; // pocet paketu ve spojeni
int ssl_data = 0;  // pocet bitu ve spojeni

string server_name;


/*
 * Funkce slouzi pro vypsani napovedy na standardni vystup.
 */
void help()
{
	cerr << "Run the program with arguments -i or -r." << endl
	<< "Example of running the program:" << endl
	<< "./sslsniff -r soubor.pcapng" << endl
	<< "./sslsniff -i enp0s3" << endl;
}


/*
 * Funkce vypise napovedu a ukonci program.
 */
void error_help()
{
	help();
	exit(1);
}


/*
 * Funkce kontroluje parametry programu.
 * V pripade spravnych parametru preda Sinformace o nich do mainu.
 * V pripade spatnych parametru vypise napovedu.  
 */
int check_params(int argc, char *argv[])
{
	string promena;
	int opt;

	// program spusten bez parametru -> vypise napovedu
	if (argc == 1)
	{
		help();
		exit(0);
	}
	else if(argc == 3)// program spusten se dvema parametry
	{
		opt = getopt(argc, argv, "ir");
		switch (opt)
		{
			case 'i': // interface
			device = argv[optind];
			return 1;
							
			case 'r': // file
			file = argv[optind];
			return 2;

			default:
			error_help();
		}
	}
	else // spatny pocet argumentu
	{
		error_help();
	}
	return 0;
}

/*
 * Funkce prochazi paket, analyzuje v nem ulozena data a vypisuje je na standartni vystup.
 */
void p_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// ukazatele na hlavicky
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	// velikosti hlavicek
	int ethernet_header_length = EHL;// pevne dana velikost ethernetove hlavicky
	int ip_header_length;
	int tcp_header_length;

	// IP hlavicka
	ip_header = packet + ethernet_header_length;
	struct ip *iph;
	iph = (struct ip *) ip_header;
	//delka ip hlavicky
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length *4;
	
	// TCP hlavicka
	tcp_header = packet + ethernet_header_length + ip_header_length;
	struct tcphdr *tcp;
	tcp = (struct tcphdr *) tcp_header;

	// pokud prisel prvni syn
	if(tcp->syn && syn == false)
	{
		syn = true;
		number_of_fins = 0;
		port_used = false;
		timestamp_used = false;
		packet_counter = 0;
		ssl_data = 0;

	}
	if(syn == false) // vyfiltrovani paketu pred zacatkem komunikace
	{
		return;
	}

	if(number_of_fins > 1) // prisli dva finy -> komunikace ukoncena
	{
		return;
	}

	packet_counter++; // paket patri ke komunikaci

	// vypis casu
	if(timestamp_used == false)// cas se zaznamena pro prvni paket komunikace
	{
		milisec = lrint(header->ts.tv_usec);// milisekundy
		sec = lrint(header->ts.tv_sec);// sekundy
		// naplneni bufferu formatovanym vypisem sekund	
		strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", localtime(&header->ts.tv_sec) );	
		timestamp_used = true;
	}

	if(port_used == false)// zacatek komunikace
	{
		// IP adresy
		klient_ip = inet_ntoa(iph->ip_src);// klient
		server_ip = inet_ntoa(iph->ip_dst);// server

		port = htons(tcp->source);//port klienta
		port_used = true;
	}

	// delka tcp hlavicky ulozena na polovine byte -> & 0xF0) >> 4;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length *4;

	//SSL hlavicka
	int ssl_hl = ethernet_header_length + ip_header_length 
	+ tcp_header_length;
	
	payload = packet + ssl_hl;

	if(*payload == 0x16 && clients_hello == false) // client hello zprava
	{
		clients_hello = true;

		payload = payload + 43;
		int sesid = *payload; //sesion id
		payload = payload + sesid + 2;
		int cip = *payload;// cipher suite lenght
		payload = payload + cip + 14;
		int naml = *payload; //name lenght
		char sni [naml];
		memccpy(sni, payload, naml+4,  naml+4);
		server_name = sni; // Server NAme Identification
	}
	
	while(*payload == 0x14 || *payload == 0x15 ||
	 *payload == 0x16 || *payload == 0x17  )// zpracuje vsechny: application data protocol
	{
		int ssl =  *(payload + 4) ;
		ssl = ssl + (*(payload + 3) * 255);
				
		ssl_data = ssl_data  + ssl;

		payload = payload + ssl  + 5;
	}
	

	if(tcp->fin && number_of_fins < 2 && clients_hello == true) // paket ma priznak fin
	{
		number_of_fins++;
		if(number_of_fins == 2)// pokud jiz prisli dva fin pakety spojeni se ukonci
		{
			last_milisec = lrint(header->ts.tv_usec);//milisekundy posledniho paketu
			last_sec = lrint(header->ts.tv_sec);//sekundy posledniho paketu

			//zaverecny vypis
			printf("%s.%06ld,", buffer, milisec);
			cout  << klient_ip << "," << port << "," << server_ip << ","
			<< server_name <<"," << ssl_data <<","<<  packet_counter; 
			// pocatecni cas odecten od koncoveho
			// pro dosazeni milisekund deleno 1000000;
            printf(",0.%06ld\n", (last_sec - sec) * 1000000 + last_milisec - milisec );

			syn = false;// syn se rusi aby mohlo nastat nove spojeni
			clients_hello = false; // clients_hello se vynuleje, aby mohlo nastat nove spojeni
		}
	}

	return;
}


/*
 * Hlavni funkce programu.
 * Postupne vola dalsi.
 */
int main(int argc, char **argv)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int s_len = 1024; // delka snapshotu
	u_char *my_arguments = NULL;


	int vysledek = check_params(argc, argv); // volani kontroli parametru

	if (vysledek == 1) // sitovi provoz
	{
		handle = pcap_open_live(device, s_len, PROMISCOUS, SIXMIN, error_buffer);
		if(handle == NULL)
		{
			fprintf(stderr, "Could not open device %s\n",  error_buffer);
			return 2;
		}
	}
	else if(vysledek == 2) // pcaapng soubor
	{
		handle = pcap_open_offline(file, error_buffer);
		if(handle == NULL)
		{
			fprintf(stderr, "Could not open file %s\n",  error_buffer);
			return 2;
		}
	}
	else
	{
		error_help();
	}

	//  TCP filter - program zpracovava jen TCP pakety
	struct bpf_program filter;
	char filter_exp[] = "tcp";
	bpf_u_int32 ip;
	
	pcap_compile(handle, &filter, filter_exp, 0, ip);
	pcap_setfilter(handle, &filter);

	// zpracovani paketu
	pcap_loop(handle, 0, p_handler, my_arguments);

	return 0;
}