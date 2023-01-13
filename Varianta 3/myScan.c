#define _CRT_SECURE_NO_WARNINGS

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "myScan.h"
#include "arg_parse.h"

typedef struct arguments arguments;
struct in_addr dest_ip;

struct pseudo_header // needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

void process_packet(unsigned char *buffer, int size)
{
	// Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr *)buffer;
	struct sockaddr_in source, dest;
	unsigned short iphdrlen;

	if (iph->protocol == 6)
	{
		struct iphdr *iph = (struct iphdr *)buffer;
		iphdrlen = iph->ihl * 4;

		struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		if (tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr)
		{
			printf("Port %d open \n", ntohs(tcph->source));
			fflush(stdout);
		}
	}
}

int start_sniffer()
{
	int sock_raw;

	int saddr_size, data_size;
	struct sockaddr saddr;

	unsigned char *buffer = (unsigned char *)malloc(65536); // Its Big!

	printf("Sniffer initialising...\n");
	fflush(stdout);

	// Create a raw socket that shall sniff
	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
	}

	saddr_size = sizeof saddr;

	while (1)
	{
		// Receive a packet
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		if (data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 1;
		}

		// Now process the packet
		process_packet(buffer, data_size);
	}

	close(sock_raw);
	printf("Sniffer finished.");
	fflush(stdout);
	return 0;
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return (answer);
}

void *receive_ack(void *ptr)
{
	// Start the sniffer thing
	start_sniffer();
}

int get_local_ip(char *buffer)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	const char *kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons(dns_port);

	int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr *)&name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
}

void *scan_thread(void *arg)
{
	struct thread_options *args = (struct thread_options *)arg;
	int ports[300];
	int flag = args->flag;
	for (int i = 0; i < args->end - args->start + 1; i++)
	{
		ports[i] = args->start + i;
	}

	if (args->randomize == 1)
	{
		for (int i = 0; i < args->end - args->start + 1; i++)
		{
			int j = rand() % (args->end - args->start + 1) + args->start;
			int temp = ports[i];
			ports[i] = ports[j];
			ports[j] = temp;
		}
	}

	for (int i = 0; i < args->end - args->start + 1; i++)
	{
		if (args->fast == 1)
		{
			usleep(500);
		}

		int port = ports[i];
		// sarim peste porturile specificate in excluded_ports
		int skip = 0;
		for (int j = 0; j < args->excluded_ports_count; j++)
		{
			if (args->excluded_ports[j] == port)
			{
				skip = 1;
				break;
			}
		}
		// daca nu exista porturi in excluded_ports
		if (skip == 0)
		{
			if (strcmp(args->scan_type, "TCP") == 0) // daca scanarea e de tip TCP
			{
				if (flag == 1)
				{
					int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
					if (sockfd < 0)
					{
						printf("Eroare socket TCP.\n");
					}

					struct sockaddr_in addr;
					bzero((char *)&addr, sizeof(addr));
					addr.sin_family = AF_INET;
					addr.sin_port = htons(port);
					addr.sin_addr.s_addr = inet_addr(args->host);

					struct timeval tv;
					tv.tv_sec = args->timeout;
					tv.tv_usec = 0;
					setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&args->timeout, sizeof(tv));

					int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)); // aici facem conectarea efectiva la port
					if (ret >= 0)
					{
						if (args->verbose == 1)
						{
							struct servent *s = getservbyport(htons(port), "tcp");
							if (s)
								printf("PORT: %d\tSTARE: OPEN SERVICE:%s\t PROTOCOL:%s\t\n", port, s->s_name, s->s_proto);
						}
						else
						{
							printf("PORT: %d\tSTARE: OPEN \n", port);
						}
					}

					close(sockfd);
				}
				else
				{
					if (flag == 2 || flag == 3 || flag == 4)
					{
						// syn, fin, xmas in functie de flaguri


						dest_ip.s_addr = inet_addr(args->host);

						int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
						if (s < 0)
						{
							printf("Error creating socket. Error number : %d . Error message : %s \n", errno, strerror(errno));
							exit(0);
						}
						else
						{
							printf("Socket created.\n");
						}
						char datagram[4096];
						memset(datagram, 0, 4096);
						struct iphdr *iph = (struct iphdr *)datagram;
						struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));

						struct pseudo_header psh;
						struct sockaddr_in dest;

						char *target = args->host; // adica hostnameul sau ip-ul adica args->host
						int source_port = 43591;

						char source_ip[20];
						get_local_ip(source_ip); // asta il populeaza pe source_ip.

						printf("Local source IP is %s \n", source_ip);

						memset(datagram, 0, 4096); /* zero out the buffer */

						iph->ihl = 5;
						iph->version = 4;
						iph->tos = 0;
						iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
						iph->id = htons(54321); // Id of this packet
						iph->frag_off = htons(16384);
						iph->ttl = 64;
						iph->protocol = IPPROTO_TCP;
						iph->check = 0;					   // Set to 0 before calculating checksum
						iph->saddr = inet_addr(source_ip); // Spoof the source ip address
						iph->daddr = dest_ip.s_addr;

						iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);

						// TCP Header
						tcph->source = htons(source_port);
						tcph->dest = htons(port);
						tcph->seq = htonl(1105024978);
						tcph->ack_seq = 0;
						tcph->doff = sizeof(struct tcphdr) / 4; // Size of tcp header
						tcph->fin = args->tcp_flags[0];
						tcph->syn = args->tcp_flags[1];
						tcph->rst = args->tcp_flags[2];
						tcph->psh = args->tcp_flags[3];
						tcph->ack = args->tcp_flags[4];
						tcph->urg = args->tcp_flags[5];
						tcph->window = htons(14600);
						tcph->check = 0;
						tcph->urg_ptr = 0;

						int one = 1;
						const int *val = &one;

						if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
						{
							printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
							exit(0);
						}

						printf("Starting sniffer thread...\n");
						char *message1 = "Thread 1";
						int iret1;
						pthread_t sniffer_thread;

						if (pthread_create(&sniffer_thread, NULL, receive_ack, (void *)message1) < 0)
						{
							printf("Could not create sniffer thread. Error number : %d . Error message : %s \n", errno, strerror(errno));
							exit(0);
						}

						printf("Starting to send syn packets\n");

						int port;
						dest.sin_family = AF_INET;
						dest.sin_addr.s_addr = dest_ip.s_addr;

						tcph->dest = htons(port);
						tcph->check = 0;

						psh.source_address = inet_addr(source_ip);
						psh.dest_address = dest.sin_addr.s_addr;
						psh.placeholder = 0;
						psh.protocol = IPPROTO_TCP;
						psh.tcp_length = htons(sizeof(struct tcphdr));

						memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

						tcph->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));
						// Send the packet
						if (sendto(s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
						{
							printf("Error sending syn packet. Error number : %d . Error message : %s \n", errno, strerror(errno));
							exit(0);
						}

						pthread_join(sniffer_thread, NULL);
						printf("%d", iret1);
					}
				}
			}
			else if (strcmp(args->scan_type, "UDP") == 0)
			{
				if (flag == 5)
				{
					int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
					if (sockfd < 0)
					{
						printf("Eroare socket UDP.\n");
					}
					struct sockaddr_in addr;
					bzero((char *)&addr, sizeof(addr));
					addr.sin_family = AF_INET;
					addr.sin_port = htons(port);
					addr.sin_addr.s_addr = inet_addr(args->host);

					struct timeval tv;
					tv.tv_sec = args->timeout;
					tv.tv_usec = 0;
					setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&args->timeout, sizeof(tv));

					int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
					if (ret >= 0)
					{

						struct servent *s = getservbyport(htons(port), "udp");
						if (s && args->verbose == 1)
							printf("PORT: %d\tSTARE: OPEN SERVICE:%s\t PROTOCOL:%s\t\n", port, s->s_name, s->s_proto);
						else if (s && args->verbose == 0)
							printf("PORT: %d\tSTARE: OPEN \n", port);
					}

					close(sockfd);
				}
				else if (flag == 0)
				{
					printf("Nu poti selecta flaguri pentru acest tip de scanare.\n");
					exit(-1);
				}
			}
			else
			{
				printf("Tip de scanare necunoscut");
				exit(-1);
			}
		}
	}
}

void create_thread(struct arguments user_args)
{
	int thread_id;
	pthread_t threads[user_args.no_threads];
	struct thread_options opt[user_args.no_threads];

	// Creare thread-uri
	for (thread_id = 0; thread_id < user_args.no_threads; thread_id++)
	{
		opt[thread_id].thread_id = thread_id;
		opt[thread_id].start = user_args.start_port + 1 + (user_args.end_port - user_args.start_port) / user_args.no_threads * thread_id;
		opt[thread_id].end = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.no_threads * (thread_id + 1);
		opt[thread_id].excluded_ports = user_args.excluded_ports;
		opt[thread_id].excluded_ports_count = user_args.excluded_ports_count;
		opt[thread_id].fast = user_args.fast;
		strcpy(opt[thread_id].host, user_args.host);
		opt[thread_id].randomize = user_args.randomize;
		opt[thread_id].timeout = user_args.timeout;
		strcpy(opt[thread_id].scan_type, user_args.scan_type);
		opt[thread_id].verbose = user_args.verbose;
		strcpy(opt[thread_id].file_to_output, user_args.file_to_output);
		opt[thread_id].flag = user_args.flag;

		for (int i = 0; i < 7; i++)
			opt[thread_id].tcp_flags[i] = user_args.tcp_flags[i];

		if (pthread_create(&threads[thread_id], NULL, scan_thread, &opt[thread_id]))
		{
			printf("Eroare creare thread\n");
			exit(-1);
		}
	}

	printf("--> Created %d threads.\n", user_args.no_threads);

	for (thread_id = 0; thread_id < user_args.no_threads; thread_id++)
	{
		pthread_join(threads[thread_id], NULL);
	}
}

void test_output_file(int *fd, int *rc, char *filename)
{

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC);
	if (fd < 0)
	{
		printf("Eroare deschidere fisier.\n");
		exit(-1);
	}

	rc = dup2(fd, 1);
	if (rc < 0)
	{
		printf("eroare file descriptor.\n");
		exit(-1);
	}
}

void set_tcp_flags(int *flags, int *flag)
{
	if (flags[0] == 0 && flags[1] == 0 && flags[2] == 0 && flags[3] == 0 && flags[4] == 0 && flags[5] == 0)
	{
		printf("Scanning with TCPConnect.\n");
		flag = 1;
	}
	else if (flags[0] == 0 && flags[1] == 1 && flags[2] == 0 && flags[3] == 0 && flags[4] == 0 && flags[5] == 0)
	{
		printf("Scanning with SYN.\n");
		flag = 2;
	}
	else if (flags[0] == 1 && flags[1] == 0 && flags[2] == 0 && flags[3] == 0 && flags[4] == 0 && flags[5] == 0)
	{
		printf("Scanning with FIN.\n");
		flag = 3;
	}
	else if (flags[0] == 1 && flags[1] == 0 && flags[2] == 0 && flags[3] == 1 && flags[4] == 0 && flags[5] == 1)
	{
		printf("Scanning with XMAS.\n");
		flag = 4;
	}
	else
	{
		printf("Tip de scanare necunoscut\n");
		return 0;
	}
}

void input_file_parse(FILE *f, arguments *args)
{
	struct hostent *target;
	char *buffer = (char *)malloc(sizeof(char) * 256);
	fread(buffer, 1, 256, f);
	char *p = strtok(buffer, " \n");
	while (p)
	{
		strcpy(args->host, p);
		target = gethostbyname(args->host);

		bzero(args->host, sizeof(args->host));
		strcpy(args->host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));

		printf("Scanning %s\n", args->host);
		arguments ar = *args;
		create_thread(ar);

		p = strtok(NULL, " \n");
	}

	free(p);
	free(buffer);
}

int main(int argc, char *argv[])
{
	struct arguments user_args;
	user_args = parse_args(argc, argv);

	struct hostent *target;
	int rc, fd;

	// daca optiunea -o e setata = scriem outputul intr-un fisier
	if (strlen(user_args.file_to_output) != 0)
	{
		test_output_file(&fd, &rc, &(user_args.file_to_output));
	}

	// setare scan-type

	if (strcmp(user_args.scan_type, "TCP") == 0)
	{ // daca e scanare de tip tcp
		set_tcp_flags(user_args.tcp_flags, &(user_args.flag));
	}
	else if (strcmp(user_args.scan_type, "UDP") == 0)
	{
		if (user_args.tcp_flags[0] == 0 && user_args.tcp_flags[1] == 0 && user_args.tcp_flags[2] == 0 && user_args.tcp_flags[3] == 0 && user_args.tcp_flags[4] == 0 && user_args.tcp_flags[5] == 0)
		{
			printf("Scanning with UDP.\n");
			user_args.flag = 5;
		}
	}
	else
	{
		printf("Tip de scanare necunoscut.\n");
		exit(-1);
	}

	// daca luam hostnames si adrese ip dintr-un fisier adica optiunea -i e setata:
	if (strlen(user_args.file_to_input) == 0)
	{
		if (strlen(user_args.host) == 0)
		{
			printf("Introduceti hostname/ip.\n");
			return 0;
		}

		target = gethostbyname(user_args.host); // transformare nume de domeniu in adresa ip

		bzero(user_args.host, sizeof(user_args.host)); // face user_args->host 0 ca sa-l populez cu formatul ascii al adresei ip date
		strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));

		printf("Scanning %s\n", user_args.host);
		create_thread(user_args); // creare thread-uri
	}

	else
	{
		FILE *f = fopen(user_args.file_to_input, "r");
		if (f == NULL)
		{
			printf("Eroare deschidere fisier citire '%s'!\n", user_args.file_to_input);
			fclose(f);
			return 0;
		}

		// parsare continut fisier

		input_file_parse(f, &user_args);
	}

	rc = close(fd);
	return 0;
}
