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

/*Functie pentru aflarea IP-ului propriu*/
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

/*Afisare stare porturi, in functie de tipul de protocol*/
void display_port_status(int port, int v, char *type)
{
	if (v == 1)
	{
		struct servent *s = getservbyport(htons(port), type);
		if (s && port < 1024)
			printf("PORT: %d\tSTARE: OPEN SERVICE:%s\t PROTOCOL:%s\t\n", port, s->s_name, s->s_proto);
		else if (port > 1024)
		{
			printf("PORT: %d\tSTARE: OPEN \n", port);
		}
	}
	else
	{
		printf("PORT: %d\tSTARE: OPEN \n", port);
	}
}

/*Scanarea porturilor, cu ajutorul threadurilor.*/
void *scan_thread(void *arg)
{
	struct thread_options *args = (struct thread_options *)arg;
	int ports[300];
	int flag = args->flag;
	for (int i = 0; i < args->end - args->start + 1; i++)
	{
		ports[i] = args->start + i;
	}

	/*randomize*/
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
			sleep(0);
		}
		else if (args->fast == 0)
		{
			sleep(1);
		}

		int port = ports[i];

		/*sarim peste porturile specificate in excluded_ports*/
		int skip = 0;
		for (int j = 0; j < args->excluded_ports_count; j++)
		{
			if (args->excluded_ports[j] == port)
			{
				skip = 1;
				break;
			}
		}
		/*daca nu exista porturi in excluded_ports*/
		if (skip == 0)
		{
			if (strcmp(args->scan_type, "TCP") == 0) /*daca scanarea e de tip TCP*/
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

					int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)); /*aici facem conectarea efectiva la port*/
					if (ret >= 0)
					{
						display_port_status(port, args->verbose, "tcp");
					}

					close(sockfd);
				}
				else
				{

					if (flag == 2 || flag == 3 || flag == 4)
					{
						/*syn, fin, xmas in functie de flaguri*/
						int sockfd;
						struct iphdr *ip_header;
						struct tcphdr *tcp_header;
						char packet[5000];

						sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

						char source_ip[20];
						get_local_ip(source_ip); /*aflare IP propriu*/

						/*IP header*/
						ip_header = (struct iphdr *)packet;
						ip_header->ihl = 5;
						ip_header->version = 4;
						ip_header->tos = 0;
						ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
						ip_header->id = htons(54321);
						ip_header->frag_off = 0;
						ip_header->ttl = 255;
						ip_header->protocol = IPPROTO_TCP;
						ip_header->check = 0;
						ip_header->saddr = inet_addr(source_ip);
						ip_header->daddr = inet_addr(args->host);

						/*TCP header*/
						tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
						tcp_header->source = htons(2500);
						tcp_header->dest = htons(port);
						tcp_header->seq = random();
						tcp_header->ack_seq = 0;
						tcp_header->doff = 5;
						tcp_header->syn = args->tcp_flags[1];
						tcp_header->ack = args->tcp_flags[4];
						tcp_header->fin = args->tcp_flags[0];
						tcp_header->psh = args->tcp_flags[3];
						tcp_header->rst = args->tcp_flags[2];
						tcp_header->urg = args->tcp_flags[5];
						tcp_header->window = htons(5840);
						tcp_header->check = 0;
						tcp_header->urg_ptr = 0;

						struct sockaddr_in dest;
						memset(&dest, 0, sizeof(dest));
						dest.sin_family = AF_INET;
						dest.sin_port = htons(port);
						dest.sin_addr.s_addr = inet_addr(args->host);

						/*Trimitere packet*/
						if (sendto(sockfd, packet, ip_header->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
						{
							printf("Error: sendto() failed.\n");
							close(sockfd);
							return 1;
						}

						printf("Packet sent.\n");

						/*Asteptare raspuns*/
						fd_set read_fds;
						struct timeval timeout;
						int ret;

						FD_ZERO(&read_fds);
						FD_SET(sockfd, &read_fds);

						timeout.tv_sec = 15;
						timeout.tv_usec = 0;

						ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

						if (ret == 0)
						{
							printf("Error: Timeout waiting for response.\n");
							close(sockfd);
							return 1;
						}
						else if (ret < 0)
						{
							printf("Error: select() failed.\n");
							close(sockfd);
							return 1;
						}

						/*Primire raspuns*/
						char recv_buf[1024];
						struct sockaddr_in recv_src;
						socklen_t recv_src_len;
						int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&recv_src, &recv_src_len);

						if (recv_len < 0)
						{
							printf("Error: recvfrom() failed.\n");
							close(sockfd);
							return 1;
						}

						/*Verificam daca pachetul primit este ceea ce ne dorim*/
						ip_header = (struct iphdr *)recv_buf;
						tcp_header = (struct tcphdr *)(recv_buf + sizeof(struct iphdr));

						if (flag == 2)
						{
							if (tcp_header->syn == 1 && tcp_header->ack == 1)
							{
								display_port_status(port, args->verbose, "tcp");
							}
							else
							{
								printf("Error: Invalid SYN-ACK response.\n");
								close(sockfd);
								return 1;
							}
						}
						else if (flag == 3)
						{
							if (tcp_header->fin == 1 && tcp_header->ack == 1)
							{
								display_port_status(port, args->verbose, "tcp");
							}
							else
							{
								printf("Error: Invalid FIN-ACK response.\n");
								close(sockfd);
								return 1;
							}
						}
						else if (flag == 4)
						{
							if (tcp_header->rst == 1 && tcp_header->ack == 1)
							{
								display_port_status(port, args->verbose, "tcp");
							}
							else
							{
								printf("Error: Invalid XMAS response.\n");
								close(sockfd);
								return 1;
							}
						}

						close(sockfd);
						return 0;
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
						display_port_status(port, args->verbose, "udp");
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

/*Creare threaduri si asignarea lor pe un anumit numar de porturi, proportional cu numarul de threaduri.
Popularea structurii thread_options.*/
void create_thread(struct arguments user_args)
{
	int thread_id, check = 0;
	pthread_t threads[user_args.no_threads];
	struct thread_options opt[user_args.no_threads];

	/*Creare thread-uri*/
	for (thread_id = 0; thread_id < user_args.no_threads; thread_id++)
	{
		opt[thread_id].thread_id = thread_id;
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

		if (user_args.end_port == user_args.start_port)
		{
			opt[thread_id].start = user_args.start_port;
			opt[thread_id].end = user_args.start_port;
			check = 1;
		}
		else
		{
			opt[thread_id].start = user_args.start_port + 1 + (user_args.end_port - user_args.start_port) / user_args.no_threads * thread_id;
			opt[thread_id].end = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.no_threads * (thread_id + 1);
			check = user_args.no_threads;
		}

		if (pthread_create(&threads[thread_id], NULL, scan_thread, &opt[thread_id]))
		{
			printf("Eroare creare thread\n");
			exit(-1);
		}

		if (check == 1)
		{
			thread_id = user_args.no_threads;
		}
	}

	printf("--> Created %d threads.\n", check);

	for (thread_id = 0; thread_id < check; thread_id++)
	{
		pthread_join(threads[thread_id], NULL);
	}
}

/*Daca exista un fisier de iesire dat ca parametru, il deschidem cu ajutorul unui descriptor de fisier.*/
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
		printf("Eroare file descriptor.\n");
		exit(-1);
	}
}

/*Parsare flaguri TCP*/
void set_tcp_flags(int *flags, int *flag)
{
	if (flags[0] == 0 && flags[1] == 0 && flags[2] == 0 && flags[3] == 0 && flags[4] == 0 && flags[5] == 0)
	{
		printf("Scanning with TCPConnect.\n");
		*flag = 1;
	}
	else if (flags[0] == 0 && flags[1] == 1 && flags[2] == 0 && flags[3] == 0 && flags[4] == 0 && flags[5] == 0)
	{
		printf("Scanning with SYN.\n");
		*flag = 2;
	}
	else if (flags[0] == 1 && flags[1] == 0 && flags[2] == 0 && flags[3] == 0 && flags[4] == 0 && flags[5] == 0)
	{
		printf("Scanning with FIN.\n");
		*flag = 3;
	}
	else if (flags[0] == 1 && flags[1] == 0 && flags[2] == 0 && flags[3] == 1 && flags[4] == 0 && flags[5] == 1)
	{
		printf("Scanning with XMAS.\n");
		*flag = 4;
	}
	else
	{
		printf("Tip de scanare necunoscut\n");
		return 0;
	}
}

/*Daca exista un fisier de input, parsam IP-urile/hostname-urile*/
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

/*Parsam argumentele programului, cu ajutorul header-ului argv_parse.h
si interpretam argumentele date*/
int main(int argc, char *argv[])
{
	struct arguments user_args;
	user_args = parse_args(argc, argv);

	struct hostent *target;
	int rc, fd;

	/*daca optiunea -o e setata = scriem outputul intr-un fisier*/
	if (strlen(user_args.file_to_output) != 0)
	{
		test_output_file(&fd, &rc, &(user_args.file_to_output));
	}

	/*setare scan-type*/
	if (strcmp(user_args.scan_type, "TCP") == 0)
	{ 
		/*daca e scanare de tip tcp*/
		set_tcp_flags(&(user_args.tcp_flags), &(user_args.flag));
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

	/*daca luam hostnames si adrese ip dintr-un fisier adica optiunea -i e setata:*/
	if (strlen(user_args.file_to_input) == 0)
	{
		if (strlen(user_args.host) == 0)
		{
			printf("Introduceti hostname/ip.\n");
			return 0;
		}

		target = gethostbyname(user_args.host); /*transformare nume de domeniu in adresa ip*/

		bzero(user_args.host, sizeof(user_args.host)); /*face user_args->host 0 ca sa-l populez cu formatul ascii al adresei ip date*/
		strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));

		printf("Scanning %s\n", user_args.host);
		create_thread(user_args); /*creare thread-uri*/
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

		/*parsare continut fisier*/
		input_file_parse(f, &user_args);
	}

	rc = close(fd);
	return 0;
}
