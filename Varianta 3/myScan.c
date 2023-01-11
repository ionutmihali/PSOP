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

#include "myScan.h"
#include "arg_parse.h"

typedef struct arguments arguments;

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

		int skip = 0;
		for (int j = 0; j < args->excluded_ports_count; j++)
		{
			if (args->excluded_ports[j] == port)
			{
				skip = 1;
				break;
			}
		}

		if (skip == 0)
		{
			if (strcmp(args->scan_type, "TCP") == 0)
			{
				if (flag == 1)
				{
					int sockfd = socket(AF_INET, SOCK_STREAM, 0);
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

					int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
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
					if (flag == 2 || flag==3 || flag==4)
					{
						// syn, fin, xmas in functie de flaguri
						// TO DO
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
	pthread_t threads[user_args.threads];
	struct thread_options opt[user_args.threads];

	// Creare thread-uri
	for (thread_id = 0; thread_id < user_args.threads; thread_id++)
	{
		opt[thread_id].thread_id = thread_id;
		opt[thread_id].start = user_args.start_port + 1 + (user_args.end_port - user_args.start_port) / user_args.threads * thread_id;
		opt[thread_id].end = user_args.start_port + (user_args.end_port - user_args.start_port) / user_args.threads * (thread_id + 1);
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

	printf("--> Created %d threads.\n", user_args.threads);

	for (thread_id = 0; thread_id < user_args.threads; thread_id++)
	{
		pthread_join(threads[thread_id], NULL);
	}
}

int main(int argc, char *argv[])
{
	struct arguments user_args;
	struct hostent *target;
	int rc, fd;

	user_args = parse_args(argc, argv);

	if (strlen(user_args.file_to_output) != 0)
	{
		fd = open(user_args.file_to_output, O_RDWR | O_CREAT | O_TRUNC);
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

	if (strcmp(user_args.scan_type, "TCP") == 0)
	{
		if (user_args.tcp_flags[0] == 0 && user_args.tcp_flags[1] == 0 && user_args.tcp_flags[2] == 0 && user_args.tcp_flags[3] == 0 && user_args.tcp_flags[4] == 0 && user_args.tcp_flags[5] == 0)
		{
			printf("Scanning with TCPConnect.\n");
			user_args.flag = 1;
		}
		else if (user_args.tcp_flags[0] == 0 && user_args.tcp_flags[1] == 1 && user_args.tcp_flags[2] == 0 && user_args.tcp_flags[3] == 0 && user_args.tcp_flags[4] == 0 && user_args.tcp_flags[5] == 0)
		{
			printf("Scanning with SYN.\n");
			user_args.flag = 2;
		}
		else if (user_args.tcp_flags[0] == 1 && user_args.tcp_flags[1] == 0 && user_args.tcp_flags[2] == 0 && user_args.tcp_flags[3] == 0 && user_args.tcp_flags[4] == 0 && user_args.tcp_flags[5] == 0)
		{
			printf("Scanning with FIN.\n");
			user_args.flag = 3;
		}
		else if (user_args.tcp_flags[0] == 1 && user_args.tcp_flags[1] == 0 && user_args.tcp_flags[2] == 0 && user_args.tcp_flags[3] == 1 && user_args.tcp_flags[4] == 0 && user_args.tcp_flags[5] == 1)
		{
			printf("Scanning with XMAS.\n");
			user_args.flag = 4;
		}
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

	if (strlen(user_args.file_to_input) == 0)
	{
		if (strlen(user_args.host) == 0)
		{
			printf("Introduceti hostname/ip.\n");
			return 0;
		}

		// Resolve hostname
		target = gethostbyname(user_args.host); // transformare nume de domeniu in adresa ip

		bzero(user_args.host, sizeof(user_args.host)); // face user_args->host 0

		strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
		printf("Scanning %s\n", user_args.host);
		create_thread(user_args);
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

		char *buffer = (char *)malloc(sizeof(char) * 256);
		fread(buffer, 1, 256, f);
		char *p = strtok(buffer, " \n");
		while (p)
		{
			strcpy(user_args.host, p);
			target = gethostbyname(user_args.host);

			bzero(user_args.host, sizeof(user_args.host));

			// Copy to struct with typecasting
			strcpy(user_args.host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
			printf("Scanning %s\n", user_args.host);
			create_thread(user_args);

			p = strtok(NULL, " \n");
		}

		free(p);
		free(buffer);
	}

	rc = close(fd);
	return 0;
}
