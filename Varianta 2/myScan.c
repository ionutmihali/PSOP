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

#define MAX_THREADS 2 // Total thread-uri

int myScan_error(const char *s, int sock)
{
#ifdef DEBUGING
	perror(s);
#endif
	if (sock)
		close(sock);
	return 0;
}

int scanner(const char *host, int *port, int timeout, int *start, int *end)
{
	// connect to target information
	struct sockaddr_in address;
	struct sockaddr_in bind_addr;

	// timeout information
	struct timeval time;
	fd_set write_fds;
	socklen_t error_len;

	int sd;
	int write_permission;
	int error = 1;
	int ok = 1;

	while (!*start)
	{
		sleep(2); // asteapta 2s
	}

	while (!*end)
	{
		// asteapta 2 secunde
		while (*port == 0)
		{
			sleep(2);
		}
		address.sin_family = AF_INET;			   //  AF_INET = IP protocol family = 2
		address.sin_addr.s_addr = inet_addr(host); // inet_addr() transforma stringul dat de o adresa IP (de la tastatura) intr-o
												   // adresa IP folosibila/care are sens
		address.sin_port = htons(*port);		   // htons() => big endian

		// nr secunde pana la timeout
		time.tv_sec = timeout;

		// nr microsecunde pana la timeout
		// time.tv_usec = 0;

		FD_ZERO(&write_fds);

		error_len = sizeof(error);

		// Creare socket
		if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			return myScan_error("socket() An error has occurred", 0);

		if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &ok, sizeof(int)) == -1)
			return myScan_error("setsockopt() An error has occured", 0);

		// Facem socketul neblocant <=> daca nu se opreste aplicatia pana nu se face conexiunea buna
		if (fcntl(sd, F_SETFL, O_NONBLOCK) == -1)
			return myScan_error("fcntl() caused error", 1);
		;

		// connect() returneaza -1 mereu pt ca am pus flagul O_NONBLOCK
		if (connect(sd, (struct sockaddr *)&address, sizeof(address)) == -1)
		{
			switch (errno)
			{
			case EWOULDBLOCK:
			case EINPROGRESS:
				break;
			default:
				return myScan_error("connect() An error has occurred", sd);
			}
		}

		FD_SET(sd, &write_fds);


		// Scriere in socket/timeout
		if ((write_permission = select(sd + 1, NULL, &write_fds, NULL, &time)) == -1)
			return myScan_error("select() An error has occurred", sd);

		// Serviciul si protocolul
		struct servent *s = getservbyport(htons(*port), NULL);

		// daca avem permisiune de scriere pe port
		if (write_permission)
			if (getsockopt(sd, SOL_SOCKET, error, &error, &error_len) != -1)
			{
				if (error == 0)
					printf("PORT: %d\tSTARE: OPEN \tSERVICIU: %s\tPROTOCOL: %s\n", *port, s->s_name, s->s_proto);
			}

		// Setam pe 0 ca sa nu l recunoasca de 100 de ori
		*port = 0;
	}
}

void *worker(void *thread_args) //  void * ca sa mearga pusa ca argumentul al 3-lea din pthread_create (start_routine)
{
	// options = pointer catre structura care contine toate argumentele din main
	struct thread_options *options;
	options = thread_args;

	// Scanare
	scanner(options->host, &options->port, options->timeout, &options->start, &options->end);

	// Termina threadul curent
	pthread_exit(NULL);
}

int create_thread(struct arguments *user_args)
{
	int thread_id;
	pthread_t threads[MAX_THREADS];
	struct thread_options options[MAX_THREADS];
	int port_scan = 1;

	// Creare thread-uri
	for (thread_id = 0; thread_id < MAX_THREADS; thread_id++)
	{
		options[thread_id].start = 0;
		options[thread_id].end = 0;
		options[thread_id].port = 0;
		options[thread_id].timeout = user_args->timeout;
		options[thread_id].thread_id = thread_id;
		strncpy(options[thread_id].host, user_args->host, (size_t)INET_ADDRSTRLEN);

		if (pthread_create(&threads[thread_id], NULL, worker, (void *)&options[thread_id]))
		{
#ifdef DEBUGING
			perror("pthread_create() error");
#endif
			return EXIT_FAILURE;
		}
	}

	thread_id = 0;
	printf("--> Created %d threads.\n", MAX_THREADS);

	while (port_scan < 65535)
	{
		for (int i = 0; i < MAX_THREADS; i++)
		{
			if (options[i].port == 0)
			{
				options[i].port = port_scan;
				port_scan++;
				options[i].start = 1;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct arguments *user_args;
	struct hostent *target;

	user_args = parse_args(argc, argv);

	if (strlen(user_args->file_input) == 0)
	{
		if (strlen(user_args->host) == 0)
		{
			printf("Please provide a hostname");
			return 0;
		}

		// Resolve hostname
		//while(!target) retry translating the target
		target = gethostbyname(user_args->host); // transformare nume de domeniu in adresa ip

		bzero(user_args->host, sizeof(user_args->host)); // face user_args->host 0

		strcpy(user_args->host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
		printf("Scanning %s\n", user_args->host);
		create_thread(user_args);
	}
	else
	{
		FILE *f = fopen(user_args->file_input, "r");
		if (f == NULL)
		{
			printf("Error on openning '%s'!\n", user_args->file_input);
			fclose(f);
			return 0; // Ies din program.
		}

		char *buffer = (char *)malloc(sizeof(char) * 256);
		fread(buffer, 1, 256, f);
		char *p = strtok(buffer, " \n");
		while (p)
		{
			strcpy(user_args->host, p);
			target = gethostbyname(user_args->host);

			bzero(user_args->host, sizeof(user_args->host));

			// Copy to struct with typecasting
			strcpy(user_args->host, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
			printf("Scanning %s\n", user_args->host);
			create_thread(user_args);

			p = strtok(NULL, " \n");
		}

		free(p);
		free(buffer);
	}
	sleep(user_args->timeout + user_args->timeout); // Ensure all threads had done their work
}
