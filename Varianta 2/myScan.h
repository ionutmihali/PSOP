struct thread_options {
	char host[INET_ADDRSTRLEN]; //inet_addrstrlen = 16
	int port;
	int timeout;
	pthread_t thread_id;
	int start;
	int end;
};

int myScan_error(const char *s, int sock);

void *worker(void *thread_args);

int scanner(const char * host, int *port, int timeout, int *start, int *end);
