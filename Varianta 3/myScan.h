struct thread_options {
	char host[INET_ADDRSTRLEN]; //inet_addrstrlen = 16
	int port;
	pthread_t thread_id;
    int timeout;                // timeout pentru fiecare port
    int threads;                // numar de thread-uri
    char file_to_output[30];    // fisier de output
    char file_to_input[30];     // fisier de input
    int start;             // port inceput range
    int end;               // port sfarsit range
    char scan_type[10];         // tipul scanarii: SYN, ACK, FIN, XMAS, NULL
    int verbose;                // verbose
    int randomize;              // scanarea porturilor in ordine aleatoare
    int fast;                   // scanare rapida
    int *excluded_ports;        // range de porturi excluse de la scanare
    int excluded_ports_count;
    char tcp_flags[7]; // TCP flags la scanare
    int flag;
};

int myScan_error(const char *s, int sock);
