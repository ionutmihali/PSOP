
#include <argp.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>
#include <netdb.h>

#define DEFAULT_SCAN_TYPE "SYN"

struct arguments
{
    char host[INET_ADDRSTRLEN]; // hostname sau IP
    int timeout;                // timeout pentru fiecare port
    int no_threads;                // numar de thread-uri
    char file_to_output[30];    // fisier de output
    char file_to_input[30];     // fisier de input
    int start_port;             // port inceput range
    int end_port;               // port sfarsit range
    char scan_type[10];         // tipul scanarii: SYN, ACK, FIN, XMAS, NULL
    int verbose;                // verbose
    int randomize;              // scanarea porturilor in ordine aleatoare
    int fast;                   // scanare rapida
    int *excluded_ports;        // range de porturi excluse de la scanare
    int excluded_ports_count;
    int tcp_flags[7]; // TCP flags la scanare
    int flag;         
    int menu;
};

struct argp_option options[] = {
    {"host", 'h', "hostname/IPv4", 0, "Target host to scan"},
    {"timeout", 't', "SECONDS", 0, "Speed of scanning/seconds of timeout."},
    {"output", 'o', "FILE", 0, "Output to FILE instead of standard output"},
    {"input", 'i', "FILE", 0, "Input from FILE instead of standard input"},
    {"port", 'p', "PORT NUMBER:0-65535", 0, "Port range to scan"},
    {"threads", 'T', "THREADS NUMBER", 0, "Number of threads to use for the scan"},
    {"scan-type", 's', "TCP/UDP", 0, "Scan type (TCP, UDP)"},
    {"verbose", 'v', "1-verbose, 0-no verbose", 0, "Verbose mode"},
    {"random", 'r', "1-random, 0-no random", 0, "Randomize the order of the ports being scanned"},
    {"fast", 'f', "1-fast, 0-no fast", 0, "Use faster but less reliable scanning techniques"},
    {"exclude", 'e', "port/port1,port2,.../startport-endport", 0, "Exclude a range of ports from the scan"},
    {"tcp-flags", 'F', "F/S/P/R/A/U/combination:FPU", 0, "Customize the TCP flags sent during the scan: F=FIN, S=SYN, P=PUSH, R=RESET, A=ACK, U=URGENT, NULL = TCPConnect, FPU = XMAS "}, // nu
    {0}};

char doc[] =
    "myScan is a port scanner application that is intended to show some logic behind port scanning.\n";

char args_doc[] = "";

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = (struct arguments *)state->input;

    switch (key)
    {
    case 'h':
        strncpy(arguments->host, arg, (size_t)INET_ADDRSTRLEN);
        break;
    case 't':
        arguments->timeout = atoi(arg);
        break;
    case 'o':
        strncpy(arguments->file_to_output, arg, 30);
        break;
    case 'i':
        strncpy(arguments->file_to_input, arg, 30);
        break;
    case 'T':
        arguments->no_threads = atoi(arg);
        break;
    case 'p':;
        char range[20];
        strncpy(range, arg, 20);
        char *dash = strchr(range, '-');
        if (dash == NULL)
        {
            arguments->start_port = arguments->end_port = atoi(range);
        }
        else
        {
            *dash = '\0';
            arguments->start_port = atoi(range);
            arguments->end_port = atoi(dash + 1);
        }
        break;
    case 's':
        strncpy(arguments->scan_type, arg, 30);
        break;
    case 'v':
        arguments->verbose = 1;
        break;
    case 'r':
        arguments->randomize = 1;
        break;
    case 'f':
        arguments->fast = 1;
        break;
    case 'e':;
        char range1[20];
        strncpy(range1, arg, 20);
        arguments->excluded_ports_count = 1;
        for (int i = 0; range1[i] != '\0'; i++)
        {
            if (range1[i] == ',' || range1[i] == '-')
            {
                arguments->excluded_ports_count++;
            }
        }
        arguments->excluded_ports = (int *)malloc(sizeof(int) * arguments->excluded_ports_count);
        int i = 0;
        char *range_copy = strdup(range1);
        char *token = strtok(range_copy, ",");
        while (token != NULL)
        {
            char *dash = strchr(token, '-');
            if (dash == NULL)
            {
                arguments->excluded_ports[i++] = atoi(token);
            }
            else
            {
                *dash = '\0';
                int start_port = atoi(token);
                int end_port = atoi(dash + 1);
                for (int i = start_port; i <= end_port; i++)
                {
                    arguments->excluded_ports[i++] = i;
                }
            }
            token = strtok(NULL, ",");
        }
        free(range_copy);
        break;
    case 'F':;
        char flags_string[7];
        strncpy(flags_string, arg, 7);
        for (int i = 0; flags_string[i] != '\0'; i++)
        {
            switch (flags_string[i])
            {
            case 'F': // FIN
                arguments->tcp_flags[0] = 1;
                break;
            case 'S': // SYN
                arguments->tcp_flags[1] = 1;
                break;
            case 'R': // RESET
                arguments->tcp_flags[2] = 1;
                break;
            case 'P': // PUSH
                arguments->tcp_flags[3] = 1;
                break;
            case 'A': // ACK
                arguments->tcp_flags[4] = 1;
                break;
            case 'U': // urgent
                arguments->tcp_flags[5] = 1;
                break;
            default:
                fprintf(stderr, "Error: invalid TCP flag '%c'\n", flags_string[i]);
                return 1;
            }
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp argp = {options, parse_opt, args_doc, doc};

struct arguments parse_args(int argc, char *argv[])
{
    static struct arguments arguments;
    strcpy(arguments.host, "");
    arguments.timeout = 3;
    arguments.no_threads = 5;
    arguments.start_port = 1;
    strcpy(arguments.scan_type, "TCP");
    arguments.end_port = 1024;
    arguments.verbose = 0;
    arguments.randomize = 0;
    arguments.fast = 0;
    strcpy(arguments.file_to_output, "");
    strcpy(arguments.file_to_input, "");
    arguments.excluded_ports = NULL;
    arguments.excluded_ports_count = 0;
    for (int i = 0; i < 7; i++)
    {
        arguments.tcp_flags[i] = 0;
    }
    arguments.flag = 1;

    int i = argp_parse(&argp, argc, argv, 0, 0, &arguments);
    return arguments;
}