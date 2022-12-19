
#include <argp.h>
#include <stdlib.h>
#include <error.h>

struct arguments
{
    char host[INET_ADDRSTRLEN]; // hostname sau IP 
    int timeout;                // timeout pentru fiecare port
    char file_to_output[30];    // fisier de output
    char file_input[30];        // fisier de input
    int menu;
};

struct argp_option options[] = {
    {"host", 'h', "HOST", 0, "Target host to scan"},
    {"timeout", 't', "SECONDS", 0, "Speed of scanning/seconds of timeout."},
    {"output", 'o', "FILE", 0, "Output to FILE instead of standard output"},
    {"input", 'i', "FILE", 0, "Input from FILE instead of standard input"},
    {0}};

char doc[] =
    "myScan is a port scanner application that is intended to show some logic behind port scanning.\n";

char args_doc[] = "";

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'h':
        strncpy(arguments->host, arg, (size_t)INET_ADDRSTRLEN);
        break;
    case 't':
        // printf("%s", arg);
        arguments->timeout = atoi(arg);
        break;
    case 'o':
        strncpy(arguments->file_to_output, arg, 30);
        break;
    case 'i':
        strncpy(arguments->file_input, arg, 30);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, args_doc, doc};

struct arguments *parse_args(int argc, char *argv[])
{
    static struct arguments args;
    int i = argp_parse(&argp, argc, argv, 0, 0, &args);
    return &args;
}
