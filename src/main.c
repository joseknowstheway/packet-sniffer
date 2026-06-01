/*
 * main.c — entry point.
 *
 * Argument parsing now lives in filter.c (parse_args), which understands both
 * the interface flag (-i) and the filter flags (--proto, --port, --host). main
 * just wires the parsed config into the capture engine.
 */

#include "capture.h"
#include "filter.h"

#include <locale.h> /* setlocale — enables %' thousands grouping in stats */

int main(int argc, char *argv[])
{
    /* Adopt the environment's locale so large numbers print with separators. */
    setlocale(LC_ALL, "");

    app_config_t cfg;
    parse_args(argc, argv, &cfg);

    return start_capture(&cfg);
}
