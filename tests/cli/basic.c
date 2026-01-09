#include <assert.h>
#include <stdlib.h>

static void a_test_system_lifecycle() {
    char *system_start, *system_status, *system_stop;
    int res, status;

    system_start = "aura system start -p";
    system_status = "aura system status";
    system_stop = "aura system stop";
    /**/

    return 0;
}

static void a_test_invalid_commands() {}

int main(int argc, char **argv) {
    a_test_system_lifecycle();

    return 0;
}