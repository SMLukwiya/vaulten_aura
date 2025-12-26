#ifndef AURA_CLI_FLAG_H
#define AURA_CLI_FLAG_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    CLI_FLAG_STRING,
    CLI_FLAG_BOOL,
    CLI_FLAG_INT,
    CLI_FLAG_FLOAT
} aura_flag_type_t;

struct aura_cli_flag {
    char short_name;
    char *name;
    char *description;
    char *default_value;
    char *deprecated;
    aura_flag_type_t type;
    bool is_hidden;
    bool is_required;
    bool is_set;
    size_t offset_in_option;
};

extern struct aura_cli_flag version_flag;
extern struct aura_cli_flag help_flag;
// extern struct aura_cli_flag path_flag;

#endif