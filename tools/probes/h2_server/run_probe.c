#include "probe.h"

extern const struct aura_h2_probe_scenario_group preface_scenarios;
extern const struct aura_h2_probe_scenario_group headers_scenarios;
extern const struct aura_h2_probe_scenario_group continuation_scenarios;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <service/port>\n", argv[0]);
        return -1;
    }

    /* Connection preface */
    app_debug(false, 0, "========== %s ==========", preface_scenarios.name);
    for (int i = 0; i < (int)preface_scenarios.scenario_cnt; ++i) {
        app_debug(false, 0, "%d) %s", i + 1, preface_scenarios.scenarios[i].name);
        preface_scenarios.scenarios[i].scenario_fn(argv[1], argv[2]);
    }

    /* Headers */
    app_debug(false, 0, "========== %s ==========", headers_scenarios.name);
    for (int i = 0; i < (int)headers_scenarios.scenario_cnt; ++i) {
        app_debug(false, 0, "%d) %s", i + 1, headers_scenarios.scenarios[i].name);
        headers_scenarios.scenarios[i].scenario_fn(argv[1], argv[2]);
    }

    /* Continuation */
    app_debug(false, 0, "========== %s ==========", continuation_scenarios.name);
    for (int i = 0; i < (int)continuation_scenarios.scenario_cnt; ++i) {
        app_debug(false, 0, "%d) %s", i + 1, continuation_scenarios.scenarios[i].name);
        continuation_scenarios.scenarios[i].scenario_fn(argv[1], argv[2]);
    }
}