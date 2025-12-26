#ifndef AURA_H2_SCHEDULER
#define AURA_H2_SCHEDULER

#include "h2/connection.h"

/**
 * Select the next frame to transmit based on the
 * some prefered criteria
 */
struct aura_h2_out_frame *aura_schedule_next_frame(struct aura_h2_sender_engine *engine);

#endif