// SPDX-License-Identifier: Apache-2.0
/** Runs the authenticator core as a process that speaks CTAPHID packets on stdin/stdout. */
#include "fido.h"

#include <stdlib.h>

bool hal_host_eof(void);

int main(void) {
    const char* up_timeout = getenv("PASSKEY_UP_TIMEOUT_MS");
    fido_init();
    if (up_timeout != NULL) {
        fido_set_up_timeout_ms((uint32_t)atoi(up_timeout));
    }
    while (!hal_host_eof()) {
        fido_poll(100);
    }
    return 0;
}
