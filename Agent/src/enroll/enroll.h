#ifndef IG_ENROLL_H
#define IG_ENROLL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *host;
    uint16_t    port;
    const char *ca_crt;
    const char *agent_crt;
    const char *agent_key;
    const char *enrollment_id;
    const char *xor_key;
    const char *hostname;
    const char *ip;
    const char *os;
    uint8_t     monitor_type;
} ig_enroll_config_t;

int ig_enroll_needed(const char *agent_crt, const char *agent_key);
int ig_enroll_execute(const ig_enroll_config_t *cfg);
void ig_secure_bzero(void *p, size_t n);

#endif /* IG_ENROLL_H */
