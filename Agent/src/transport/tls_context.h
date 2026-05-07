#ifndef IG_TLS_CONTEXT_H
#define IG_TLS_CONTEXT_H

#include <openssl/ssl.h>

typedef struct {
    SSL_CTX *ctx;
} ig_tls_ctx_t;

/* CA 인증서 + 클라이언트 인증서 + 개인키로 mTLS SSL_CTX 초기화 */
int  tls_context_init(ig_tls_ctx_t *out,
                      const char *ca_crt,
                      const char *agent_crt,
                      const char *agent_key);

SSL *ig_tls_wrap(ig_tls_ctx_t *ctx, int fd);

void tls_context_free(ig_tls_ctx_t *ctx);

#endif /* IG_TLS_CONTEXT_H */
