#ifndef IM_TLS_CONTEXT_H
#define IM_TLS_CONTEXT_H

#include <openssl/ssl.h>

typedef struct {
    SSL_CTX *ctx;
} im_tls_ctx_t;

/* CA 인증서 + 클라이언트 인증서 + 개인키로 mTLS SSL_CTX 초기화 */
int  tls_context_init(im_tls_ctx_t *out,
                      const char *ca_crt,
                      const char *agent_crt,
                      const char *agent_key);

SSL *im_tls_wrap(im_tls_ctx_t *ctx, int fd);

void tls_context_free(im_tls_ctx_t *ctx);

#endif /* IM_TLS_CONTEXT_H */
