#include "tls_context.h"
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <syslog.h>
#include <string.h>

/*
 * OpenSSL 버전 호환성
 *
 * OpenSSL 1.0.x (CentOS 7):
 *   - TLS_client_method()          → SSLv23_client_method()
 *   - SSL_CTX_set_min_proto_version → 없음, SSL_OP_NO_* 옵션으로 대체
 *   - TLS1_3_VERSION               → 없음 (1.0.x는 TLS 1.2까지)
 *
 * OpenSSL 1.1.x+ (Ubuntu 18.04+, CentOS 8+):
 *   - TLS_client_method()          → 그대로 사용
 *   - SSL_CTX_set_min_proto_version → 사용 가능
 */

int tls_context_init(im_tls_ctx_t *out,
                     const char *ca_crt,
                     const char *agent_crt,
                     const char *agent_key)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* OpenSSL 1.1.0+ */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
#else
    /* OpenSSL 1.0.x */
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
#endif
    if (!ctx) {
        syslog(LOG_ERR, "tls: SSL_CTX_new 실패");
        return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    /* OpenSSL 1.1.1+: TLS 1.3 사용 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* OpenSSL 1.1.0: TLS 1.2 최소 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#else
    /* OpenSSL 1.0.x: SSL_OP_NO_* 로 구버전 비활성화 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif

    /* CA 인증서 로드 → 서버 인증서 검증용 */
    if (SSL_CTX_load_verify_locations(ctx, ca_crt, NULL) != 1) {
        syslog(LOG_ERR, "tls: CA 인증서 로드 실패: %s", ca_crt);
        SSL_CTX_free(ctx);
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* 클라이언트 인증서 로드 (mTLS) */
    if (SSL_CTX_use_certificate_file(ctx, agent_crt, SSL_FILETYPE_PEM) != 1) {
        syslog(LOG_ERR, "tls: 에이전트 인증서 로드 실패: %s", agent_crt);
        SSL_CTX_free(ctx);
        return -1;
    }

    /* 개인키 로드 */
    if (SSL_CTX_use_PrivateKey_file(ctx, agent_key, SSL_FILETYPE_PEM) != 1) {
        syslog(LOG_ERR, "tls: 개인키 로드 실패: %s", agent_key);
        SSL_CTX_free(ctx);
        return -1;
    }

    /* 인증서-개인키 쌍 검증 */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        syslog(LOG_ERR, "tls: 인증서-개인키 불일치");
        SSL_CTX_free(ctx);
        return -1;
    }

    out->ctx = ctx;
    syslog(LOG_INFO, "tls: mTLS 컨텍스트 초기화 완료");
    return 0;
}

SSL *im_tls_wrap(im_tls_ctx_t *ctx, int fd)
{
    if (!ctx || !ctx->ctx) return NULL;

    SSL *ssl = SSL_new(ctx->ctx);
    if (!ssl) {
        syslog(LOG_ERR, "tls: SSL_new 실패");
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        unsigned long err = ERR_get_error();
        char errbuf[256];
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        syslog(LOG_ERR, "tls: TLS 핸드셰이크 실패: %s", errbuf);
        SSL_free(ssl);
        return NULL;
    }

    syslog(LOG_INFO, "tls: TLS 핸드셰이크 성공 (protocol=%s)",
           SSL_get_version(ssl));
    return ssl;
}

void tls_context_free(im_tls_ctx_t *ctx)
{
    if (ctx && ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}
