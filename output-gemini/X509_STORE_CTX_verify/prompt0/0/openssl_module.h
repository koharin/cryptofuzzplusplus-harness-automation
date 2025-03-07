#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <vector>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 입력 데이터를 ntlsa, ncert, noncheck으로 분할
    // 각 부분을 데이터의 1/3씩 할당
    size_t part_size = size / 3;
    size_t ntlsa_size = part_size;
    size_t ncert_size = part_size;
    size_t noncheck_size = size - 2 * part_size;

    const uint8_t *ntlsa_data = data;
    const uint8_t *ncert_data = data + ntlsa_size;
    const uint8_t *noncheck_data = data + ntlsa_size + ncert_size;

    // 1. ntlsa: 신뢰할 수 있는 인증서 저장소 생성 및 초기화
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        return 0;
    }

    // ntlsa_data를 사용하여 인증서 추가
    // DER 형식의 인증서로 가정하고, 하나의 인증서만 추가
    const unsigned char *p = ntlsa_data;
    X509 *cert = d2i_X509(NULL, &p, ntlsa_size);
    if (cert) {
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    }

    // 2. ncert: 검증할 인증서 체인 생성
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        X509_STORE_free(store);
        return 0;
    }

    p = ncert_data;
    cert = d2i_X509(NULL, &p, ncert_size);
    if (cert) {
        sk_X509_push(chain, cert);
    } else {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return 0;
    }

    // 3. noncheck: 검증 파라미터 설정
    // 여기서는 noncheck_data를 사용하여 검증 플래그를 설정
    // 예를 들어, noncheck_data의 첫 번째 바이트를 플래그로 사용
    long verify_flags = X509_V_FLAG_DEFAULT;
    if (noncheck_size > 0) {
        verify_flags |= noncheck_data[0] & 0xFF; // 비트 플래그로 사용
    }

    // 검증 컨텍스트 초기화
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return 0;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, chain) != 1) {
        X509_STORE_CTX_free(store_ctx);
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return 0;
    }

    // 검증 플래그 설정
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(store_ctx);
    if (param) {
        X509_VERIFY_PARAM_set_flags(param, verify_flags);
    }

    // 4. X509_STORE_CTX_verify 호출
    int ret = X509_STORE_CTX_verify(store_ctx);

    // 5. 정리
    X509_STORE_CTX_free(store_ctx);
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_free(store);

    return ret;
}
