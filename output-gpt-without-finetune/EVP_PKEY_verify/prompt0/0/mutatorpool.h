#include <string>
#include "cryptofuzz/config.h"

struct EVP_PKEY_verify_Mutation {
    std::string cleartext;
    std::string digestType;
    size_t keySize;
};

extern MutatorPool<EVP_PKEY_verify_Mutation, cryptofuzz::config::kMutatorPoolSize> Pool_EVP_PKEY_verify_Mutation;

template <class T, size_t Size>
class MutatorPool {
    private:
        std::array<T, Size> pool = {};
        bool set = false;
    public:
        void Set(const T& v);
        bool Have(void) const;
        T Get(void) const;
};
