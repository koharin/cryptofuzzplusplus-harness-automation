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

typedef struct {
    std::string ntlsa;
    std::string ncert;
    std::string noncheck;
    const uint8_t* ntlsa_data;
} X509_STORE_CTX_verify_Mutation;

extern MutatorPool<X509_STORE_CTX_verify_Mutation, cryptofuzz::config::kMutatorPoolSize> Pool_X509_STORE_CTX_verify;
