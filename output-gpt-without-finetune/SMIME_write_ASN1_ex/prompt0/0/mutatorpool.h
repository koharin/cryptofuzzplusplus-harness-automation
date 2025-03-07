template <class T, size_t Size>
class SMIME_MutatorPool {
    private:
        std::array<T, Size> pool = {};
        bool set = false;
    public:
        void Set(const T& v);
        bool Have(void) const;
        T Get(void) const;
};

typedef struct {
    int CMS_flag;
    int SMIME_flag;
    int cipherType;
} SMIME_Encryption_Params;
extern SMIME_MutatorPool<SMIME_Encryption_Params, cryptofuzz::config::kMutatorPoolSize> Pool_SMIME_Encryption;
