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
    uint64_t curveID;
    std::string priv;
} CurvePrivkey_Pair;
extern MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurvePrivkey;

typedef struct {
    uint64_t curveID;
    std::string privkey;
    std::string pub_x;
    std::string pub_y;
} CurveKeypair_Pair;
extern MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveKeypair;

typedef struct {
    uint64_t curveID;
    std::string cleartext;
    std::string pub_x;
    std::string pub_y;
    std::string sig_r;
    std::string sig_y;
} CurveECDSASignature_Pair;
extern MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECDSASignature;

typedef struct {
    uint64_t curveID;
    std::string x;
    std::string y;
} CurveECC_Point_Pair;
extern MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECC_Point;

extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum;
extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum_Primes;

typedef struct {
    uint64_t curveID;
    bool hashOrPoint;
    std::string point_v;
    std::string point_w;
    std::string point_x;
    std::string point_y;
    std::string cleartext;
    std::string dest;
    std::string aug;
    std::string pub_x;
    std::string pub_y;
    std::string sig_v;
    std::string sig_w;
    std::string sig_x;
    std::string sig_y;
} CurveBLSSignature_Pair;
extern MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSSignature;

typedef struct {
    uint64_t curveID;
    std::string g1_x;
    std::string g1_y;
} CurveBLSG1_Pair;
extern MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1;

typedef struct {
    uint64_t curveID;
    std::string g2_v;
    std::string g2_w;
    std::string g2_x;
    std::string g2_y;
} CurveBLSG2_Pair;
extern MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2;

typedef struct {
    std::string bn1;
    std::string bn2;
    std::string bn3;
    std::string bn4;
    std::string bn5;
    std::string bn6;
    std::string bn7;
    std::string bn8;
    std::string bn9;
    std::string bn10;
    std::string bn11;
    std::string bn12;
} Fp12;
extern MutatorPool<Fp12, cryptofuzz::config::kMutatorPoolSize> Pool_Fp12;

typedef struct {
    struct G1 {
        std::string g1_x;
        std::string g1_y;
    };

    struct G2 {
        std::string g2_v;
        std::string g2_w;
        std::string g2_x;
        std::string g2_y;
    };

    std::vector<
        std::pair<G1, G2>
    > msgpub;
} BLS_BatchSignature_;
extern MutatorPool<BLS_BatchSignature_, cryptofuzz::config::kMutatorPoolSize> Pool_BLS_BatchSignature;

extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PrivateKey;
extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PublicKey;

typedef struct {
    std::string modulus;
    std::string private_exponent;
} RSAPrivateKey_Pair;
extern MutatorPool<RSAPrivateKey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_RSA_PrivateKey;

typedef struct {
    std::string modulus;
    std::string public_exponent;
} RSA_PublicKey_Pair;
extern MutatorPool<RSA_PublicKey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_RSA_PublicKey;

typedef struct {
    std::string modulus;
    std::string public_exponent;
    std::string private_exponent;
} RSAKeypair_Pair;
extern MutatorPool<RSAKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_RSAKeypair;
