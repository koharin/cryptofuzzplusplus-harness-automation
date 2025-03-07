/* Executor code for EVP_PKEY_verify */
template <>
class Executor<component::Signature, operation::EVP_PKEY_verify> : public ExecutorBase<component::Signature, operation::EVP_PKEY_verify> {
public:
    Executor(const std::shared_ptr<Module>& module) : ExecutorBase<component::Signature, operation::EVP_PKEY_verify>(module) {}

    std::optional<component::Signature> Run(operation::EVP_PKEY_verify& op) override {
        std::optional<component::Signature> result = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        try {
            auto pkey = getPublicKey(op.keySize);

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
            if (!ctx) {
                return std::nullopt;
            }
            if (EVP_PKEY_verify_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return std::nullopt;
            }
            const EVP_MD* md = toEVPMD(op.digestType);
            if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return std::nullopt;
            }

            int verified = EVP_PKEY_verify(ctx, 
                                           (const unsigned char*)op.signature.data(), op.signature.size(), 
                                           (const unsigned char*)op.cleartext.data(), op.cleartext.size());
            if (verified == 1) {
                result = component::Signature((const uint8_t*)"", 0);
            } else if (verified < 0) {
                /* Error occurred. Returning std::nullopt */
            }
            EVP_PKEY_CTX_free(ctx);
        } catch (fuzzing::datasource::Datasource::OutOfData) {}

        return result;
    }
};
