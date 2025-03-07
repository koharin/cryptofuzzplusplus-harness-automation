        virtual std::optional<bool> OpEVP_PKEY_verify(operation::EVP_PKEY_verify& op) {
            (void)op;
            return std::nullopt;
        }
