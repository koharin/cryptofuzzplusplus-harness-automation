void test(const operation::EVP_PKEY_verify& op, const std::optional<bool>& result) {
    if (result == std::nullopt) {
        return;
    }

    if (*result == false) {
        if (op.cleartext.size() <= 0) {
            // Verification failed due to an empty cleartext, which is invalid
            abort();
        }

        if (op.digestType != "SHA256") {
            // We expected SHA256 but found something else
            abort();
        }

        if (op.keySize < 2048) {
            // Ensure key size is at secure standard
            abort();
        }
    }
}
