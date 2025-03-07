void test(const operation::EVP_PKEY_verify& op, const std::optional<bool>& result) {
    if (!result.has_value()) {
        return;
    }

    // Here, we'd normally check the operation details, but since we're given
    // provided mutation variables: cleartext, digestType, and keySize. Let's assume
    // these must be part of the operation.

    if (*result == false) {
        // If the verification failed, determine if it might be due to incorrect setup.

        // A simple example check could involve inspecting attributes in 'op'.
        // For this demonstration, assume the op contains the mutation variables
        // directly (this may require adjustments based on the actual structure of `op`).

        if (op.cleartext.size() <= 0) {
            // Verification failed due to an empty cleartext, which is invalid
            abort(); // Force a crash to indicate error
        }

        if (op.digestType != "SHA256") {
            // We expected SHA256 but found something else
            abort(); // Invalid digest type specified
        }

        if (op.keySize < 2048) {
            // Ensure key size is at secure standard
            abort(); // Key size too small
        }
    }
}
