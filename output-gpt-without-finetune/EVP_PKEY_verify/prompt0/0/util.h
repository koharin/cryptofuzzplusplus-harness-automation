#include <string>
#include "nlohmann/json.hpp"
#include "cryptofuzz/config.h"

// Function to convert EVP_PKEY_verify_Mutation to string format.
std::string ToString(const EVP_PKEY_verify_Mutation& mutation) {
    return "Cleartext: " + mutation.cleartext +
           ", DigestType: " + mutation.digestType +
           ", KeySize: " + std::to_string(mutation.keySize);
}

// Function to convert EVP_PKEY_verify_Mutation to JSON format.
nlohmann::json ToJSON(const EVP_PKEY_verify_Mutation& mutation) {
    return {
        {"cleartext", mutation.cleartext},
        {"digestType", mutation.digestType},
        {"keySize", mutation.keySize}
    };
}
