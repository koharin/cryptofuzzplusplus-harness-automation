MutatorPool<EVP_PKEY_verify_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_EVP_PKEY_verify;

template <>
void MutatorPool<EVP_PKEY_verify_Pair, cryptofuzz::config::kMutatorPoolSize>::
    Init(std::mt19937& rng) {
  // cleartext
  AddMutator([&rng]() -> EVP_PKEY_verify_Pair {
    EVP_PKEY_verify_Pair result;
    result.cleartext = GenAsciiString(rng, 1, 256);
    return result;
  });

  // digestType
  AddMutator([]() -> EVP_PKEY_verify_Pair {
    EVP_PKEY_verify_Pair result;
    result.digestType = 0;
    return result;
  });

  // keySize
  AddMutator([]() -> EVP_PKEY_verify_Pair {
    EVP_PKEY_verify_Pair result;
    result.keySize = 0;
    return result;
  });
}
