case CF_OPERATION("EVP_PKEY_verify"):
{
    parameters["modifier"] = getBuffer(PRNG() % 1024);
    parameters["cleartext"] = getBuffer(PRNG() % 2048);
    parameters["digestType"] = getRandomDigest();
    parameters["keySize"] = PRNG() % 2048;

    cryptofuzz::operation::EVP_PKEY_verify op(parameters);
    op.Serialize(dsOut2);
}
break;
