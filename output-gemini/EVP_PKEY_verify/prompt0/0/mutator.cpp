            case    CF_OPERATION("EVP_PKEY_verify"):
                {
                    parameters["modifier"] = "";
                    parameters["cleartext"] = getBuffer(PRNG64() % maxSize);
                    parameters["digestType"] = getRandomDigest();
                    parameters["keySize"] = (PRNG() % (4096 - 1024 + 1)) + 1024;

                    cryptofuzz::operation::EVP_PKEY_verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
