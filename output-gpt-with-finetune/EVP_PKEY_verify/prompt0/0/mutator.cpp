            case    CF_OPERATION("EVP_PKEY_verify"):
                {
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    parameters["digestType"] = getBuffer(PRNG() % 1024);
                    parameters["keySize"] = getBuffer(PRNG() % 1024);

                    cryptofuzz::operation::EVP_PKEY_verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
