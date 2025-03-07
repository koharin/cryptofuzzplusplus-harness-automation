            case    CF_OPERATION("X509_STORE_CTX_verify"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* ntlsa_data */
                    numParts++; /* ncert */
                    numParts++; /* noncheck */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["ntlsa"] = getBuffer(lengths[1]);
                    parameters["ncert"] = getBuffer(lengths[2]);
                    parameters["noncheck"] = getBuffer(lengths[3]);

                    cryptofuzz::operation::X509_STORE_CTX_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
