case CF_OPERATION("SMIME_WriteASN1Ex"):
{
    size_t numParts = 0;

    numParts++; /* modifier */
    numParts++; /* out */
    numParts++; /* val */
    numParts++; /* data */

    const auto lengths = SplitLength(maxSize - 64, numParts);

    parameters["modifier"] = getBuffer(lengths[0]);
    parameters["out"] = getBuffer(lengths[1]);
    parameters["val"] = getBuffer(lengths[2]);
    parameters["data"] = getBuffer(lengths[3]);
    
    parameters["CMS_flag"] = PRNG() % 2;
    parameters["SMIME_flag"] = PRNG() % 2;
    parameters["cipherType"] = getRandomCipher();

    if (getBool()) {
        parameters["mdalgs_enabled"] = true;
        parameters["mdalgs"] = getRandomAlgorithms();
    } else {
        parameters["mdalgs_enabled"] = false;
    }

    parameters["it"] = getRandomASN1_Item();

    cryptofuzz::operation::SMIME_WriteASN1Ex op(parameters);
    op.Serialize(dsOut2);
}
break;
