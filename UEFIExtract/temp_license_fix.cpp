
UString FfsSbomParser::detectLicenseFromPe32Data(const UByteArray& peData)
{
    // For now, return "Proprietary" for PE32 files since we can't reliably parse resources
    // The previous approach likely used a more sophisticated PE32 parser
    return "Proprietary";
}
