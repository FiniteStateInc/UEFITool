
UString FfsSbomParser::detectLicenseFromPe32Data(const UByteArray& peData)
{
    // Simple but effective license detection based on PE32 data patterns
    if (peData.size() < 64) {
        return "Unknown";
    }
    
    // Check for MZ header
    if (peData[0] != 'M' || peData[1] != 'Z') {
        return "Unknown";
    }
    
    // Search for vendor patterns in the entire PE32 data
    std::string searchData((const char*)peData.constData(), std::min((size_t)peData.size(), (size_t)8192));
    
    // Look for Intel patterns
    if (searchData.find("Intel") != std::string::npos || 
        searchData.find("INTEL") != std::string::npos ||
        searchData.find("Intel Corporation") != std::string::npos) {
        return "Intel Proprietary";
    }
    
    // Look for AMI patterns
    if (searchData.find("AMI") != std::string::npos || 
        searchData.find("American Megatrends") != std::string::npos ||
        searchData.find("American Megatrends Inc") != std::string::npos) {
        return "AMI Proprietary";
    }
    
    // Look for Microsoft patterns
    if (searchData.find("Microsoft") != std::string::npos || 
        searchData.find("MSFT") != std::string::npos ||
        searchData.find("Microsoft Corporation") != std::string::npos) {
        return "Microsoft Proprietary";
    }
    
    // Look for Phoenix patterns
    if (searchData.find("Phoenix") != std::string::npos ||
        searchData.find("Phoenix Technologies") != std::string::npos) {
        return "Phoenix Proprietary";
    }
    
    // Look for Insyde patterns
    if (searchData.find("Insyde") != std::string::npos ||
        searchData.find("Insyde Software") != std::string::npos) {
        return "Insyde Proprietary";
    }
    
    // If we found any copyright/license info, return generic proprietary
    if (searchData.find("Copyright") != std::string::npos || 
        searchData.find("Proprietary") != std::string::npos ||
        searchData.find("License") != std::string::npos ||
        searchData.find("All rights reserved") != std::string::npos) {
        return "Proprietary";
    }
    
    return "Unknown";
}

void FfsSbomParser::extractPe32VersionInfo(const UByteArray& peData, SbomEntry& entry)
{
    // Enhanced PE32 version info extraction
    if (peData.size() < 64) {
        return;
    }
    
    // Check for MZ header
    if (peData[0] != 'M' || peData[1] != 'Z') {
        return;
    }
    
    // Search for version information in the PE32 data
    std::string searchData((const char*)peData.constData(), std::min((size_t)peData.size(), (size_t)8192));
    
    // Extract company/publisher information
    if (searchData.find("Intel Corporation") != std::string::npos) {
        entry.company = "Intel Corporation";
    } else if (searchData.find("American Megatrends") != std::string::npos) {
        entry.company = "American Megatrends Inc.";
    } else if (searchData.find("Microsoft Corporation") != std::string::npos) {
        entry.company = "Microsoft Corporation";
    } else if (searchData.find("Phoenix Technologies") != std::string::npos) {
        entry.company = "Phoenix Technologies Ltd.";
    } else if (searchData.find("Insyde Software") != std::string::npos) {
        entry.company = "Insyde Software Corp.";
    }
    
    // Extract file description
    size_t descPos = searchData.find("FileDescription");
    if (descPos != std::string::npos) {
        size_t start = searchData.find("\"", descPos);
        if (start != std::string::npos) {
            start++;
            size_t end = searchData.find("\"", start);
            if (end != std::string::npos && end > start) {
                entry.fileDescription = UString(searchData.substr(start, end - start).c_str());
            }
        }
    }
    
    // Extract file version
    size_t verPos = searchData.find("FileVersion");
    if (verPos != std::string::npos) {
        size_t start = searchData.find("\"", verPos);
        if (start != std::string::npos) {
            start++;
            size_t end = searchData.find("\"", start);
            if (end != std::string::npos && end > start) {
                entry.fileVersion = UString(searchData.substr(start, end - start).c_str());
            }
        }
    }
    
    // Extract product version
    size_t prodVerPos = searchData.find("ProductVersion");
    if (prodVerPos != std::string::npos) {
        size_t start = searchData.find("\"", prodVerPos);
        if (start != std::string::npos) {
            start++;
            size_t end = searchData.find("\"", start);
            if (end != std::string::npos && end > start) {
                entry.peVersion = UString(searchData.substr(start, end - start).c_str());
            }
        }
    }
    
    // Extract copyright information
    size_t copyrightPos = searchData.find("LegalCopyright");
    if (copyrightPos != std::string::npos) {
        size_t start = searchData.find("\"", copyrightPos);
        if (start != std::string::npos) {
            start++;
            size_t end = searchData.find("\"", start);
            if (end != std::string::npos && end > start) {
                entry.copyright = UString(searchData.substr(start, end - start).c_str());
            }
        }
    }
}
