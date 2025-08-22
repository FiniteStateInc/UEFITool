
// Enhanced PE32 parser with better resource section handling
UString FfsSbomParser::detectLicenseFromPe32Data(const UByteArray& peData)
{
    if (peData.size() < 64) {
        return "Unknown";
    }
    
    // Check for MZ header
    if (peData[0] != 'M' || peData[1] != 'Z') {
        return "Unknown";
    }
    
    // Get PE offset
    UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
    if (peOffset + 248 > peData.size()) {
        return "Unknown";
    }
    
    // Check for PE signature
    if (peData[peOffset] != 'P' || peData[peOffset + 1] != 'E') {
        return "Unknown";
    }
    
    // Get optional header size
    UINT16 optionalHeaderSize = readUnaligned((const UINT16*)(peData.constData() + peOffset + 20));
    if (optionalHeaderSize < 224) {
        return "Unknown";
    }
    
    // Get number of data directories
    UINT32 numberOfRvaAndSizes = readUnaligned((const UINT32*)(peData.constData() + peOffset + 24));
    if (numberOfRvaAndSizes < 16) {
        return "Unknown";
    }
    
    // Get resource directory RVA and size
    UINT32 resourceRva = readUnaligned((const UINT32*)(peData.constData() + peOffset + 208));
    UINT32 resourceSize = readUnaligned((const UINT32*)(peData.constData() + peOffset + 212));
    
    if (resourceRva == 0 || resourceSize == 0) {
        return "Unknown";
    }
    
    // Find the .rsrc section to convert RVA to file offset
    UINT32 resourceOffset = 0;
    UINT16 numberOfSections = readUnaligned((const UINT16*)(peData.constData() + peOffset + 6));
    UINT32 sectionTableOffset = peOffset + 24 + optionalHeaderSize;
    
    for (UINT16 i = 0; i < numberOfSections; i++) {
        UINT32 sectionOffset = sectionTableOffset + i * 40;
        if (sectionOffset + 40 > peData.size()) break;
        
        // Check if this is the .rsrc section
        const char* sectionName = (const char*)(peData.constData() + sectionOffset);
        if (strncmp(sectionName, ".rsrc", 5) == 0) {
            UINT32 virtualAddress = readUnaligned((const UINT32*)(peData.constData() + sectionOffset + 12));
            UINT32 pointerToRawData = readUnaligned((const UINT32*)(peData.constData() + sectionOffset + 20));
            UINT32 sizeOfRawData = readUnaligned((const UINT32*)(peData.constData() + sectionOffset + 16));
            
            if (resourceRva >= virtualAddress && resourceRva < virtualAddress + sizeOfRawData) {
                resourceOffset = pointerToRawData + (resourceRva - virtualAddress);
                break;
            }
        }
    }
    
    if (resourceOffset == 0 || resourceOffset + resourceSize > peData.size()) {
        return "Unknown";
    }
    
    // Search for vendor patterns in the resource section
    const char* data = (const char*)peData.constData() + resourceOffset;
    size_t searchSize = std::min((size_t)resourceSize, (size_t)(peData.size() - resourceOffset));
    
    // Convert to string for pattern matching
    std::string searchData(data, searchSize);
    
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
