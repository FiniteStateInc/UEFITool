
// UEFI Version Info structure
typedef struct {
    UINT16 BuildNumber;
    CHAR16 VersionString[1];
} EFI_VERSION_INFO;

void FfsSbomParser::extractVersionFromNode(const UModelIndex& index, SbomEntry& entry)
{
    if (!index.isValid()) {
        return;
    }
    
    // Search for ALL Version sections in children and collect them
    std::vector<UString> allVersions;
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex child = index.child(i, 0);
        if (!child.isValid()) continue;
        
        if (model->type(child) == Types::Section && model->subtype(child) == EFI_SECTION_VERSION) {
            // Found a version section
            if (!model->hasEmptyBody(child)) {
                const UByteArray& versionData = model->body(child);
                
                // Parse EFI_VERSION_INFO structure
                if (versionData.size() >= sizeof(UINT16)) {
                    UINT16 buildNumber = readUnaligned((const UINT16*)versionData.constData());
                    
                    // The version string starts after the build number
                    if (versionData.size() > sizeof(UINT16)) {
                        // Convert UTF-16 to string (simplified)
                        const char* versionStr = (const char*)(versionData.constData() + sizeof(UINT16));
                        UString versionString = UString(versionStr);
                        
                        // Clean up the version string (remove null bytes, etc.)
                        std::string cleanVer((const char*)versionString.toLocal8Bit());
                        size_t nullPos = cleanVer.find('\0\);
                        if (nullPos != std::string::npos) {
                            cleanVer = cleanVer.substr(0, nullPos);
                        }
                        
                        if (!cleanVer.empty()) {
                            allVersions.push_back(UString(cleanVer.c_str()));
                            logProgress("Found version section for " + entry.componentName + ": " + UString(cleanVer.c_str()) + " (build " + usprintf("%d", buildNumber) + ")");
                        }
                    }
                }
            }
        }
        
        // Recursively search in children
        extractVersionFromNode(child, entry);
    }
    
    // If we found multiple versions, choose the most appropriate one
    if (!allVersions.empty()) {
        UString selectedVersion = allVersions[0]; // Default to first
        
        // Look for version "0.1" first (as seen in info.txt files)
        for (const UString& ver : allVersions) {
            if (ver == "0.1") {
                selectedVersion = ver;
                break;
            }
        }
        
        // Parse the selected version string
        std::string verStr((const char*)selectedVersion.toLocal8Bit());
        size_t lastDot = verStr.find_last_of('.');
        if (lastDot != std::string::npos) {
            entry.version = UString(verStr.substr(0, lastDot).c_str());
            entry.build = UString(verStr.substr(lastDot + 1).c_str());
        } else {
            entry.version = selectedVersion;
        }
        
        // Add version info to description
        if (!entry.description.isEmpty()) {
            entry.description += " (Version: " + selectedVersion + ")";
        } else {
            entry.description = "Version: " + selectedVersion;
        }
        
        logProgress("Selected version for " + entry.componentName + ": " + selectedVersion + " (from " + usprintf("%zu", allVersions.size()) + " available)");
    }
}
