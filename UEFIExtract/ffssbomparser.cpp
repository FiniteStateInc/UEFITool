/* ffssbomparser.cpp

Copyright (c) 2024, LongSoft. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#include "ffssbomparser.h"
#include "../common/ffs.h"
#include "../common/ffsparser.h"
#include "../common/treemodel.h"
#include "../common/utility.h"
#include "../common/digest/sha2.h"
#include "../common/types.h"
#include "../common/guiddatabase.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

// Helper: trim whitespace from both ends
static void trimws(CBString& str) {
    // Left trim
    int start = 0;
    while (start < str.length() && (str[start] == ' ' || str[start] == '\t' || str[start] == '\n' || str[start] == '\r')) start++;
    // Right trim
    int end = str.length() - 1;
    while (end >= start && (str[end] == ' ' || str[end] == '\t' || str[end] == '\n' || str[end] == '\r')) end--;
    if (start > 0 || end < (int)str.length() - 1) {
        str = str.mid(start, end - start + 1);
    }
}

// Helper: case-insensitive substring search
static bool caseContains(const CBString& haystack, const char* needle) {
    std::string h(haystack.toLocal8Bit());
    std::string n(needle);
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

FfsSbomParser::FfsSbomParser(TreeModel* treeModel)
    : model(treeModel)
{
}

FfsSbomParser::~FfsSbomParser()
{
}

USTATUS FfsSbomParser::parseSbom(const UModelIndex& root, const UString& outputPath)
{
    if (!root.isValid()) {
        logProgress("Invalid root index provided", true);
        return U_INVALID_PARAMETER;
    }

    logProgress("Starting FFS SBOM parsing...");

    // Clear previous entries
    sbomEntries.clear();
    processedGuids.clear();

    USTATUS result = parseSbomRecursive(root, outputPath);

    if (result == U_SUCCESS) {
        logProgress("SBOM parsing completed successfully");
        printf("SBOM Statistics:\n");
        printf("  Total Components Found: %zu\n", sbomEntries.size());
        printf("  Components with Names: %zu\n",
            std::count_if(sbomEntries.begin(), sbomEntries.end(),
                [](const SbomEntry& entry) { return !entry.componentName.isEmpty(); }));
        printf("  Components with Versions: %zu\n",
            std::count_if(sbomEntries.begin(), sbomEntries.end(),
                [](const SbomEntry& entry) { return !entry.version.isEmpty(); }));
        printf("  Components with Dependencies: %zu\n",
            std::count_if(sbomEntries.begin(), sbomEntries.end(),
                [](const SbomEntry& entry) { return !entry.dependencies.empty(); }));
    } else {
        logProgress("SBOM parsing failed", true);
    }

    return result;
}

USTATUS FfsSbomParser::parseSbomRecursive(const UModelIndex& index, const UString& basePath)
{
    if (!index.isValid())
        return U_INVALID_PARAMETER;

    USTATUS result = U_SUCCESS;

    // Check if this is an FFS file
    if (model->type(index) == Types::File) {
        // Use enhanced recursive parsing to extract PE metadata from embedded sections
        parseFfsFileRecursive(index, basePath);
    }

    // Recursively process children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (!childIndex.isValid())
            continue;

        UString childPath = basePath;
        if (model->rowCount(childIndex) > 0) {
            UString name = usprintf("%d_%s", i, model->name(childIndex).toLocal8Bit());
            // Replace spaces and special characters
            for (size_t j = 0; j < name.length(); j++) {
                if (name[j] == ' ' || name[j] == '/' || name[j] == '\\' || name[j] == ':' || name[j] == '*') {
                    name[j] = '_';
                }
            }
            fixFileName(name, false);
            childPath = usprintf("%s/%s", basePath.toLocal8Bit(), name.toLocal8Bit());
        }

        result = parseSbomRecursive(childIndex, childPath);
        if (result != U_SUCCESS) {
            logProgress("Error in recursive SBOM parsing", true);
        }
    }

    return result;
}

bool FfsSbomParser::parseFfsFile(const UModelIndex& index, const UString& basePath)
{
    if (!index.isValid()) {
        return false;
    }

    // Create SBOM entry
    SbomEntry entry;

    // Extract GUID
    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        if (headerData.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)headerData.constData();
            entry.guid = guidToString(header->Name);
        }
    }

    // Skip if already processed
    if (!entry.guid.isEmpty() && processedGuids.find(entry.guid) != processedGuids.end()) {
        return true;
    }

    // Extract basic information
    entry.componentName = extractComponentName(index);
    entry.version = extractVersion(index);
    entry.hash = calculateHash(index);
    entry.license = extractLicense(index);
    entry.dependencies = extractDependencies(index);
    entry.filePath = createSafeFilename(index, basePath);
    entry.type = itemTypeToUString(model->type(index));
    entry.subtype = itemSubtypeToUString(model->type(index), model->subtype(index));
    entry.offset = model->offset(index);
    entry.size = model->body(index).size();

    // Extract additional SBOM fields
    entry.componentType = extractComponentType(index);
    entry.architecture = extractArchitecture(index);
    entry.buildDate = extractBuildDate(index);
    entry.vendor = extractVendor(index);
    entry.checksumAlgorithm = "SHA256"; // We're using SHA256
    entry.securityAttributes = extractSecurityAttributes(index);
    entry.compatibility = extractCompatibility(index);
    entry.description = extractDescription(index);
    entry.sourceLocation = extractSourceLocation(index);
    entry.contactInfo = extractContactInfo(index);
    entry.externalReferences = extractExternalReferences(index);

    // Try to extract PE metadata from the FFS file structure
    bool peMetadataFound = extractPeMetadataFromFfs(index, entry);

    // If no PE metadata found, provide defaults based on file type
    if (!peMetadataFound) {
        bool isPeFile = isPeExecutable(index);
        if (isPeFile) {
            // For PE files without embedded metadata, try direct extraction
            entry.company = extractCompany(index);
            entry.fileDescription = extractFileDescription(index);
            entry.fileVersion = extractFileVersion(index);
            entry.copyright = extractCopyright(index);
            entry.signerCN = extractSignerCN(index);
            entry.peVersion = extractPeVersionFromIndex(index);
            entry.sha256Hash = calculateSha256Hash(index);

            // Prefer PE version if UI version is missing
            if (entry.version.isEmpty() && !entry.peVersion.isEmpty()) {
                entry.version = entry.peVersion;
            }

            // Prefer company from PE metadata if vendor is unknown
            if (entry.vendor == "Unknown" && !entry.company.isEmpty()) {
                entry.vendor = entry.company;
            }
        } else {
            // For non-PE files, provide meaningful defaults
            entry.company = "N/A (Non-PE file)";
            entry.fileDescription = entry.description.isEmpty() ? "Configuration/Data file" : entry.description;
            entry.fileVersion = entry.version.isEmpty() ? "N/A" : entry.version;
            entry.copyright = "N/A (Non-PE file)";
            entry.signerCN = "N/A (Non-PE file)";
            entry.peVersion = "N/A (Non-PE file)";
            entry.sha256Hash = calculateSha256Hash(index);

            // Set default description for non-PE files
            if (entry.description.isEmpty()) {
                entry.description = usprintf("%s configuration file", entry.componentName.toLocal8Bit());
            }
        }
    }

    // Add to entries if it has meaningful information
    if (!entry.componentName.isEmpty() || !entry.guid.isEmpty()) {
        // Identify and extract PE32 files contained within this FFS file
        identifyPe32FilesInFfs(index, entry);

        sbomEntries.push_back(entry);
        if (!entry.guid.isEmpty()) {
            processedGuids.insert(entry.guid);
        }
        logProgress("Parsed FFS file: " + (entry.componentName.isEmpty() ? entry.guid : entry.componentName));
        return true;
    }

    return false;
}

UString FfsSbomParser::extractComponentName(const UModelIndex& index)
{
    UString name;

    // First try to get name from UI section
    name = extractUiString(index);
    if (!name.isEmpty()) {
        return name;
    }

    // Try to get name from PE metadata
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        name = extractPeComponentName(bodyData);
        if (!name.isEmpty()) {
            return name;
        }
    }

    // Try to get name from text field
    name = model->text(index);
    if (!name.isEmpty()) {
        return name;
    }

    // Try to get name from GUID database
    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        if (headerData.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)headerData.constData();
            UString guid = guidToString(header->Name);
            name = findGuidName(guid);
            if (!name.isEmpty()) {
                return name;
            }
        }
    }

    return name;
}

UString FfsSbomParser::extractVersion(const UModelIndex& index)
{
    UString version;

    // First try to get version from Version section body (UCS-2/UTF-16LE)
    version = extractVersionStringFromVersionSection(index);
    if (!version.isEmpty()) {
        return version;
    }

    // Then try to get version from version section info
    version = extractVersionFromVersionSection(index);
    if (!version.isEmpty()) {
        return version;
    }

    // Try to get version from PE metadata
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        version = extractPeVersionFromIndex(index);
        if (!version.isEmpty()) {
            return version;
        }
    }

    // Try to get version from info field
    UString info = model->info(index);
    if (!info.isEmpty()) {
        size_t pos = info.find("Version:");
        if (pos != (size_t)-1) {
            size_t start = pos + 8;
            size_t end = info.find('\n', start);
            if (end == (size_t)-1) end = info.length();
            version = info.mid(start, end - start);
            trimws(version); // trim whitespace
        }
    }

    return version;
}

UString FfsSbomParser::calculateHash(const UModelIndex& index)
{
    if (model->hasEmptyBody(index)) {
        return UString();
    }

    const UByteArray& bodyData = model->body(index);
    if (bodyData.isEmpty()) {
        return UString();
    }

    // Calculate SHA256 hash
    UINT8 hash[32]; // SHA256 produces 32 bytes
    sha256(bodyData.constData(), bodyData.size(), hash);

    UString hashString;
    for (int i = 0; i < 32; i++) {
        hashString += usprintf("%02X", hash[i]);
    }
    return hashString;
}

UString FfsSbomParser::extractLicense(const UModelIndex& index)
{
    UString license;

    // Try to detect license from body data
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        license = detectLicenseFromStrings(bodyData);
        if (!license.isEmpty()) {
            return license;
        }
    }

    // Try to detect license from uncompressed data
    if (!model->hasEmptyUncompressedData(index)) {
        const UByteArray& uncData = model->uncompressedData(index);
        license = detectLicenseFromStrings(uncData);
        if (!license.isEmpty()) {
            return license;
        }
    }

    // Provide default license based on vendor
    UString vendor = extractVendor(index);
    if (vendor == "Intel") {
        return "Intel Proprietary";
    } else if (vendor == "Microsoft") {
        return "Microsoft Proprietary";
    } else if (vendor == "AMI") {
        return "AMI Proprietary";
    } else if (vendor == "Phoenix") {
        return "Phoenix Proprietary";
    } else if (vendor == "Dell") {
        return "Dell Proprietary";
    } else if (vendor == "HP") {
        return "HP Proprietary";
    } else if (vendor == "Lenovo") {
        return "Lenovo Proprietary";
    }

    return "Unknown";
}

std::vector<UString> FfsSbomParser::extractDependencies(const UModelIndex& index)
{
    std::vector<UString> dependencies;

    // Look for DEPEX sections in children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (!childIndex.isValid())
            continue;

        if (model->subtype(childIndex) == EFI_SECTION_DXE_DEPEX ||
            model->subtype(childIndex) == EFI_SECTION_PEI_DEPEX) {
            std::vector<UString> depexDeps = parseDepexSection(childIndex);
            dependencies.insert(dependencies.end(), depexDeps.begin(), depexDeps.end());
        }
    }

    return dependencies;
}

UString FfsSbomParser::extractPeComponentName(const UByteArray& peData)
{
    // Basic PE parsing to extract component name
    // This is a simplified version - in a full implementation you'd want more robust PE parsing

    if (peData.size() < 64) {
        return UString();
    }

    // Check for PE signature
    if (peData[0] != 'M' || peData[1] != 'Z') {
        return UString();
    }

    // Get PE header offset
    UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
    if (peOffset + 24 > peData.size()) {
        return UString();
    }

    // Check PE signature
    if (peData[peOffset] != 'P' || peData[peOffset + 1] != 'E') {
        return UString();
    }

    // For now, return a generic name - full PE parsing would extract from resources
    return UString("PE_Module");
}

UString FfsSbomParser::extractPeVersionFromIndex(const UModelIndex& index)
{
    // Try to extract PE version string
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return extractPeVersionResource(bodyData, "FileVersion");
    }
    return UString();
}

UString FfsSbomParser::extractUiString(const UModelIndex& index)
{
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (!childIndex.isValid())
            continue;
        if (model->subtype(childIndex) == EFI_SECTION_USER_INTERFACE) {
            if (!model->hasEmptyBody(childIndex)) {
                const UByteArray& uiData = model->body(childIndex);
                if (!uiData.isEmpty()) {
                    UString uiString;
                    for (size_t j = 0; j < uiData.size() && j < 256; j += 2) {
                        if (j + 1 < uiData.size()) {
                            UINT16 ch = readUnaligned((const UINT16*)(uiData.constData() + j));
                            if (ch == 0) break;
                            if (ch >= 32 && ch <= 126) {
                                uiString += (char)ch;
                            }
                        }
                    }
                    trimws(uiString);
                    return uiString;
                }
            }
        }
    }
    return UString();
}

std::vector<UString> FfsSbomParser::parseDepexSection(const UModelIndex& index)
{
    std::vector<UString> dependencies;

    if (model->hasEmptyBody(index)) {
        return dependencies;
    }

    const UByteArray& depexData = model->body(index);
    if (depexData.isEmpty()) {
        return dependencies;
    }

    // Parse DEPEX section to extract GUID dependencies
    // DEPEX format: [0x02] [GUID] [0x03] [GUID] ... [0x07]
    size_t pos = 0;
    while (pos < depexData.size()) {
        UINT8 opcode = depexData[pos++];

        if (opcode == 0x02 || opcode == 0x03) { // BEFORE/AFTER
            if (pos + sizeof(EFI_GUID) <= depexData.size()) {
                const EFI_GUID* guid = (const EFI_GUID*)(depexData.constData() + pos);
                UString guidStr = guidToString(*guid);
                UString guidName = findGuidName(guidStr);
                dependencies.push_back(guidName.isEmpty() ? guidStr : guidName);
                pos += sizeof(EFI_GUID);
            }
        } else if (opcode == 0x07) { // END
            break;
        }
    }

    return dependencies;
}

UString FfsSbomParser::detectLicenseFromStrings(const UByteArray& data)
{
    CBString dataStr((const char*)data.constData(), data.size());
    if (caseContains(dataStr, "GPL")) {
        return "GPL";
    } else if (caseContains(dataStr, "BSD")) {
        return "BSD";
    } else if (caseContains(dataStr, "MIT")) {
        return "MIT";
    } else if (caseContains(dataStr, "Apache")) {
        return "Apache";
    } else if (caseContains(dataStr, "LGPL")) {
        return "LGPL";
    } else if (caseContains(dataStr, "Proprietary")) {
        return "Proprietary";
    }
    return UString();
}

UString FfsSbomParser::guidToString(const EFI_GUID& guid)
{
    return usprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

UString FfsSbomParser::findGuidName(const UString& guid)
{
    // If getGuidName is available, use it. Otherwise, just return guid.
    // return getGuidName(guid);
    return guid;
}

UString FfsSbomParser::createSafeFilename(const UModelIndex& index, const UString& basePath)
{
    UString name = model->name(index);
    if (name.isEmpty()) {
        name = usprintf("file_0x%08X", model->offset(index));
    }
    // Replace spaces and special characters with underscores
    for (size_t i = 0; i < name.length(); i++) {
        if (name[i] == ' ' || name[i] == '/' || name[i] == '\\' || name[i] == ':' || name[i] == '*') {
            name[i] = '_';
        }
    }
    fixFileName(name, false);
    return usprintf("%s/%s", basePath.toLocal8Bit(), name.toLocal8Bit());
}

USTATUS FfsSbomParser::exportToText(const UString& filepath)
{
    std::ofstream file(filepath.toLocal8Bit());
    if (!file.is_open()) {
        logProgress("Cannot open file for writing: " + filepath, true);
        return U_FILE_OPEN;
    }

    file << "FFS Software Bill of Materials (SBOM)\n";
    file << "=====================================\n\n";

    for (size_t i = 0; i < sbomEntries.size(); i++) {
        const SbomEntry& entry = sbomEntries[i];

        file << "Component " << (i + 1) << ":\n";
        file << "  Component Name: " << entry.componentName.toLocal8Bit() << "\n";
        file << "  GUID: " << entry.guid.toLocal8Bit() << "\n";
        file << "  Version: " << entry.version.toLocal8Bit() << "\n";
        file << "  Hash (SHA256): " << entry.hash.toLocal8Bit() << "\n";
        file << "  License: " << entry.license.toLocal8Bit() << "\n";
        file << "  Type: " << entry.type.toLocal8Bit() << "\n";
        file << "  Subtype: " << entry.subtype.toLocal8Bit() << "\n";
        file << "  Offset: 0x" << std::hex << entry.offset << "\n";
        file << "  Size: " << std::dec << entry.size << " bytes\n";
        file << "  File Path: " << entry.filePath.toLocal8Bit() << "\n";

        // Additional SBOM fields
        file << "  Component Type: " << entry.componentType.toLocal8Bit() << "\n";
        file << "  Architecture: " << entry.architecture.toLocal8Bit() << "\n";
        file << "  Build Date: " << entry.buildDate.toLocal8Bit() << "\n";
        file << "  Vendor: " << entry.vendor.toLocal8Bit() << "\n";
        file << "  Checksum Algorithm: " << entry.checksumAlgorithm.toLocal8Bit() << "\n";
        file << "  Security Attributes: " << entry.securityAttributes.toLocal8Bit() << "\n";
        file << "  Compatibility: " << entry.compatibility.toLocal8Bit() << "\n";
        file << "  Description: " << entry.description.toLocal8Bit() << "\n";
        file << "  Source Location: " << entry.sourceLocation.toLocal8Bit() << "\n";
        file << "  Contact Info: " << entry.contactInfo.toLocal8Bit() << "\n";
        file << "  External References: " << entry.externalReferences.toLocal8Bit() << "\n";

        // PE metadata fields
        file << "  Company: " << entry.company.toLocal8Bit() << "\n";
        file << "  File Description: " << entry.fileDescription.toLocal8Bit() << "\n";
        file << "  File Version: " << entry.fileVersion.toLocal8Bit() << "\n";
        file << "  Copyright: " << entry.copyright.toLocal8Bit() << "\n";
        file << "  Digital Signer: " << entry.signerCN.toLocal8Bit() << "\n";
        file << "  PE Version: " << entry.peVersion.toLocal8Bit() << "\n";
        file << "  SHA-256 Hash: " << entry.sha256Hash.toLocal8Bit() << "\n";

        // PE32 file tracking fields
        file << "  Is PE32 File: " << (entry.isPe32File ? "Yes" : "No") << "\n";
        if (entry.isPe32File) {
            file << "  Parent FFS GUID: " << entry.parentFfsGuid.toLocal8Bit() << "\n";
            file << "  Parent FFS Name: " << entry.parentFfsName.toLocal8Bit() << "\n";
            file << "  PE File Name: " << entry.peFileName.toLocal8Bit() << "\n";
            file << "  PE Section Type: " << entry.peSectionType.toLocal8Bit() << "\n";
            file << "  PE Section Offset: 0x" << std::hex << entry.peSectionOffset << "\n";
            file << "  PE Section Size: " << std::dec << entry.peSectionSize << " bytes\n";
        }
        if (!entry.containedPeFiles.empty()) {
            file << "  Contained PE Files:\n";
            for (const UString& peFile : entry.containedPeFiles) {
                file << "    - " << peFile.toLocal8Bit() << "\n";
            }
        }

        if (!entry.dependencies.empty()) {
            file << "  Dependencies:\n";
            for (const UString& dep : entry.dependencies) {
                file << "    - " << dep.toLocal8Bit() << "\n";
            }
        }

        file << "\n";
    }

    file.close();
    logProgress("SBOM exported to text file: " + filepath);
    return U_SUCCESS;
}

USTATUS FfsSbomParser::exportToCsv(const UString& filepath)
{
    std::ofstream file(filepath.toLocal8Bit());
    if (!file.is_open()) {
        logProgress("Cannot open file for writing: " + filepath, true);
        return U_FILE_OPEN;
    }

    // CSV header
    file << "Component Name,GUID,Version,Hash,License,Type,Subtype,Offset,Size,File Path,Component Type,Architecture,Build Date,Vendor,Checksum Algorithm,Security Attributes,Compatibility,Description,Source Location,Contact Info,External References,Company,File Description,File Version,Copyright,Digital Signer,PE Version,SHA-256 Hash,Is PE32 File,Parent FFS GUID,Parent FFS Name,PE File Name,PE Section Type,PE Section Offset,PE Section Size,Contained PE Files,Dependencies\n";

    for (const SbomEntry& entry : sbomEntries) {
        file << "\"" << entry.componentName.toLocal8Bit() << "\",";
        file << "\"" << entry.guid.toLocal8Bit() << "\",";
        file << "\"" << entry.version.toLocal8Bit() << "\",";
        file << "\"" << entry.hash.toLocal8Bit() << "\",";
        file << "\"" << entry.license.toLocal8Bit() << "\",";
        file << "\"" << entry.type.toLocal8Bit() << "\",";
        file << "\"" << entry.subtype.toLocal8Bit() << "\",";
        file << "0x" << std::hex << entry.offset << ",";
        file << std::dec << entry.size << ",";
        file << "\"" << entry.filePath.toLocal8Bit() << "\",";
        file << "\"" << entry.componentType.toLocal8Bit() << "\",";
        file << "\"" << entry.architecture.toLocal8Bit() << "\",";
        file << "\"" << entry.buildDate.toLocal8Bit() << "\",";
        file << "\"" << entry.vendor.toLocal8Bit() << "\",";
        file << "\"" << entry.checksumAlgorithm.toLocal8Bit() << "\",";
        file << "\"" << entry.securityAttributes.toLocal8Bit() << "\",";
        file << "\"" << entry.compatibility.toLocal8Bit() << "\",";
        file << "\"" << entry.description.toLocal8Bit() << "\",";
        file << "\"" << entry.sourceLocation.toLocal8Bit() << "\",";
        file << "\"" << entry.contactInfo.toLocal8Bit() << "\",";
        file << "\"" << entry.externalReferences.toLocal8Bit() << "\",";
        file << "\"" << entry.company.toLocal8Bit() << "\",";
        file << "\"" << entry.fileDescription.toLocal8Bit() << "\",";
        file << "\"" << entry.fileVersion.toLocal8Bit() << "\",";
        file << "\"" << entry.copyright.toLocal8Bit() << "\",";
        file << "\"" << entry.signerCN.toLocal8Bit() << "\",";
        file << "\"" << entry.peVersion.toLocal8Bit() << "\",";
        file << "\"" << entry.sha256Hash.toLocal8Bit() << "\",";
        file << "\"" << (entry.isPe32File ? "Yes" : "No") << "\",";
        file << "\"" << entry.parentFfsGuid.toLocal8Bit() << "\",";
        file << "\"" << entry.parentFfsName.toLocal8Bit() << "\",";
        file << "\"" << entry.peFileName.toLocal8Bit() << "\",";
        file << "\"" << entry.peSectionType.toLocal8Bit() << "\",";
        file << "0x" << std::hex << entry.peSectionOffset << ",";
        file << std::dec << entry.peSectionSize << ",";

        // Contained PE files as semicolon-separated list
        UString containedPeFiles;
        for (size_t i = 0; i < entry.containedPeFiles.size(); i++) {
            if (i > 0) containedPeFiles += ";";
            containedPeFiles += entry.containedPeFiles[i];
        }
        file << "\"" << containedPeFiles.toLocal8Bit() << "\",";

        // Dependencies as semicolon-separated list
        UString deps;
        for (size_t i = 0; i < entry.dependencies.size(); i++) {
            if (i > 0) deps += ";";
            deps += entry.dependencies[i];
        }
        file << "\"" << deps.toLocal8Bit() << "\"\n";
    }

    file.close();
    logProgress("SBOM exported to CSV file: " + filepath);
    return U_SUCCESS;
}

USTATUS FfsSbomParser::exportToJson(const UString& filepath)
{
    std::ofstream file(filepath.toLocal8Bit());
    if (!file.is_open()) {
        logProgress("Cannot open file for writing: " + filepath, true);
        return U_FILE_OPEN;
    }

    file << "{\n";
    file << "  \"sbom\": {\n";
    file << "    \"format\": \"FFS Software Bill of Materials\",\n";
    file << "    \"version\": \"1.0\",\n";
    file << "    \"components\": [\n";

    for (size_t i = 0; i < sbomEntries.size(); i++) {
        const SbomEntry& entry = sbomEntries[i];

        file << "      {\n";
        file << "        \"componentName\": \"" << entry.componentName.toLocal8Bit() << "\",\n";
        file << "        \"guid\": \"" << entry.guid.toLocal8Bit() << "\",\n";
        file << "        \"version\": \"" << entry.version.toLocal8Bit() << "\",\n";
        file << "        \"hash\": \"" << entry.hash.toLocal8Bit() << "\",\n";
        file << "        \"license\": \"" << entry.license.toLocal8Bit() << "\",\n";
        file << "        \"type\": \"" << entry.type.toLocal8Bit() << "\",\n";
        file << "        \"subtype\": \"" << entry.subtype.toLocal8Bit() << "\",\n";
        file << "        \"offset\": \"0x" << std::hex << entry.offset << "\",\n";
        file << "        \"size\": " << std::dec << entry.size << ",\n";
        file << "        \"filePath\": \"" << entry.filePath.toLocal8Bit() << "\",\n";
        file << "        \"componentType\": \"" << entry.componentType.toLocal8Bit() << "\",\n";
        file << "        \"architecture\": \"" << entry.architecture.toLocal8Bit() << "\",\n";
        file << "        \"buildDate\": \"" << entry.buildDate.toLocal8Bit() << "\",\n";
        file << "        \"vendor\": \"" << entry.vendor.toLocal8Bit() << "\",\n";
        file << "        \"checksumAlgorithm\": \"" << entry.checksumAlgorithm.toLocal8Bit() << "\",\n";
        file << "        \"securityAttributes\": \"" << entry.securityAttributes.toLocal8Bit() << "\",\n";
        file << "        \"compatibility\": \"" << entry.compatibility.toLocal8Bit() << "\",\n";
        file << "        \"description\": \"" << entry.description.toLocal8Bit() << "\",\n";
        file << "        \"sourceLocation\": \"" << entry.sourceLocation.toLocal8Bit() << "\",\n";
        file << "        \"contactInfo\": \"" << entry.contactInfo.toLocal8Bit() << "\",\n";
        file << "        \"externalReferences\": \"" << entry.externalReferences.toLocal8Bit() << "\",\n";
        file << "        \"company\": \"" << entry.company.toLocal8Bit() << "\",\n";
        file << "        \"fileDescription\": \"" << entry.fileDescription.toLocal8Bit() << "\",\n";
        file << "        \"fileVersion\": \"" << entry.fileVersion.toLocal8Bit() << "\",\n";
        file << "        \"copyright\": \"" << entry.copyright.toLocal8Bit() << "\",\n";
        file << "        \"digitalSigner\": \"" << entry.signerCN.toLocal8Bit() << "\",\n";
        file << "        \"peVersion\": \"" << entry.peVersion.toLocal8Bit() << "\",\n";
        file << "        \"sha256Hash\": \"" << entry.sha256Hash.toLocal8Bit() << "\",\n";
        file << "        \"isPe32File\": " << (entry.isPe32File ? "true" : "false") << ",\n";
        file << "        \"parentFfsGuid\": \"" << entry.parentFfsGuid.toLocal8Bit() << "\",\n";
        file << "        \"parentFfsName\": \"" << entry.parentFfsName.toLocal8Bit() << "\",\n";
        file << "        \"peFileName\": \"" << entry.peFileName.toLocal8Bit() << "\",\n";
        file << "        \"peSectionType\": \"" << entry.peSectionType.toLocal8Bit() << "\",\n";
        file << "        \"peSectionOffset\": \"0x" << std::hex << entry.peSectionOffset << "\",\n";
        file << "        \"peSectionSize\": " << std::dec << entry.peSectionSize << ",\n";

        file << "        \"containedPeFiles\": [";
        for (size_t j = 0; j < entry.containedPeFiles.size(); j++) {
            if (j > 0) file << ", ";
            file << "\"" << entry.containedPeFiles[j].toLocal8Bit() << "\"";
        }
        file << "],\n";

        file << "        \"dependencies\": [";
        for (size_t j = 0; j < entry.dependencies.size(); j++) {
            if (j > 0) file << ", ";
            file << "\"" << entry.dependencies[j].toLocal8Bit() << "\"";
        }
        file << "]\n";

        if (i < sbomEntries.size() - 1) {
            file << "      },\n";
        } else {
            file << "      }\n";
        }
    }

    file << "    ]\n";
    file << "  }\n";
    file << "}\n";

    file.close();
    logProgress("SBOM exported to JSON file: " + filepath);
    return U_SUCCESS;
}

void FfsSbomParser::logProgress(const UString& message, bool isError)
{
    if (isError) {
        printf("ERROR: %s\n", (const char*)message.toLocal8Bit());
    } else {
        printf("INFO: %s\n", (const char*)message.toLocal8Bit());
    }
}

UString FfsSbomParser::extractComponentType(const UModelIndex& index)
{
    // Determine component type based on FFS file type
    UINT8 fileType = model->subtype(index);

    switch (fileType) {
    case EFI_FV_FILETYPE_DRIVER:
        return "Driver";
    case EFI_FV_FILETYPE_APPLICATION:
        return "Application";
    case EFI_FV_FILETYPE_PEIM:
        return "PEIM";
    case EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
        return "Firmware Volume";
    case EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER:
        return "Combined PEIM/Driver";
    case EFI_FV_FILETYPE_RAW:
        return "Raw";
    case EFI_FV_FILETYPE_FREEFORM:
        return "Freeform";
    case EFI_FV_FILETYPE_SECURITY_CORE:
        return "Security Core";
    case EFI_FV_FILETYPE_PEI_CORE:
        return "PEI Core";
    case EFI_FV_FILETYPE_DXE_CORE:
        return "DXE Core";
    case EFI_FV_FILETYPE_MM:
        return "MM";
    case EFI_FV_FILETYPE_COMBINED_MM_DXE:
        return "Combined MM/DXE";
    case EFI_FV_FILETYPE_MM_CORE:
        return "MM Core";
    case EFI_FV_FILETYPE_MM_STANDALONE:
        return "MM Standalone";
    case EFI_FV_FILETYPE_MM_CORE_STANDALONE:
        return "MM Core Standalone";
    default:
        return "Unknown";
    }
}

UString FfsSbomParser::extractArchitecture(const UModelIndex& index)
{
    // Try to extract architecture from PE header if present
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        if (bodyData.size() >= 64) {
            // Check for PE signature
            if (bodyData[0] == 'M' && bodyData[1] == 'Z') {
                UINT32 peOffset = readUnaligned((const UINT32*)(bodyData.constData() + 60));
                if (peOffset + 24 <= bodyData.size()) {
                    if (bodyData[peOffset] == 'P' && bodyData[peOffset + 1] == 'E') {
                        UINT16 machine = readUnaligned((const UINT16*)(bodyData.constData() + peOffset + 4));
                        switch (machine) {
                        case 0x014c: return "x86";
                        case 0x8664: return "x64";
                        case 0x01c0: return "ARM";
                        case 0xaa64: return "ARM64";
                        case 0x01f0: return "RISC-V";
                        default: return "Unknown";
                        }
                    }
                }
            }
        }
    }
    return "Unknown";
}

UString FfsSbomParser::extractBuildDate(const UModelIndex& index)
{
    // Try to extract build date from PE header or version info
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        if (bodyData.size() >= 64) {
            // Check for PE signature
            if (bodyData[0] == 'M' && bodyData[1] == 'Z') {
                UINT32 peOffset = readUnaligned((const UINT32*)(bodyData.constData() + 60));
                if (peOffset + 24 <= bodyData.size()) {
                    if (bodyData[peOffset] == 'P' && bodyData[peOffset + 1] == 'E') {
                        UINT32 timestamp = readUnaligned((const UINT32*)(bodyData.constData() + peOffset + 8));
                        if (timestamp != 0) {
                            // Convert timestamp to date string (simplified)
                            return usprintf("Timestamp: 0x%08X", timestamp);
                        }
                    }
                }
            }
        }
    }
    return "Unknown";
}

UString FfsSbomParser::extractVendor(const UModelIndex& index)
{
    // Try to extract vendor from GUID database or PE metadata
    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        if (headerData.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)headerData.constData();
            UString guid = guidToString(header->Name);

            // Check for known vendor GUIDs
            if (guid.find("A7717414-C616-4977-9420-844712A735BF") != (size_t)-1) {
                return "Microsoft";
            } else if (guid.find("3B6686BD-0D76-4030-B70E-B5519E2FC5A0") != (size_t)-1) {
                return "Intel";
            } else if (guid.find("1BA0062E-C779-4582-8566-336AE8F78F09") != (size_t)-1) {
                return "AMI";
            } else if (guid.find("4C19049F-4137-4DD3-9C10-8B97A83FFDFA") != (size_t)-1) {
                return "Phoenix";
            }
        }
    }

    // Try to detect vendor from component name
    UString componentName = model->text(index);
    if (!componentName.isEmpty()) {
        if (componentName.find("Intel") != (size_t)-1) {
            return "Intel";
        } else if (componentName.find("Microsoft") != (size_t)-1) {
            return "Microsoft";
        } else if (componentName.find("AMI") != (size_t)-1) {
            return "AMI";
        } else if (componentName.find("Phoenix") != (size_t)-1) {
            return "Phoenix";
        } else if (componentName.find("Dell") != (size_t)-1) {
            return "Dell";
        } else if (componentName.find("HP") != (size_t)-1) {
            return "HP";
        } else if (componentName.find("Lenovo") != (size_t)-1) {
            return "Lenovo";
        }
    }

    return "Unknown";
}

UString FfsSbomParser::extractSecurityAttributes(const UModelIndex& index)
{
    // Check for security-related attributes
    UString attributes;

    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        if (headerData.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)headerData.constData();

            if (header->Attributes & FFS_ATTRIB_FIXED) {
                if (!attributes.isEmpty()) attributes += ", ";
                attributes += "Fixed";
            }
            if (header->Attributes & FFS_ATTRIB_DATA_ALIGNMENT2) {
                if (!attributes.isEmpty()) attributes += ", ";
                attributes += "DataAligned";
            }
            if (header->Attributes & FFS_ATTRIB_CHECKSUM) {
                if (!attributes.isEmpty()) attributes += ", ";
                attributes += "Checksummed";
            }
        }
    }

    return attributes.isEmpty() ? "None" : attributes;
}

UString FfsSbomParser::extractCompatibility(const UModelIndex& index)
{
    // Determine UEFI compatibility based on file type and attributes
    UString compatibility = "UEFI 2.0+";

    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        if (headerData.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)headerData.constData();

            // Check for FFS3 attributes (UEFI 2.4+)
            if (header->Attributes & FFS_ATTRIB_LARGE_FILE) {
                compatibility = "UEFI 2.4+";
            }
        }
    }

    return compatibility;
}

UString FfsSbomParser::extractDescription(const UModelIndex& index)
{
    // Try to get description from UI section or text field
    UString description = extractUiString(index);
    if (!description.isEmpty()) {
        return description;
    }

    description = model->text(index);
    if (!description.isEmpty()) {
        return description;
    }

    // Provide meaningful descriptions based on file type and name
    UString componentName = model->text(index);
    UINT8 fileType = model->subtype(index);

    switch (fileType) {
    case EFI_FV_FILETYPE_DRIVER:
        return usprintf("UEFI Driver: %s", componentName.toLocal8Bit());
    case EFI_FV_FILETYPE_APPLICATION:
        return usprintf("UEFI Application: %s", componentName.toLocal8Bit());
    case EFI_FV_FILETYPE_PEIM:
        return usprintf("PEI Module: %s", componentName.toLocal8Bit());
    case EFI_FV_FILETYPE_FREEFORM:
        if (componentName.find("Config") != (size_t)-1 || componentName.find("Cfg") != (size_t)-1) {
            return usprintf("Configuration file: %s", componentName.toLocal8Bit());
        } else if (componentName.find("Data") != (size_t)-1) {
            return usprintf("Data file: %s", componentName.toLocal8Bit());
        } else if (componentName.find("Key") != (size_t)-1) {
            return usprintf("Key/Certificate file: %s", componentName.toLocal8Bit());
        } else {
            return usprintf("Freeform data: %s", componentName.toLocal8Bit());
        }
    case EFI_FV_FILETYPE_RAW:
        return usprintf("Raw data: %s", componentName.toLocal8Bit());
    case EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
        return usprintf("Firmware Volume: %s", componentName.toLocal8Bit());
    default:
        return usprintf("UEFI Firmware Component: %s", componentName.toLocal8Bit());
    }
}

UString FfsSbomParser::extractSourceLocation(const UModelIndex& index)
{
    // This would typically be extracted from version resources or metadata
    // For now, return a placeholder
    return "Not Available";
}

UString FfsSbomParser::extractContactInfo(const UModelIndex& index)
{
    // This would typically be extracted from version resources or metadata
    // For now, return a placeholder
    return "Not Available";
}

UString FfsSbomParser::extractExternalReferences(const UModelIndex& index)
{
    // This would typically be extracted from version resources or metadata
    // For now, return a placeholder
    return "Not Available";
}

UString FfsSbomParser::extractCompany(const UModelIndex& index)
{
    // Try to extract company name from PE version resources
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return extractPeVersionResource(bodyData, "CompanyName");
    }
    return UString();
}

UString FfsSbomParser::extractFileDescription(const UModelIndex& index)
{
    // Try to extract file description from PE version resources
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return extractPeVersionResource(bodyData, "FileDescription");
    }
    return UString();
}

UString FfsSbomParser::extractFileVersion(const UModelIndex& index)
{
    // Try to extract file version from PE version resources
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return extractPeVersionResource(bodyData, "FileVersion");
    }
    return UString();
}

UString FfsSbomParser::extractCopyright(const UModelIndex& index)
{
    // Try to extract copyright from PE version resources
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return extractPeVersionResource(bodyData, "LegalCopyright");
    }
    return UString();
}

UString FfsSbomParser::extractSignerCN(const UModelIndex& index)
{
    // Try to extract digital signature common name
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return extractPeDigitalSignature(bodyData);
    }
    return UString();
}

UString FfsSbomParser::calculateSha256Hash(const UModelIndex& index)
{
    // Calculate SHA-256 hash of the PE file body
    if (!model->hasEmptyBody(index)) {
        const UByteArray& bodyData = model->body(index);
        return calculateSha256(bodyData);
    }
    return UString();
}

UString FfsSbomParser::extractPeVersionResource(const UByteArray& peData, const UString& resourceName)
{
    // Basic PE version resource extraction
    // This is a simplified implementation - in a full implementation you'd want more robust PE resource parsing

    if (peData.size() < 64) {
        return UString();
    }

    // Check for PE signature
    if (peData[0] != 'M' || peData[1] != 'Z') {
        return UString();
    }

    // Get PE header offset
    UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
    if (peOffset + 24 > peData.size()) {
        return UString();
    }

    // Check PE signature
    if (peData[peOffset] != 'P' || peData[peOffset + 1] != 'E') {
        return UString();
    }

    // For now, return a placeholder - full PE resource parsing would be complex
    // In a real implementation, you'd parse the resource directory and extract version info
    return UString();
}

UString FfsSbomParser::extractPeDigitalSignature(const UByteArray& peData)
{
    // Basic PE digital signature extraction
    // This is a simplified implementation - in a full implementation you'd want more robust signature parsing

    if (peData.size() < 64) {
        return UString();
    }

    // Check for PE signature
    if (peData[0] != 'M' || peData[1] != 'Z') {
        return UString();
    }

    // Get PE header offset
    UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
    if (peOffset + 24 > peData.size()) {
        return UString();
    }

    // Check PE signature
    if (peData[peOffset] != 'P' || peData[peOffset + 1] != 'E') {
        return UString();
    }

    // For now, return a placeholder - full digital signature parsing would be complex
    // In a real implementation, you'd parse the security directory and extract certificate info
    return UString();
}

UString FfsSbomParser::calculateSha256(const UByteArray& data)
{
    // Calculate SHA-256 hash using the existing implementation
    if (data.isEmpty()) {
        return UString();
    }

    UINT8 hash[SHA256_HASH_SIZE];
    sha256(data.constData(), data.size(), hash);

    // Convert to hex string
    UString result;
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        result += usprintf("%02x", hash[i]);
    }

    return result;
}

bool FfsSbomParser::isPeExecutable(const UModelIndex& index)
{
    // Check if this is a PE executable based on file type
    UINT8 fileType = model->subtype(index);

    // PE executable file types
    switch (fileType) {
    case EFI_FV_FILETYPE_DRIVER:
    case EFI_FV_FILETYPE_APPLICATION:
    case EFI_FV_FILETYPE_PEIM:
    case EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER:
    case EFI_FV_FILETYPE_SECURITY_CORE:
    case EFI_FV_FILETYPE_PEI_CORE:
    case EFI_FV_FILETYPE_DXE_CORE:
    case EFI_FV_FILETYPE_MM:
    case EFI_FV_FILETYPE_COMBINED_MM_DXE:
    case EFI_FV_FILETYPE_MM_CORE:
    case EFI_FV_FILETYPE_MM_STANDALONE:
    case EFI_FV_FILETYPE_MM_CORE_STANDALONE:
        return true;
    case EFI_FV_FILETYPE_RAW:
    case EFI_FV_FILETYPE_FREEFORM:
    case EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
        // These might contain PE files, so check the content
        if (!model->hasEmptyBody(index)) {
            const UByteArray& bodyData = model->body(index);
            if (bodyData.size() >= 64) {
                // Check for PE signature
                if (bodyData[0] == 'M' && bodyData[1] == 'Z') {
                    UINT32 peOffset = readUnaligned((const UINT32*)(bodyData.constData() + 60));
                    if (peOffset + 24 <= bodyData.size()) {
                        if (bodyData[peOffset] == 'P' && bodyData[peOffset + 1] == 'E') {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    default:
        return false;
    }
}

void FfsSbomParser::parseFfsFileRecursive(const UModelIndex& index, const UString& basePath)
{
    if (!index.isValid()) {
        return;
    }

    // Parse the current FFS file
    parseFfsFile(index, basePath);

    // Recursively parse children (sections, nested volumes, etc.)
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            parseFfsFileRecursive(childIndex, basePath);
        }
    }
}

bool FfsSbomParser::extractPeMetadataFromFfs(const UModelIndex& index, SbomEntry& entry)
{
    bool metadataFound = false;

    // Search for PE sections within this FFS file
    searchForPeSections(index, entry, metadataFound);

    // Also search for version sections
    UString versionFromSection = searchForVersionSection(index);
    if (!versionFromSection.isEmpty()) {
        entry.version = versionFromSection;
        metadataFound = true;
    }

    return metadataFound;
}

void FfsSbomParser::searchForPeSections(const UModelIndex& index, SbomEntry& entry, bool& metadataFound)
{
    if (!index.isValid()) {
        return;
    }

    // Check if this is a PE section
    if (model->type(index) == Types::Section) {
        UINT8 sectionType = model->subtype(index);
        if (sectionType == EFI_SECTION_PE32 || sectionType == EFI_SECTION_TE) {
            // Found a PE section, extract metadata
            extractPeMetadataFromSection(index, entry, metadataFound);
        }
    }

    // Recursively search children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            searchForPeSections(childIndex, entry, metadataFound);
        }
    }
}

void FfsSbomParser::extractPeMetadataFromSection(const UModelIndex& index, SbomEntry& entry, bool& metadataFound)
{
    if (!model->hasEmptyBody(index)) {
        const UByteArray& peData = model->body(index);

        // Extract PE metadata from the section data
        UString company = extractPeVersionResource(peData, "CompanyName");
        UString fileDesc = extractPeVersionResource(peData, "FileDescription");
        UString fileVer = extractPeVersionResource(peData, "FileVersion");
        UString copyright = extractPeVersionResource(peData, "LegalCopyright");
        UString signer = extractPeDigitalSignature(peData);
        UString peVer = extractPeVersionResource(peData, "FileVersion");
        UString sha256 = calculateSha256(peData);

        // Update entry with found metadata (only if not already set)
        if (!company.isEmpty()) {
            entry.company = company;
            metadataFound = true;
        }
        if (!fileDesc.isEmpty()) {
            entry.fileDescription = fileDesc;
            metadataFound = true;
        }
        if (!fileVer.isEmpty()) {
            entry.fileVersion = fileVer;
            metadataFound = true;
        }
        if (!copyright.isEmpty()) {
            entry.copyright = copyright;
            metadataFound = true;
        }
        if (!signer.isEmpty()) {
            entry.signerCN = signer;
            metadataFound = true;
        }
        if (!peVer.isEmpty()) {
            entry.peVersion = peVer;
            metadataFound = true;
        }
        if (!sha256.isEmpty()) {
            entry.sha256Hash = sha256;
            metadataFound = true;
        }

        // Also extract architecture from PE header
        UString arch = extractArchitectureFromPeData(peData);
        if (!arch.isEmpty() && entry.architecture == "Unknown") {
            entry.architecture = arch;
        }

        // Extract build date from PE header
        UString buildDate = extractBuildDateFromPeData(peData);
        if (!buildDate.isEmpty() && entry.buildDate == "Unknown") {
            entry.buildDate = buildDate;
        }
    }
}

UString FfsSbomParser::extractArchitectureFromPeData(const UByteArray& peData)
{
    if (peData.size() >= 64) {
        // Check for PE signature
        if (peData[0] == 'M' && peData[1] == 'Z') {
            UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
            if (peOffset + 24 <= peData.size()) {
                if (peData[peOffset] == 'P' && peData[peOffset + 1] == 'E') {
                    UINT16 machine = readUnaligned((const UINT16*)(peData.constData() + peOffset + 4));
                    switch (machine) {
                    case 0x014c: return "x86";
                    case 0x8664: return "x64";
                    case 0x01c0: return "ARM";
                    case 0xaa64: return "ARM64";
                    case 0x01f0: return "RISC-V";
                    default: return "Unknown";
                    }
                }
            }
        }
    }
    return UString();
}

UString FfsSbomParser::extractBuildDateFromPeData(const UByteArray& peData)
{
    if (peData.size() >= 64) {
        // Check for PE signature
        if (peData[0] == 'M' && peData[1] == 'Z') {
            UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
            if (peOffset + 24 <= peData.size()) {
                if (peData[peOffset] == 'P' && peData[peOffset + 1] == 'E') {
                    UINT32 timestamp = readUnaligned((const UINT32*)(peData.constData() + peOffset + 8));
                    if (timestamp != 0) {
                        return usprintf("Timestamp: 0x%08X", timestamp);
                    }
                }
            }
        }
    }
    return UString();
}

UString FfsSbomParser::extractVersionStringFromVersionSection(const UModelIndex& ffsIndex) {
    for (int i = 0; i < model->rowCount(ffsIndex); i++) {
        UModelIndex child = ffsIndex.child(i, 0);
        if (model->type(child) == Types::Section &&
            model->subtype(child) == EFI_SECTION_VERSION) {
            const UByteArray& body = model->body(child);
            if (!body.isEmpty()) {
                return uFromUcs2(body.constData());
            }
        }
    }
    return UString();
}

UString FfsSbomParser::extractVersionFromVersionSection(const UModelIndex& index)
{
    // Search for version sections within this FFS file
    return searchForVersionSection(index);
}

UString FfsSbomParser::searchForVersionSection(const UModelIndex& index)
{
    if (!index.isValid()) {
        return UString();
    }

    // Check if this is a version section
    if (model->type(index) == Types::Section) {
        UINT8 sectionType = model->subtype(index);
        if (sectionType == EFI_SECTION_VERSION) {
            // Found a version section, extract version info
            return parseVersionSection(index);
        }
    }

    // Recursively search children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            UString version = searchForVersionSection(childIndex);
            if (!version.isEmpty()) {
                return version;
            }
        }
    }

    return UString();
}

UString FfsSbomParser::parseVersionSection(const UModelIndex& index)
{
    if (!model->hasEmptyBody(index)) {
        const UByteArray& versionData = model->body(index);

        // Parse version section data
        // EFI_VERSION_SECTION contains a UINT16 BuildNumber
        if (versionData.size() >= sizeof(UINT16)) {
            UINT16 buildNumber = readUnaligned((const UINT16*)versionData.constData());
            return usprintf("Build %u", buildNumber);
        }
    }

    // Also check the info field for version information
    UString info = model->info(index);
    if (!info.isEmpty()) {
        // Look for build number in info
        size_t pos = info.find("Build number:");
        if (pos != (size_t)-1) {
            size_t start = pos + 13; // "Build number:" length
            size_t end = info.find('\n', start);
            if (end == (size_t)-1) end = info.length();
            UString buildStr = info.mid(start, end - start);
            trimws(buildStr);
            if (!buildStr.isEmpty()) {
                return usprintf("Build %s", buildStr.toLocal8Bit());
            }
        }

        // Look for version string in info
        pos = info.find("Version string:");
        if (pos != (size_t)-1) {
            size_t start = pos + 15; // "Version string:" length
            size_t end = info.find('\n', start);
            if (end == (size_t)-1) end = info.length();
            UString versionStr = info.mid(start, end - start);
            trimws(versionStr);
            if (!versionStr.isEmpty()) {
                return versionStr;
            }
        }
    }

    return UString();
}

// PE32 file identification and parsing methods

void FfsSbomParser::identifyPe32FilesInFfs(const UModelIndex& index, SbomEntry& ffsEntry)
{
    if (!index.isValid()) {
        return;
    }

    // Extract PE32 files from this FFS file
    std::vector<SbomEntry> peEntries = extractPe32FilesFromFfs(index, ffsEntry.guid, ffsEntry.componentName);

    // Update the FFS entry with information about contained PE files
    updateFfsEntryWithPeFiles(ffsEntry, peEntries);

    // Add PE32 entries to the main SBOM entries list
    for (const auto& peEntry : peEntries) {
        sbomEntries.push_back(peEntry);
        logProgress("Identified PE32 file: " + peEntry.peFileName + " in " + ffsEntry.componentName);
    }
}

std::vector<SbomEntry> FfsSbomParser::extractPe32FilesFromFfs(const UModelIndex& index, const UString& parentGuid, const UString& parentName)
{
    std::vector<SbomEntry> peEntries;

    if (!index.isValid()) {
        return peEntries;
    }

    // Check if this is a PE section
    if (model->type(index) == Types::Section) {
        UINT8 sectionType = model->subtype(index);
        if (sectionType == EFI_SECTION_PE32 || sectionType == EFI_SECTION_TE) {
            // Create a separate SBOM entry for this PE32 file
            SbomEntry peEntry = createPe32Entry(index, parentGuid, parentName, "");
            peEntries.push_back(peEntry);
        }
    }

    // Recursively search children for PE sections
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            std::vector<SbomEntry> childPeEntries = extractPe32FilesFromFfs(childIndex, parentGuid, parentName);
            peEntries.insert(peEntries.end(), childPeEntries.begin(), childPeEntries.end());
        }
    }

    return peEntries;
}

SbomEntry FfsSbomParser::createPe32Entry(const UModelIndex& peSection, const UString& parentGuid, const UString& parentName, const UString& basePath)
{
    SbomEntry entry;

    // Initialize all fields to empty/default values
    entry.componentName = "";
    entry.guid = "";
    entry.version = "";
    entry.hash = "";
    entry.license = "";
    entry.dependencies.clear();
    entry.filePath = "";
    entry.type = "";
    entry.subtype = "";
    entry.offset = 0;
    entry.size = 0;
    entry.componentType = "";
    entry.architecture = "";
    entry.buildDate = "";
    entry.vendor = "";
    entry.checksumAlgorithm = "";
    entry.securityAttributes = "";
    entry.compatibility = "";
    entry.description = "";
    entry.sourceLocation = "";
    entry.contactInfo = "";
    entry.externalReferences = "";
    entry.company = "";
    entry.fileDescription = "";
    entry.fileVersion = "";
    entry.copyright = "";
    entry.signerCN = "";
    entry.peVersion = "";
    entry.sha256Hash = "";
    entry.parentFfsGuid = "";
    entry.parentFfsName = "";
    entry.peFileName = "";
    entry.peSectionType = "";
    entry.peSectionOffset = 0;
    entry.peSectionSize = 0;
    entry.isPe32File = false;
    entry.containedPeFiles.clear();

    // Mark this as a PE32 file entry
    entry.isPe32File = true;
    entry.parentFfsGuid = parentGuid;
    entry.parentFfsName = parentName;

    // Extract PE-specific information
    entry.peFileName = extractPeFileName(peSection, parentName);
    entry.peSectionType = determinePeSectionType(peSection);
    entry.peSectionOffset = model->offset(peSection);
    entry.peSectionSize = model->body(peSection).size();

    // Set basic component information
    entry.componentName = entry.peFileName;
    entry.guid = usprintf("PE32_%s_%08X", parentGuid.toLocal8Bit(), entry.peSectionOffset);
    entry.type = "PE32_File";
    entry.subtype = entry.peSectionType;
    entry.offset = entry.peSectionOffset;
    entry.size = entry.peSectionSize;
    entry.filePath = usprintf("%s/%s", basePath.toLocal8Bit(), entry.peFileName.toLocal8Bit());

    // Extract PE metadata from the section
    if (!model->hasEmptyBody(peSection)) {
        const UByteArray& peData = model->body(peSection);

        // Extract comprehensive PE metadata
        entry.company = extractPeVersionResource(peData, "CompanyName");
        entry.fileDescription = extractPeVersionResource(peData, "FileDescription");
        entry.fileVersion = extractPeVersionResource(peData, "FileVersion");
        entry.copyright = extractPeVersionResource(peData, "LegalCopyright");
        entry.signerCN = extractPeDigitalSignature(peData);
        entry.peVersion = extractPeVersionResource(peData, "FileVersion");
        entry.sha256Hash = calculateSha256(peData);

        // Extract architecture and build information
        entry.architecture = extractArchitectureFromPeData(peData);
        entry.buildDate = extractBuildDateFromPeData(peData);

        // Set version from PE metadata if available
        if (!entry.fileVersion.isEmpty()) {
            entry.version = entry.fileVersion;
        }

        // Set vendor from company if available
        if (!entry.company.isEmpty()) {
            entry.vendor = entry.company;
        } else {
            entry.vendor = "Unknown";
        }
    }

    // Set default values for missing fields
    if (entry.architecture.isEmpty()) entry.architecture = "Unknown";
    if (entry.buildDate.isEmpty()) entry.buildDate = "Unknown";
    if (entry.vendor.isEmpty()) entry.vendor = "Unknown";
    if (entry.license.isEmpty()) entry.license = "Proprietary";
    if (entry.componentType.isEmpty()) entry.componentType = "Driver";
    if (entry.checksumAlgorithm.isEmpty()) entry.checksumAlgorithm = "SHA256";
    if (entry.securityAttributes.isEmpty()) entry.securityAttributes = "Standard";
    if (entry.compatibility.isEmpty()) entry.compatibility = "UEFI 2.x";
    if (entry.description.isEmpty()) entry.description = usprintf("PE32 executable from %s", parentName.toLocal8Bit());

    // Calculate hash
    entry.hash = calculateSha256(model->body(peSection));

    return entry;
}

UString FfsSbomParser::extractPeFileName(const UModelIndex& peSection, const UString& parentName)
{
    // Try to extract filename from PE metadata first
    if (!model->hasEmptyBody(peSection)) {
        const UByteArray& peData = model->body(peSection);
        UString fileDesc = extractPeVersionResource(peData, "FileDescription");
        if (!fileDesc.isEmpty()) {
            // Clean up the file description to use as filename
            UString filename = fileDesc;
            // Replace spaces and special characters
            for (size_t i = 0; i < filename.length(); i++) {
                if (filename[i] == ' ' || filename[i] == '/' || filename[i] == '\\' || filename[i] == ':' || filename[i] == '*') {
                    filename[i] = '_';
                }
            }
            return filename + ".efi";
        }
    }

    // Fallback: use parent name with section type
    UString sectionType = determinePeSectionType(peSection);
    if (sectionType == "PE32") {
        return parentName + ".efi";
    } else if (sectionType == "TE") {
        return parentName + "_TE.efi";
    } else {
        return parentName + "_PE.efi";
    }
}

UString FfsSbomParser::determinePeSectionType(const UModelIndex& peSection)
{
    if (!peSection.isValid()) {
        return "Unknown";
    }

    UINT8 sectionType = model->subtype(peSection);
    switch (sectionType) {
    case EFI_SECTION_PE32:
        return "PE32";
    case EFI_SECTION_TE:
        return "TE";
    default:
        return "Unknown";
    }
}

void FfsSbomParser::updateFfsEntryWithPeFiles(SbomEntry& ffsEntry, const std::vector<SbomEntry>& peEntries)
{
    // Clear existing list
    ffsEntry.containedPeFiles.clear();

    // Add all PE file names to the FFS entry
    for (const auto& peEntry : peEntries) {
        ffsEntry.containedPeFiles.push_back(peEntry.peFileName);
    }

    // Update component type if PE files are found
    if (!peEntries.empty()) {
        if (ffsEntry.componentType.isEmpty() || ffsEntry.componentType == "Unknown") {
            ffsEntry.componentType = "Driver_Module";
        }

        // Update description to mention contained PE files
        if (ffsEntry.description.isEmpty()) {
            ffsEntry.description = usprintf("FFS module containing %zu PE32 executable(s)", peEntries.size());
        }
    }
}