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
#include <fstream>
#include <iostream>
#include <dirent.h>
#include <sys/stat.h>
#include <set>

// Helper function to safely convert UString to const char* for JSON output
const char* safeStringConversion(const UString& str) {
    // Use toLocal8Bit() but ensure we don't get null bytes
    const char* data = str.toLocal8Bit();
    if (data) {
        // Find the first null byte and truncate there
        const char* nullPos = strchr(data, '\0');
        if (nullPos && nullPos != data) {
            // Create a temporary string without null bytes
            static char tempBuffer[4096];
            size_t len = nullPos - data;
            if (len < sizeof(tempBuffer) - 1) {
                strncpy(tempBuffer, data, len);
                tempBuffer[len] = '\0';
                return tempBuffer;
            }
        }
    }
    return data ? data : "";
}

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
    processedComponents.clear();

    // Create the BIOS region hierarchy first
    createBiosRegionHierarchy();

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

            // Count PE files
            size_t peFiles = std::count_if(sbomEntries.begin(), sbomEntries.end(),
                [](const SbomEntry& entry) { return entry.isPe32File; });
            printf("  PE32 Files Found: %zu\n", peFiles);

            // Count FFS files with PE files
            size_t ffsWithPe = std::count_if(sbomEntries.begin(), sbomEntries.end(),
                [](const SbomEntry& entry) { return !entry.isPe32File && !entry.containedPeFiles.empty(); });
            printf("  FFS Files with PE Files: %zu\n", ffsWithPe);
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

    // --- ME REGION SUPPORT ---
    if (model->type(index) == Types::Region && model->subtype(index) == Subtypes::MeRegion) {
        SbomEntry meEntry;
        meEntry.componentName = "ME Region";
        meEntry.type = itemTypeToUString(model->type(index));
        meEntry.subtype = itemSubtypeToUString(model->type(index), model->subtype(index));
        meEntry.offset = model->offset(index);
        meEntry.size = model->body(index).size();
        meEntry.filePath = createDumpMatchingPath(index, basePath);
        meEntry.vendor = "Intel";
        meEntry.description = "Intel Management Engine firmware region";
        meEntry.hash = calculateHash(index);
        meEntry.sha256Hash = meEntry.hash;
        // Enhanced: extract ME version/SKU/build date from body
        const UByteArray& meBody = model->body(index);
        meEntry.version = extractMeVersionFromBody(meBody);
        meEntry.meSku = extractMeSkuFromBody(meBody);
        meEntry.meBuildDate = extractMeBuildDateFromBody(meBody);
        meEntry.componentType = "Firmware";
        // Add more fields as needed
        sbomEntries.push_back(meEntry);
        logProgress("Parsed ME region at offset 0x" + usprintf("%08X", meEntry.offset));
    }
    // --- END ME REGION SUPPORT ---

    // Check if this is an FFS file
    if (model->type(index) == Types::File) {
        // Use enhanced recursive parsing to extract PE metadata from embedded sections
        parseFfsFileRecursive(index, basePath);
    }

    // Skip sections at the top level - they should only appear as children
    if (model->type(index) == Types::Section) {
        return U_SUCCESS;
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

    // Skip if already processed (check both GUID and offset for better deduplication)
    if (!entry.guid.isEmpty() && processedGuids.find(entry.guid) != processedGuids.end()) {
        return true;
    }

    // Also check if we've already processed this component by name and offset
    UString componentKey = entry.componentName + "_" + usprintf("0x%08X", model->offset(index));
    if (processedComponents.find(componentKey) != processedComponents.end()) {
        return true;
    }

    // If we have a GUID, also check if we've already processed this GUID at any offset
    if (!entry.guid.isEmpty()) {
        UString guidKey = "GUID_" + entry.guid;
        if (processedComponents.find(guidKey) != processedComponents.end()) {
            return true;
        }
    }

    // Extract basic information
    entry.componentName = extractComponentName(index);
    entry.version = extractVersion(index);
    entry.build = ""; // Initialize build field
    entry.hash = calculateHash(index);
    entry.sha256Hash = entry.hash; // Use the same hash for both fields
    entry.license = extractLicense(index);
    entry.dependencies = extractDependencies(index);
    entry.filePath = createDumpMatchingPath(index, basePath);
    entry.type = itemTypeToUString(model->type(index));
    entry.subtype = itemSubtypeToUString(model->type(index), model->subtype(index));
    entry.offset = model->offset(index);
    entry.size = model->body(index).size();

    // Extract additional SBOM fields
    entry.componentType = extractComponentType(index);
    entry.architecture = extractArchitecture(index);
    entry.buildDate = extractBuildDate(index);
    entry.vendor = extractVendor(index);
    // Removed checksumAlgorithm since it's always SHA256
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
            // Don't recalculate hash - use the one already calculated
            entry.sha256Hash = entry.hash;

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
            // Don't recalculate hash - use the one already calculated
            entry.sha256Hash = entry.hash;

            // Set default description for non-PE files
            if (entry.description.isEmpty()) {
                entry.description = usprintf("%s configuration file", entry.componentName.toLocal8Bit());
            }
        }
    }

    // Add to entries if it has a GUID (required for identification)
    if (!entry.guid.isEmpty()) {
        // Filter out sections from being top-level SBOM components
        // Sections should only appear as children, not as top-level components
        if (entry.type == "Section") {
            // Skip sections - they should only appear as children
            logProgress("Skipping section from top-level SBOM: " + entry.componentName + " (Type: " + entry.type + ", Subtype: " + entry.subtype + ")");
            return true;
        }

        // Skip components with .efi in their name - these should be handled as PE32 files within their parent
        if (entry.componentName.find(".efi") != (size_t)-1) {
            logProgress("Skipping .efi component from top-level SBOM: " + entry.componentName);
            return true;
        }

        // Generate a fallback component name if none exists
        if (entry.componentName.isEmpty()) {
            entry.componentName = usprintf("FFS_%s", entry.guid.toLocal8Bit());
            logProgress("Generated fallback name for FFS file: " + entry.componentName);
        }

        // Identify and extract PE32 files contained within this FFS file
        identifyPe32FilesInFfs(index, entry);

        // Extract version information from Version sections and update the main component's version field
        extractVersionFromVersionSections(index, entry);

        // Extract FFSv2 specific metadata if subtype is FFSv2
        if (entry.subtype == "FFSv2") {
            UString infoPath = entry.filePath + "/info.txt";
            extractFfsv2Metadata(infoPath, entry);
        }

        // Deduplicate contained PE files
        deduplicateContainedPeFiles(entry);

        // Populate sections vector
        entry.sections.clear();
        for (int i = 0; i < model->rowCount(index); i++) {
            UModelIndex sectionIndex = index.child(i, 0);
            if (!sectionIndex.isValid()) continue;
            SectionInfo section;
            section.type = itemTypeToUString(model->type(sectionIndex));
            section.subtype = itemSubtypeToUString(model->type(sectionIndex), model->subtype(sectionIndex));
            section.offset = model->offset(sectionIndex);
            section.size = model->body(sectionIndex).size();
            section.description = model->text(sectionIndex);
            entry.sections.push_back(section);

            // If this is a Version section, extract the version string
            if (model->type(sectionIndex) == Types::Section && model->subtype(sectionIndex) == EFI_SECTION_VERSION) {
                UString versionStr = extractVersionStringFromVersionSection(sectionIndex);
                if (!versionStr.isEmpty()) {
                    // If this FFS is a PE component, set entry.version
                    if (entry.isPe32File || isPeExecutable(index)) {
                        entry.version = versionStr;
                        logProgress("[DEBUG] Found Version section for PE component '" + entry.componentName + "': " + versionStr);
                    }
                }
            }

            // Check if this is a PE32 image section and create a separate PE32 file entry
            if (model->type(sectionIndex) == Types::Section && model->subtype(sectionIndex) == EFI_SECTION_PE32) {
                // Flag the component as a PE image
                entry.isPe32File = true;
                logProgress("[DEBUG] Found PE32 image section in parseFfsFile for component: " + entry.componentName);

                // Create a separate PE32 file entry
                SbomEntry pe32Entry;
                pe32Entry.componentName = entry.componentName + "_TE.efi";
                pe32Entry.guid = usprintf("PE32_%s_%08X", entry.guid.toLocal8Bit(), model->offset(sectionIndex));
                pe32Entry.type = "PE32_File";
                pe32Entry.subtype = "TE";
                pe32Entry.offset = model->offset(sectionIndex);
                pe32Entry.size = model->body(sectionIndex).size();
                pe32Entry.componentType = "Driver";
                pe32Entry.architecture = "";
                pe32Entry.buildDate = "";
                pe32Entry.vendor = "";
                pe32Entry.securityAttributes = "Standard";
                pe32Entry.compatibility = "UEFI 2.x";
                pe32Entry.description = "PE32 executable from " + entry.componentName;
                pe32Entry.sourceLocation = "";
                pe32Entry.contactInfo = "";
                pe32Entry.externalReferences = "";
                pe32Entry.company = "";
                pe32Entry.fileDescription = "";
                pe32Entry.fileVersion = "";
                pe32Entry.copyright = "";
                pe32Entry.signerCN = "";
                pe32Entry.peVersion = "";
                pe32Entry.sha256Hash = "";
                pe32Entry.parentFfsGuid = entry.guid;
                pe32Entry.parentFfsName = entry.componentName;
                pe32Entry.peFileName = entry.componentName + "_TE.efi";
                pe32Entry.peSectionType = "TE";
                pe32Entry.peSectionOffset = model->offset(sectionIndex);
                pe32Entry.peSectionSize = model->body(sectionIndex).size();

                // Calculate SHA256 hash from the PE32 section data
                if (!model->hasEmptyBody(sectionIndex)) {
                    const UByteArray& peData = model->body(sectionIndex);
                    logProgress("[DEBUG] PE32 section data size: " + usprintf("%d", peData.size()));
                    UINT8 hash[32]; // SHA256 produces 32 bytes
                    sha256(peData.constData(), peData.size(), hash);

                    UString hashString;
                    for (int i = 0; i < 32; i++) {
                        hashString += usprintf("%02X", hash[i]);
                    }

                    // Store the hash in both the parent component and PE32 entry
                    entry.hash = hashString;
                    pe32Entry.hash = hashString;
                    pe32Entry.sha256Hash = hashString;
                    logProgress("Calculated PE32 hash for component " + entry.componentName + ": " + hashString);
                } else {
                    logProgress("[DEBUG] PE32 section has empty body for component: " + entry.componentName);
                }

                // Add PE32 entry to the list
                sbomEntries.push_back(pe32Entry);
                processedGuids.insert(pe32Entry.guid);

                // Add to parent's contained PE files
                entry.containedPeFiles.push_back(pe32Entry.componentName);
            }

            // Check if this is a TE image section and create a separate TE file entry
            if (model->type(sectionIndex) == Types::Section && model->subtype(sectionIndex) == EFI_SECTION_TE) {
                // Flag the component as a PE image
                entry.isPe32File = true;
                logProgress("[DEBUG] Found TE image section in parseFfsFile for component: " + entry.componentName);

                // Create a separate TE file entry
                SbomEntry teEntry;
                teEntry.componentName = entry.componentName + "_TE.efi";
                teEntry.guid = usprintf("TE_%s_%08X", entry.guid.toLocal8Bit(), model->offset(sectionIndex));
                teEntry.type = "PE32_File";
                teEntry.subtype = "TE";
                teEntry.offset = model->offset(sectionIndex);
                teEntry.size = model->body(sectionIndex).size();
                teEntry.componentType = "Driver";
                teEntry.architecture = "";
                teEntry.buildDate = "";
                teEntry.vendor = "";
                teEntry.securityAttributes = "Standard";
                teEntry.compatibility = "UEFI 2.x";
                teEntry.description = "PE32 executable from " + entry.componentName;
                teEntry.sourceLocation = "";
                teEntry.contactInfo = "";
                teEntry.externalReferences = "";
                teEntry.company = "";
                teEntry.fileDescription = "";
                teEntry.fileVersion = "";
                teEntry.copyright = "";
                teEntry.signerCN = "";
                teEntry.peVersion = "";
                teEntry.sha256Hash = "";
                teEntry.parentFfsGuid = entry.guid;
                teEntry.parentFfsName = entry.componentName;
                teEntry.peFileName = entry.componentName + "_TE.efi";
                teEntry.peSectionType = "TE";
                teEntry.peSectionOffset = model->offset(sectionIndex);
                teEntry.peSectionSize = model->body(sectionIndex).size();

                // Calculate SHA256 hash from the TE section data
                if (!model->hasEmptyBody(sectionIndex)) {
                    const UByteArray& teData = model->body(sectionIndex);
                    logProgress("[DEBUG] TE section data size: " + usprintf("%d", teData.size()));
                    UINT8 hash[32]; // SHA256 produces 32 bytes
                    sha256(teData.constData(), teData.size(), hash);

                    UString hashString;
                    for (int i = 0; i < 32; i++) {
                        hashString += usprintf("%02X", hash[i]);
                    }

                    // Store the hash in both the parent component and TE entry
                    entry.hash = hashString;
                    teEntry.hash = hashString;
                    teEntry.sha256Hash = hashString;
                    logProgress("Calculated TE hash for component " + entry.componentName + ": " + hashString);
                } else {
                    logProgress("[DEBUG] TE section has empty body for component: " + entry.componentName);
                }

                // Add TE entry to the list
                sbomEntries.push_back(teEntry);
                processedGuids.insert(teEntry.guid);

                // Add to parent's contained PE files
                entry.containedPeFiles.push_back(teEntry.componentName);
            }
        }

        // Check if this component has PE32 image sections in its children and calculate hash
        checkForPe32ImageSectionsInChildren(index, entry);

        sbomEntries.push_back(entry);
        processedGuids.insert(entry.guid);
        processedComponents.insert(componentKey);
        if (!entry.guid.isEmpty()) {
            processedComponents.insert("GUID_" + entry.guid);
        }
        logProgress("Parsed FFS file: " + entry.componentName);
        return true;
    } else {
        // Try to extract Variable GUID from body (for NVRAM/variable stores)
        UString variableGuid;
        if (!model->hasEmptyBody(index)) {
            const UByteArray& bodyData = model->body(index);
            // Look for a GUID pattern in the first 64 bytes (common for variable stores)
            if (bodyData.size() >= 16) {
                // Try every offset in the first 64 bytes
                for (size_t offset = 0; offset + 16 <= std::min<size_t>(bodyData.size(), 64); offset++) {
                    const EFI_GUID* possibleGuid = (const EFI_GUID*)(bodyData.constData() + offset);
                    UString guidStr = guidToString(*possibleGuid);
                    // Heuristic: GUIDs are not all zero and not all 0xFF
                    bool notAllZero = false, notAllFF = false;
                    for (int i = 0; i < 16; i++) {
                        if (bodyData[offset + i] != 0x00) notAllZero = true;
                        if (bodyData[offset + i] != 0xFF) notAllFF = true;
                    }
                    if (notAllZero && notAllFF) {
                        variableGuid = guidStr;
                        break;
                    }
                }
            }
        }
        if (!variableGuid.isEmpty()) {
            entry.guid = variableGuid;
            logProgress("No FFS GUID found, using Variable GUID from body: " + variableGuid, true);
            identifyPe32FilesInFfs(index, entry);

            // Extract FFSv2 specific metadata if subtype is FFSv2
            if (entry.subtype == "FFSv2") {
                UString infoPath = entry.filePath + "/info.txt";
                extractFfsv2Metadata(infoPath, entry);
            }

            // Deduplicate contained PE files
            deduplicateContainedPeFiles(entry);

            // Populate sections vector
            entry.sections.clear();
            for (int i = 0; i < model->rowCount(index); i++) {
                UModelIndex sectionIndex = index.child(i, 0);
                if (!sectionIndex.isValid()) continue;
                SectionInfo section;
                section.type = itemTypeToUString(model->type(sectionIndex));
                section.subtype = itemSubtypeToUString(model->type(sectionIndex), model->subtype(sectionIndex));
                section.offset = model->offset(sectionIndex);
                section.size = model->body(sectionIndex).size();
                section.description = model->text(sectionIndex);
                entry.sections.push_back(section);

                // If this is a Version section, extract the version string
                if (model->type(sectionIndex) == Types::Section && model->subtype(sectionIndex) == EFI_SECTION_VERSION) {
                    UString versionStr = extractVersionStringFromVersionSection(sectionIndex);
                    if (!versionStr.isEmpty()) {
                        // If this FFS is a PE component, set entry.version
                        if (entry.isPe32File || isPeExecutable(index)) {
                            entry.version = versionStr;
                            logProgress("[DEBUG] Found Version section for PE component '" + entry.componentName + "': " + versionStr);
                        }
                    }
                }

                // Check if this is a PE32 image section and flag the component as a PE image
                if (model->type(sectionIndex) == Types::Section && model->subtype(sectionIndex) == EFI_SECTION_PE32) {
                    // Flag the component as a PE image
                    entry.isPe32File = true;
                    logProgress("[DEBUG] Found PE32 image section in parseFfsFile for component: " + entry.componentName);

                    // Calculate SHA256 hash from the PE32 section data
                    if (!model->hasEmptyBody(sectionIndex)) {
                        const UByteArray& peData = model->body(sectionIndex);
                        logProgress("[DEBUG] PE32 section data size: " + usprintf("%d", peData.size()));
                        UINT8 hash[32]; // SHA256 produces 32 bytes
                        sha256(peData.constData(), peData.size(), hash);

                        UString hashString;
                        for (int i = 0; i < 32; i++) {
                            hashString += usprintf("%02X", hash[i]);
                        }

                        // Store the hash in the component
                        entry.hash = hashString;
                        logProgress("Calculated PE32 hash for component " + entry.componentName + ": " + hashString);
                    } else {
                        logProgress("[DEBUG] PE32 section has empty body for component: " + entry.componentName);
                    }
                }
            }
            sbomEntries.push_back(entry);
            processedGuids.insert(entry.guid);
            processedComponents.insert(componentKey);
            if (!entry.guid.isEmpty()) {
                processedComponents.insert("GUID_" + entry.guid);
            }
            logProgress("Parsed FFS file (Variable GUID): " + entry.componentName);
            return true;
        }
        // Create a descriptive message about the file being skipped
        UString fileInfo = "Skipping FFS file with no GUID and no Variable GUID found";

        // Add component name if available
        if (!entry.componentName.isEmpty()) {
            fileInfo += " - Name: " + entry.componentName;
        }

        // Add file type and subtype if available
        if (!entry.type.isEmpty() || !entry.subtype.isEmpty()) {
            fileInfo += " - Type: ";
            if (!entry.type.isEmpty() && !entry.subtype.isEmpty()) {
                fileInfo += entry.type + "/" + entry.subtype;
            } else if (!entry.type.isEmpty()) {
                fileInfo += entry.type;
            } else {
                fileInfo += entry.subtype;
            }
        }

        // Add offset if available
        if (entry.offset != 0) {
            fileInfo += usprintf(" - Offset: 0x%08X", entry.offset);
        }

        // Add text representation if available
        UString text = model->text(index);
        if (!text.isEmpty()) {
            fileInfo += " - Text: " + text;
        }

        // Add file path if available
        if (!entry.filePath.isEmpty()) {
            fileInfo += " - FilePath: " + entry.filePath;
        }

        logProgress(fileInfo, true);
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

    // Try to generate a name based on file type and subtype
    UString typeStr = itemTypeToUString(model->type(index));
    UString subtypeStr = itemSubtypeToUString(model->type(index), model->subtype(index));
    if (!typeStr.isEmpty() || !subtypeStr.isEmpty()) {
        if (!typeStr.isEmpty() && !subtypeStr.isEmpty()) {
            name = usprintf("%s_%s", typeStr.toLocal8Bit(), subtypeStr.toLocal8Bit());
        } else if (!typeStr.isEmpty()) {
            name = typeStr;
        } else {
            name = subtypeStr;
        }
        // Clean up the name
        for (size_t i = 0; i < name.length(); i++) {
            if (name[i] == ' ' || name[i] == '/' || name[i] == '\\' || name[i] == ':' || name[i] == '*') {
                name[i] = '_';
            }
        }
        if (!name.isEmpty()) {
            return name;
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

    // Then try to get version from version section info files
    UString infoFilePath = searchForVersionInfoFile(index);
    if (!infoFilePath.isEmpty()) {
        version = extractVersionFromInfoFile(infoFilePath);
        if (!version.isEmpty()) {
            logProgress("Extracted version from info file: " + version);
            return version;
        }
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

UString FfsSbomParser::createDumpMatchingPath(const UModelIndex& index, const UString& basePath)
{
    // Build the exact dump directory path by traversing the UEFI model tree
    // This replicates the logic used in ffsdumper.cpp to create directory names
    std::vector<UString> pathComponents;
    UModelIndex currentIndex = index;

    // Traverse up the tree to build the path components
    while (currentIndex.isValid()) {
        UModelIndex parentIndex = currentIndex.parent();
        if (parentIndex.isValid()) {
            // Find the index of this child in its parent
            int childIndex = -1;
            for (int i = 0; i < model->rowCount(parentIndex); i++) {
                if (parentIndex.child(i, 0) == currentIndex) {
                    childIndex = i;
                    break;
                }
            }

            if (childIndex >= 0) {
                // Get the name using the same logic as ffsdumper.cpp
                bool useText = false;
                if (model->type(currentIndex) != Types::Volume) {
                    useText = !model->text(currentIndex).isEmpty();
                }

                UString name = usprintf("%d %s", childIndex,
                    (useText ? model->text(currentIndex) : model->name(currentIndex)).toLocal8Bit());

                // Apply the same fixFileName logic as ffsdumper.cpp
                fixFileName(name, false);

                pathComponents.insert(pathComponents.begin(), name);
            }
        }
        currentIndex = parentIndex;
    }

    // Build the full path starting with the correct dump directory
    UString dumpDir = "/Users/lanceware/Downloads/74.dump";

    // Build the full path
    UString fullPath = dumpDir;
    for (size_t i = 0; i < pathComponents.size(); i++) {
        if (!fullPath.isEmpty() && fullPath[fullPath.length() - 1] != '/') {
            fullPath += "/";
        }
        fullPath += pathComponents[i];
    }

    // Validate that the path actually exists in the file system
    DIR* dir = opendir(fullPath.toLocal8Bit());
    if (dir) {
        closedir(dir);
        return fullPath;
    } else {
        // If the path doesn't exist, return a fallback path based on the component name
        UString componentName = model->name(index);
        if (componentName.isEmpty()) {
            componentName = model->text(index);
        }
        if (componentName.isEmpty()) {
            componentName = "Unknown";
        }

        // Create a fallback path in the dump directory
        UString fallbackPath = usprintf("%s/%s", dumpDir.toLocal8Bit(), componentName.toLocal8Bit());
        logProgress("Warning: Generated path does not exist, using fallback: " + fallbackPath);
        return fallbackPath;
    }
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

        // Special handling for Region/BIOS components
        if (entry.type == "Region" && entry.subtype == "BIOS") {
            file << "  Type: " << entry.type.toLocal8Bit() << "\n";
            file << "  Subtype: " << entry.subtype.toLocal8Bit() << "\n";
            if (!entry.fixed.isEmpty()) {
                file << "  Fixed: " << entry.fixed.toLocal8Bit() << "\n";
            }
            file << "  Base: " << entry.base.toLocal8Bit() << "\n";
            file << "  Address: " << entry.address.toLocal8Bit() << "\n";
            file << "  Offset: 0x" << std::hex << entry.offset << "\n";
            if (!entry.fullSize.isEmpty()) {
                file << "  Full size: " << entry.fullSize.toLocal8Bit() << "\n";
            }
            file << "  File Path: " << entry.filePath.toLocal8Bit() << "\n";

            // Children listing
            if (!entry.children.empty()) {
                file << "  Children:\n";
                for (const auto& child : entry.children) {
                    file << "    - Type: " << child.type.toLocal8Bit() << ", Subtype: " << child.subtype.toLocal8Bit();
                    if (!child.componentName.isEmpty()) {
                        file << ", Name: " << child.componentName.toLocal8Bit();
                    }
                    if (!child.filesystemGuid.isEmpty()) {
                        file << ", FileSystemGUID: " << child.filesystemGuid.toLocal8Bit();
                    }
                    if (!child.volumeGuid.isEmpty()) {
                        file << ", VolumeGUID: " << child.volumeGuid.toLocal8Bit();
                    }
                    file << "\n";
                }
            }
        } else {
            // Standard export for non-Region/BIOS components
        file << "  Component Name: " << entry.componentName.toLocal8Bit() << "\n";
        file << "  GUID: " << entry.guid.toLocal8Bit() << "\n";
        file << "  Version: " << entry.version.toLocal8Bit() << "\n";
            file << "  Build: " << entry.build.toLocal8Bit() << "\n";
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
        // Removed checksumAlgorithm since it's always SHA256
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

            // FFSv2 specific fields (only for FFSv2 subtypes)
            if (entry.subtype == "FFSv2") {
                file << "  Filesystem GUID: " << entry.filesystemGuid.toLocal8Bit() << "\n";
                file << "  Volume GUID: " << entry.volumeGuid.toLocal8Bit() << "\n";
                file << "  Attributes: " << entry.attributes.toLocal8Bit() << "\n";
                file << "  Signature: " << entry.signature.toLocal8Bit() << "\n";
                file << "  Checksum: " << entry.checksum.toLocal8Bit() << "\n";
            }

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

        // Sections block
        if (!entry.sections.empty()) {
            file << "  Sections:\n";
            for (const SectionInfo& section : entry.sections) {
                file << "    - Type: " << section.type.toLocal8Bit();
                file << ", Subtype: " << section.subtype.toLocal8Bit();
                file << ", Offset: 0x" << std::hex << section.offset;
                file << ", Size: " << std::dec << section.size << " bytes";
                if (!section.description.isEmpty()) {
                    file << ", Description: " << section.description.toLocal8Bit();
                }
                file << "\n";
            }
        }

            // Section Info block (for processed subfolder information) - only show non-duplicate info
            if (!entry.sectionInfo.empty()) {
                file << "  Section Info:\n";
                for (const UString& section : entry.sectionInfo) {
                    // Skip duplicate FFSv2 information that's already shown above
                    if (entry.subtype == "FFSv2" &&
                        (section.find("Filesystem GUID:") >= 0 ||
                         section.find("Volume GUID:") >= 0 ||
                         section.find("Attributes:") >= 0 ||
                         section.find("Signature:") >= 0 ||
                         section.find("Checksum:") >= 0)) {
                        continue;
                    }
                    file << "    - " << section.toLocal8Bit() << "\n";
                }
            }

            // Children block (for subfolder components)
            if (!entry.children.empty()) {
                file << "  Children:\n";
                for (const auto& child : entry.children) {
                    file << "    - Type: " << child.type.toLocal8Bit() << ", Subtype: " << child.subtype.toLocal8Bit();
                    if (!child.componentName.isEmpty()) {
                        file << ", Name: " << child.componentName.toLocal8Bit();
                    }
                    file << "\n";
                }
            }
        }

        file << "\n";
    }

    file.close();
    logProgress("SBOM exported to text file: " + filepath);
    return U_SUCCESS;
}

USTATUS FfsSbomParser::exportToStdout()
{
    std::cout << "FFS Software Bill of Materials (SBOM)\n";
    std::cout << "=====================================\n\n";

    for (size_t i = 0; i < sbomEntries.size(); i++) {
        const SbomEntry& entry = sbomEntries[i];

        std::cout << "Component " << (i + 1) << ":\n";

        // Special handling for Region/BIOS components
        if (entry.type == "Region" && entry.subtype == "BIOS") {
            std::cout << "  Type: " << entry.type.toLocal8Bit() << "\n";
            std::cout << "  Subtype: " << entry.subtype.toLocal8Bit() << "\n";
            if (!entry.fixed.isEmpty()) {
                std::cout << "  Fixed: " << entry.fixed.toLocal8Bit() << "\n";
            }
            std::cout << "  Base: " << entry.base.toLocal8Bit() << "\n";
            std::cout << "  Address: " << entry.address.toLocal8Bit() << "\n";
            std::cout << "  Offset: 0x" << std::hex << entry.offset << "\n";
            if (!entry.fullSize.isEmpty()) {
                std::cout << "  Full size: " << entry.fullSize.toLocal8Bit() << "\n";
            }
            std::cout << "  File Path: " << entry.filePath.toLocal8Bit() << "\n";

            // Children listing
            if (!entry.children.empty()) {
                std::cout << "  Children:\n";
                for (const auto& child : entry.children) {
                    std::cout << "    - Type: " << child.type.toLocal8Bit() << ", Subtype: " << child.subtype.toLocal8Bit();
                    if (!child.componentName.isEmpty()) {
                        std::cout << ", Name: " << child.componentName.toLocal8Bit();
                    }
                    if (!child.filesystemGuid.isEmpty()) {
                        std::cout << ", FileSystemGUID: " << child.filesystemGuid.toLocal8Bit();
                    }
                    if (!child.volumeGuid.isEmpty()) {
                        std::cout << ", VolumeGUID: " << child.volumeGuid.toLocal8Bit();
                    }
                    std::cout << "\n";
                }
            }
        } else {
            // Standard export for non-Region/BIOS components
            std::cout << "  Component Name: " << entry.componentName.toLocal8Bit() << "\n";
            std::cout << "  GUID: " << entry.guid.toLocal8Bit() << "\n";
            std::cout << "  Version: " << entry.version.toLocal8Bit() << "\n";
            std::cout << "  Build: " << entry.build.toLocal8Bit() << "\n";
            std::cout << "  Hash (SHA256): " << entry.hash.toLocal8Bit() << "\n";
            std::cout << "  License: " << entry.license.toLocal8Bit() << "\n";
            std::cout << "  Type: " << entry.type.toLocal8Bit() << "\n";
            std::cout << "  Subtype: " << entry.subtype.toLocal8Bit() << "\n";
            std::cout << "  Offset: 0x" << std::hex << entry.offset << "\n";
            std::cout << "  Size: " << std::dec << entry.size << " bytes\n";
            std::cout << "  File Path: " << entry.filePath.toLocal8Bit() << "\n";

            // Additional SBOM fields
            std::cout << "  Component Type: " << entry.componentType.toLocal8Bit() << "\n";
            std::cout << "  Architecture: " << entry.architecture.toLocal8Bit() << "\n";
            std::cout << "  Build Date: " << entry.buildDate.toLocal8Bit() << "\n";
            std::cout << "  Vendor: " << entry.vendor.toLocal8Bit() << "\n";
            // Removed checksumAlgorithm since it's always SHA256
            std::cout << "  Security Attributes: " << entry.securityAttributes.toLocal8Bit() << "\n";
            std::cout << "  Compatibility: " << entry.compatibility.toLocal8Bit() << "\n";
            std::cout << "  Description: " << entry.description.toLocal8Bit() << "\n";
            std::cout << "  Source Location: " << entry.sourceLocation.toLocal8Bit() << "\n";
            std::cout << "  Contact Info: " << entry.contactInfo.toLocal8Bit() << "\n";
            std::cout << "  External References: " << entry.externalReferences.toLocal8Bit() << "\n";

            // PE metadata fields
            std::cout << "  Company: " << entry.company.toLocal8Bit() << "\n";
            std::cout << "  File Description: " << entry.fileDescription.toLocal8Bit() << "\n";
            std::cout << "  File Version: " << entry.fileVersion.toLocal8Bit() << "\n";
            std::cout << "  Copyright: " << entry.copyright.toLocal8Bit() << "\n";
            std::cout << "  Digital Signer: " << entry.signerCN.toLocal8Bit() << "\n";
            std::cout << "  PE Version: " << entry.peVersion.toLocal8Bit() << "\n";
            std::cout << "  SHA-256 Hash: " << entry.sha256Hash.toLocal8Bit() << "\n";

            // FFSv2 specific fields (only for FFSv2 subtypes)
            if (entry.subtype == "FFSv2") {
                std::cout << "  Filesystem GUID: " << entry.filesystemGuid.toLocal8Bit() << "\n";
                std::cout << "  Volume GUID: " << entry.volumeGuid.toLocal8Bit() << "\n";
                std::cout << "  Attributes: " << entry.attributes.toLocal8Bit() << "\n";
                std::cout << "  Signature: " << entry.signature.toLocal8Bit() << "\n";
                std::cout << "  Checksum: " << entry.checksum.toLocal8Bit() << "\n";
            }

            // PE32 file tracking fields
            std::cout << "  Is PE32 File: " << (entry.isPe32File ? "Yes" : "No") << "\n";
            if (entry.isPe32File) {
                std::cout << "  Parent FFS GUID: " << entry.parentFfsGuid.toLocal8Bit() << "\n";
                std::cout << "  Parent FFS Name: " << entry.parentFfsName.toLocal8Bit() << "\n";
                std::cout << "  PE File Name: " << entry.peFileName.toLocal8Bit() << "\n";
                std::cout << "  PE Section Type: " << entry.peSectionType.toLocal8Bit() << "\n";
                std::cout << "  PE Section Offset: 0x" << std::hex << entry.peSectionOffset << "\n";
                std::cout << "  PE Section Size: " << std::dec << entry.peSectionSize << " bytes\n";
            }
            if (!entry.containedPeFiles.empty()) {
                std::cout << "  Contained PE Files:\n";
                for (const UString& peFile : entry.containedPeFiles) {
                    std::cout << "    - " << peFile.toLocal8Bit() << "\n";
                }
            }

            if (!entry.dependencies.empty()) {
                std::cout << "  Dependencies:\n";
                for (const UString& dep : entry.dependencies) {
                    std::cout << "    - " << dep.toLocal8Bit() << "\n";
                }
            }

            // Sections block
            if (!entry.sections.empty()) {
                std::cout << "  Sections:\n";
                for (const SectionInfo& section : entry.sections) {
                    std::cout << "    - Type: " << section.type.toLocal8Bit();
                    std::cout << ", Subtype: " << section.subtype.toLocal8Bit();
                    std::cout << ", Offset: 0x" << std::hex << section.offset;
                    std::cout << ", Size: " << std::dec << section.size << " bytes";
                    if (!section.description.isEmpty()) {
                        std::cout << ", Description: " << section.description.toLocal8Bit();
                    }
                    std::cout << "\n";
                }
            }

            // Section Info block (for processed subfolder information) - only show non-duplicate info
            if (!entry.sectionInfo.empty()) {
                std::cout << "  Section Info:\n";
                for (const UString& section : entry.sectionInfo) {
                    // Skip duplicate FFSv2 information that's already shown above
                    if (entry.subtype == "FFSv2" &&
                        (section.find("Filesystem GUID:") >= 0 ||
                         section.find("Volume GUID:") >= 0 ||
                         section.find("Attributes:") >= 0 ||
                         section.find("Signature:") >= 0 ||
                         section.find("Checksum:") >= 0)) {
                        continue;
                    }
                    std::cout << "    - " << section.toLocal8Bit() << "\n";
                }
            }

            // Children block (for subfolder components)
            if (!entry.children.empty()) {
                std::cout << "  Children:\n";
                for (const auto& child : entry.children) {
                    std::cout << "    - Type: " << child.type.toLocal8Bit() << ", Subtype: " << child.subtype.toLocal8Bit();
                    if (!child.componentName.isEmpty()) {
                        std::cout << ", Name: " << child.componentName.toLocal8Bit();
                    }
                    std::cout << "\n";
                }
            }
        }

        std::cout << "\n";
    }

    logProgress("SBOM exported to stdout");
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
    file << "Component Name,GUID,Version,Hash,License,Type,Subtype,Offset,Size,File Path,Component Type,Architecture,Build Date,Vendor,Security Attributes,Compatibility,Description,Source Location,Contact Info,External References,Company,File Description,File Version,Copyright,Digital Signer,PE Version,SHA-256 Hash,Is PE32 File,Parent FFS GUID,Parent FFS Name,PE File Name,PE Section Type,PE Section Offset,PE Section Size,Contained PE Files,Dependencies\n";

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
        // Removed checksumAlgorithm since it's always SHA256
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



USTATUS FfsSbomParser::exportToJsonStdout()
{
    std::cout << "{\n";
    std::cout << "  \"sbom\": {\n";
    std::cout << "    \"format\": \"FFS Software Bill of Materials\",\n";
    std::cout << "    \"version\": \"1.0\",\n";
    std::cout << "    \"components\": [\n";

    for (size_t i = 0; i < sbomEntries.size(); i++) {
        const SbomEntry& entry = sbomEntries[i];

        std::cout << "      {\n";
        std::cout << "        \"componentName\": \"" << entry.componentName.toLocal8Bit() << "\",\n";
        std::cout << "        \"guid\": \"" << entry.guid.toLocal8Bit() << "\",\n";
        std::cout << "        \"version\": \"" << entry.version.toLocal8Bit() << "\",\n";
        std::cout << "        \"build\": \"" << entry.build.toLocal8Bit() << "\",\n";
        std::cout << "        \"hash\": \"" << entry.hash.toLocal8Bit() << "\",\n";
        std::cout << "        \"license\": \"" << entry.license.toLocal8Bit() << "\",\n";
        std::cout << "        \"type\": \"" << entry.type.toLocal8Bit() << "\",\n";
        std::cout << "        \"subtype\": \"" << entry.subtype.toLocal8Bit() << "\",\n";
        std::cout << "        \"offset\": \"0x" << std::hex << entry.offset << "\",\n";
        std::cout << "        \"size\": " << std::dec << entry.size << ",\n";
        std::cout << "        \"componentType\": \"" << (entry.componentType == "Unknown" ? "" : entry.componentType.toLocal8Bit()) << "\",\n";
        std::cout << "        \"architecture\": \"" << (entry.architecture == "Unknown" ? "" : entry.architecture.toLocal8Bit()) << "\",\n";
        std::cout << "        \"buildDate\": \"" << (entry.buildDate == "Unknown" ? "" : entry.buildDate.toLocal8Bit()) << "\",\n";
        std::cout << "        \"vendor\": \"" << (entry.vendor == "Unknown" ? "" : entry.vendor.toLocal8Bit()) << "\",\n";
        // Removed checksumAlgorithm since it's always SHA256
        std::cout << "        \"securityAttributes\": \"" << (entry.securityAttributes == "None" ? "" : entry.securityAttributes.toLocal8Bit()) << "\",\n";
        std::cout << "        \"compatibility\": \"" << (entry.compatibility == "UEFI 2.0+" ? "" : entry.compatibility.toLocal8Bit()) << "\",\n";
        std::cout << "        \"description\": \"" << (entry.description == "UEFI Firmware Component: " ? "" : entry.description.toLocal8Bit()) << "\",\n";
        std::cout << "        \"sourceLocation\": \"" << (entry.sourceLocation == "Not Available" ? "" : entry.sourceLocation.toLocal8Bit()) << "\",\n";
        std::cout << "        \"contactInfo\": \"" << (entry.contactInfo == "Not Available" ? "" : entry.contactInfo.toLocal8Bit()) << "\",\n";
        std::cout << "        \"externalReferences\": \"" << (entry.externalReferences == "Not Available" ? "" : entry.externalReferences.toLocal8Bit()) << "\",\n";
        std::cout << "        \"company\": \"" << (entry.company == "N/A (Non-PE file)" ? "" : entry.company.toLocal8Bit()) << "\",\n";
        std::cout << "        \"fileDescription\": \"" << (entry.fileDescription == "UEFI Firmware Component: " ? "" : entry.fileDescription.toLocal8Bit()) << "\",\n";
        std::cout << "        \"fileVersion\": \"" << (entry.fileVersion == "N/A" ? "" : entry.fileVersion.toLocal8Bit()) << "\",\n";
        std::cout << "        \"copyright\": \"" << (entry.copyright == "N/A (Non-PE file)" ? "" : entry.copyright.toLocal8Bit()) << "\",\n";
        std::cout << "        \"digitalSigner\": \"" << (entry.signerCN == "N/A (Non-PE file)" ? "" : entry.signerCN.toLocal8Bit()) << "\",\n";
        std::cout << "        \"peVersion\": \"" << (entry.peVersion == "N/A (Non-PE file)" ? "" : entry.peVersion.toLocal8Bit()) << "\",\n";
        std::cout << "        \"sha256Hash\": \"" << entry.sha256Hash.toLocal8Bit() << "\",\n";
        std::cout << "        \"parentFfsGuid\": \"" << entry.parentFfsGuid.toLocal8Bit() << "\",\n";
        std::cout << "        \"parentFfsName\": \"" << entry.parentFfsName.toLocal8Bit() << "\",\n";
        std::cout << "        \"peFileName\": \"" << entry.peFileName.toLocal8Bit() << "\",\n";
        std::cout << "        \"peSectionType\": \"" << entry.peSectionType.toLocal8Bit() << "\",\n";
        std::cout << "        \"peSectionOffset\": \"0x" << std::hex << entry.peSectionOffset << "\",\n";
        std::cout << "        \"peSectionSize\": " << std::dec << entry.peSectionSize << ",\n";

        std::cout << "        \"containedPeFiles\": [";
        for (size_t j = 0; j < entry.containedPeFiles.size(); j++) {
            if (j > 0) std::cout << ", ";
            std::cout << "\"" << entry.containedPeFiles[j].toLocal8Bit() << "\"";
        }
        std::cout << "],\n";

        std::cout << "        \"dependencies\": [";
        for (size_t j = 0; j < entry.dependencies.size(); j++) {
            if (j > 0) std::cout << ", ";
            std::cout << "\"" << entry.dependencies[j].toLocal8Bit() << "\"";
        }
        std::cout << "],\n";

        std::cout << "        \"sections\": [\n";
        for (size_t j = 0; j < entry.sections.size(); j++) {
            if (j > 0) std::cout << ",\n";
            std::cout << "          {\n";
            std::cout << "            \"type\": \"" << entry.sections[j].type.toLocal8Bit() << "\",\n";
            std::cout << "            \"subtype\": \"" << entry.sections[j].subtype.toLocal8Bit() << "\",\n";
            std::cout << "            \"offset\": \"0x" << std::hex << entry.sections[j].offset << "\",\n";
            std::cout << "            \"size\": " << std::dec << entry.sections[j].size << ",\n";
            std::cout << "            \"description\": \"" << entry.sections[j].description.toLocal8Bit() << "\"\n";
            std::cout << "          }\n";
        }
        std::cout << "        ]\n";

        if (i < sbomEntries.size() - 1) {
            std::cout << "      },\n";
        } else {
            std::cout << "      }\n";
        }
    }

    std::cout << "    ]\n";
    std::cout << "  }\n";
    std::cout << "}\n";

    logProgress("SBOM exported to JSON stdout");
    return U_SUCCESS;
}

void FfsSbomParser::logProgress(const UString& message, bool isError)
{
    // Skip DEBUG messages to keep output clean
    if (message.find("[DEBUG]") != (size_t)-1) {
        return;
    }

    if (isError) {
        fprintf(stderr, "ERROR: %s\n", (const char*)message.toLocal8Bit());
    } else {
        fprintf(stderr, "INFO: %s\n", (const char*)message.toLocal8Bit());
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

// Removed calculateSha256Hash function - using calculateHash instead

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

    UINT8 hash[32]; // SHA256 produces 32 bytes
    sha256(data.constData(), data.size(), hash);

    // Convert to hex string
    UString result;
    for (int i = 0; i < 32; i++) {
        result += usprintf("%02x", hash[i]);
    }

    return result;
}

bool FfsSbomParser::isPeExecutable(const UModelIndex& index)
{
    // NEW LOGIC: Only consider files as PE executables if their file path matches *PE32*image*section* pattern

    // Generate the file path for this index
    UString filePath = createSafeFilename(index, "");

    // Check if the file path matches the PE32 section pattern
    std::string pathStr = filePath.toLocal8Bit();

    // Look for the pattern *PE32*image*section*
    // The actual paths in the dump directory are like: ".../1 PE32 image section/"
    size_t pe32Pos = pathStr.find("PE32");
    if (pe32Pos != std::string::npos) {
        size_t imagePos = pathStr.find("image", pe32Pos);
        if (imagePos != std::string::npos) {
            size_t sectionPos = pathStr.find("section", imagePos);
            if (sectionPos != std::string::npos) {
                            return true;
                        }
                    }
                }

    return false;
}

void FfsSbomParser::extractFfsv2Metadata(const UString& infoFilePath, SbomEntry& entry)
{
    std::string pathStr = infoFilePath.toLocal8Bit();
    std::ifstream infoFile(pathStr);
    if (!infoFile.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(infoFile, line)) {
        if (line.find("FileSystem GUID:") == 0) {
            entry.filesystemGuid = UString(line.substr(16).c_str());
            trim(entry.filesystemGuid);
        } else if (line.find("Volume GUID:") == 0) {
            entry.volumeGuid = UString(line.substr(12).c_str());
            trim(entry.volumeGuid);
        } else if (line.find("Attributes:") == 0) {
            entry.attributes = UString(line.substr(11).c_str());
            trim(entry.attributes);
        } else if (line.find("Signature:") == 0) {
            entry.signature = UString(line.substr(10).c_str());
            trim(entry.signature);
        } else if (line.find("Checksum:") == 0) {
            entry.checksum = UString(line.substr(9).c_str());
            trim(entry.checksum);
        } else if (line.find("Revision:") == 0) {
            UString revision = UString(line.substr(9).c_str());
            trim(revision);
            // Add revision to version field
            if (!entry.version.isEmpty()) {
                entry.version += " (Rev: " + revision + ")";
            } else {
                entry.version = "Rev: " + revision;
            }
        }
    }
    infoFile.close();
}

void FfsSbomParser::deduplicateContainedPeFiles(SbomEntry& entry)
{
    // Remove duplicate PE file names from containedPeFiles vector
    std::set<UString> uniquePeFiles;
    std::vector<UString> deduplicatedPeFiles;

    for (const auto& peFile : entry.containedPeFiles) {
        if (uniquePeFiles.find(peFile) == uniquePeFiles.end()) {
            uniquePeFiles.insert(peFile);
            deduplicatedPeFiles.push_back(peFile);
        }
    }

    entry.containedPeFiles = deduplicatedPeFiles;
}

void FfsSbomParser::populateRegionChildren(SbomEntry& regionEntry)
{
    if (regionEntry.type != "Region" || regionEntry.subtype != "BIOS") {
        return;
    }

    std::string regionPath = regionEntry.filePath.toLocal8Bit();
    DIR* dir = opendir(regionPath.c_str());
    if (!dir) {
        logProgress("Error: Cannot open region directory: " + regionEntry.filePath);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string dirName = entry->d_name;

        // Skip . and .. and non-directories
        if (dirName == "." || dirName == ".." || entry->d_type != DT_DIR) {
            continue;
        }

        // Create a child component using the full directory name
        SbomEntry childComponent;

        // Extract the GUID part from the directory name (e.g., "12 7BEBD21A-A1E5-4C4C-9CA1-A0C168BCBD9D")
        UString originalName = UString(dirName.c_str());
        UString friendlyName = translateGuidToFriendlyName(originalName);

        childComponent.componentName = friendlyName;
        childComponent.guid = UString(dirName.c_str());
        childComponent.type = "Folder";
        childComponent.subtype = "Component";
        childComponent.filePath = UString((regionPath + "/" + dirName).c_str());
        childComponent.filesystemGuid = "";
        childComponent.volumeGuid = "";

        // Try to read info.txt to get more details
        std::string infoPath = childComponent.filePath.toLocal8Bit() + std::string("/info.txt");
        std::ifstream infoFile(infoPath);
        if (infoFile.is_open()) {
            std::string line;
            while (std::getline(infoFile, line)) {
                if (line.find("Type:") == 0) {
                    childComponent.type = UString(line.substr(5).c_str());
                    trim(childComponent.type);
                } else if (line.find("Subtype:") == 0) {
                    childComponent.subtype = UString(line.substr(8).c_str());
                    trim(childComponent.subtype);
                } else if (line.find("FileSystem GUID:") == 0) {
                    childComponent.filesystemGuid = UString(line.substr(16).c_str());
                    trim(childComponent.filesystemGuid);
                } else if (line.find("Volume GUID:") == 0) {
                    childComponent.volumeGuid = UString(line.substr(12).c_str());
                    trim(childComponent.volumeGuid);
                }
            }
            infoFile.close();
        }

        // Process subfolders under this child and add them as sections
        processSubfolderForComponent(childComponent.filePath, childComponent);

        // Recursively process subfolders to create children of children
        populateSubfolderChildren(childComponent);

        regionEntry.children.push_back(childComponent);
    }

    closedir(dir);
    logProgress("Populated " + usprintf("%zu", regionEntry.children.size()) + " children for region: " + regionEntry.componentName);
}

void FfsSbomParser::createBiosRegionHierarchy()
{
    // Create the main BIOS Region component
    SbomEntry biosRegion;
    biosRegion.componentName = "5 BIOS Region";
    biosRegion.guid = "BIOS-REGION-ROOT";
    biosRegion.version = "";
    biosRegion.hash = "";
    biosRegion.license = "Unknown";
    biosRegion.type = "Region";
    biosRegion.subtype = "BIOS";
    biosRegion.offset = 0;
    biosRegion.size = 0;
    biosRegion.filePath = "/Users/lanceware/Downloads/74.dump/5 BIOS region";
    biosRegion.base = "0x0";
    biosRegion.address = "0x0";
    biosRegion.componentType = "Firmware Region";
    biosRegion.architecture = "Unknown";
    biosRegion.buildDate = "Unknown";
    biosRegion.vendor = "Unknown";
    biosRegion.securityAttributes = "None";
    biosRegion.compatibility = "UEFI 2.0+";
    biosRegion.description = "Main BIOS Region containing firmware components";
    biosRegion.sourceLocation = "Not Available";
    biosRegion.contactInfo = "Not Available";
    biosRegion.externalReferences = "Not Available";
    biosRegion.company = "N/A";
    biosRegion.fileDescription = "BIOS Region";
    biosRegion.fileVersion = "N/A";
    biosRegion.copyright = "N/A";
    biosRegion.signerCN = "N/A";
    biosRegion.peVersion = "N/A";
    biosRegion.sha256Hash = "";
    biosRegion.isPe32File = false;
    biosRegion.parentFfsGuid = "";
    biosRegion.parentFfsName = "";
    biosRegion.peFileName = "";
    biosRegion.peSectionType = "";
    biosRegion.peSectionOffset = 0;
    biosRegion.peSectionSize = 0;
    biosRegion.dependencies.clear();
    biosRegion.sections.clear();

    // Read BIOS region metadata from info.txt
    std::string biosRegionInfoPath = "/Users/lanceware/Downloads/74.dump/5 BIOS region/info.txt";
    std::ifstream infoFile(biosRegionInfoPath);
    if (infoFile.is_open()) {
        std::string line;
        while (std::getline(infoFile, line)) {
            if (line.find("Fixed:") == 0) {
                biosRegion.fixed = UString(line.substr(6).c_str());
                trim(biosRegion.fixed);
            } else if (line.find("Base:") == 0) {
                biosRegion.base = UString(line.substr(5).c_str());
                trim(biosRegion.base);
            } else if (line.find("Address:") == 0) {
                biosRegion.address = UString(line.substr(8).c_str());
                trim(biosRegion.address);
            } else if (line.find("Offset:") == 0) {
                UString offsetStr = UString(line.substr(7).c_str());
                trim(offsetStr);
                // Convert hex offset to decimal for the offset field
                std::string offsetHex = offsetStr.toLocal8Bit();
                if (offsetHex.find("h") != std::string::npos) {
                    offsetHex = offsetHex.substr(0, offsetHex.find("h"));
                }
                biosRegion.offset = std::stoul(offsetHex, nullptr, 16);
            } else if (line.find("Full size:") == 0) {
                biosRegion.fullSize = UString(line.substr(10).c_str());
                trim(biosRegion.fullSize);
            }
        }
        infoFile.close();
    }

    // Populate children for this region
    populateRegionChildren(biosRegion);

    // Add the BIOS Region to the SBOM
    sbomEntries.push_back(biosRegion);

    // Add all children as separate SBOM entries
    for (const auto& child : biosRegion.children) {
        SbomEntry childComponent = child; // Create a copy

        // Apply friendly name to the component name for the top-level entry
        UString originalName = childComponent.componentName;
        UString friendlyName = translateGuidToFriendlyName(originalName);
        childComponent.componentName = friendlyName;

        // Process the child component to get detailed information
        processSubfolderForComponent(childComponent.filePath, childComponent);

        sbomEntries.push_back(childComponent);
    }

    logProgress("Created BIOS region hierarchy with " + usprintf("%zu", biosRegion.children.size()) + " children");
}

void FfsSbomParser::trim(UString& str)
{
    // Remove leading and trailing whitespace
    while (!str.isEmpty() && (str[0] == ' ' || str[0] == '\t' || str[0] == '\r' || str[0] == '\n')) {
        str = str.mid(1, str.length() - 1);
    }
    while (!str.isEmpty() && (str[str.length()-1] == ' ' || str[str.length()-1] == '\t' || str[str.length()-1] == '\r' || str[str.length()-1] == '\n')) {
        str = str.left(str.length()-1);
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
    VersionInfo versionFromSection = searchForVersionSection(index);
    if (!versionFromSection.versionString.isEmpty() || !versionFromSection.buildNumber.isEmpty()) {
        if (!versionFromSection.versionString.isEmpty()) {
            entry.version = versionFromSection.versionString;
        }
        if (!versionFromSection.buildNumber.isEmpty()) {
            entry.build = versionFromSection.buildNumber;
        }
        metadataFound = true;
    }

    return metadataFound;
}

void FfsSbomParser::searchForPeSections(const UModelIndex& index, SbomEntry& entry, bool& metadataFound)
{
    if (!index.isValid()) {
        return;
    }

    // NEW LOGIC: Only process PE sections if their file path matches *PE32*image*section* pattern
    if (model->type(index) == Types::Section) {
        UINT8 sectionType = model->subtype(index);
        if (sectionType == EFI_SECTION_PE32 || sectionType == EFI_SECTION_TE) {
            // Generate the file path for this section
            UString filePath = createSafeFilename(index, "");
            std::string pathStr = filePath.toLocal8Bit();

            // Check if the file path matches the PE32 section pattern
            size_t pe32Pos = pathStr.find("PE32");
            if (pe32Pos != std::string::npos) {
                size_t imagePos = pathStr.find("image", pe32Pos);
                if (imagePos != std::string::npos) {
                    size_t sectionPos = pathStr.find("section", imagePos);
                    if (sectionPos != std::string::npos) {
                        // Found a PE section that matches our pattern, extract metadata
            extractPeMetadataFromSection(index, entry, metadataFound);
                    }
                }
            }
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
        // Don't recalculate hash - use the one already calculated
        // UString sha256 = calculateSha256(peData);

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
        // Don't recalculate hash - use the one already calculated
        // if (!sha256.isEmpty()) {
        //     entry.sha256Hash = sha256;
        //     metadataFound = true;
        // }

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

    // ENHANCED PE METADATA EXTRACTION (Python code equivalent)
    // If standard extraction failed or metadata is incomplete, try enhanced extraction
    if (!metadataFound || entry.company.isEmpty() || entry.fileDescription.isEmpty()) {
        UString pePath = findPe32SectionInFfs(index);
        if (!pePath.isEmpty()) {
            PeMetadata meta = extractEnhancedPeMetadata(pePath);

            // Update entry with enhanced metadata (with fallback logic)
            if (entry.company.isEmpty()) {
                entry.company = meta.company.isEmpty() ? meta.signerCN : meta.company;
            }
            if (entry.fileDescription.isEmpty()) {
                entry.fileDescription = meta.fileDescription;
            }
            if (entry.fileVersion.isEmpty()) {
                entry.fileVersion = meta.fileVersion;
            }
            if (entry.peVersion.isEmpty()) {
                entry.peVersion = meta.fileVersion;
            }
            if (entry.copyright.isEmpty()) {
                entry.copyright = meta.copyright;
            }

            // Prefer PE version if UI version is missing
            if (entry.version.isEmpty() && !entry.peVersion.isEmpty()) {
                entry.version = entry.peVersion;
            }

            // Calculate SHA-256 hash if not already done
            if (entry.sha256Hash.isEmpty()) {
                entry.sha256Hash = calculateSha256FromFile(pePath);
            }

            metadataFound = true;
            logProgress("Enhanced PE metadata extracted for: " + entry.componentName);
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
    return "Unknown";
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
    VersionInfo versionInfo = searchForVersionSection(index);
    return versionInfo.versionString;
}

VersionInfo FfsSbomParser::searchForVersionSection(const UModelIndex& index)
{
    VersionInfo result;

    if (!index.isValid()) {
        return result;
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
            VersionInfo version = searchForVersionSection(childIndex);
            if (!version.versionString.isEmpty() || !version.buildNumber.isEmpty()) {
                return version;
            }
        }
    }

    return result;
}

VersionInfo FfsSbomParser::parseVersionSection(const UModelIndex& index)
{
    VersionInfo result;

    if (!model->hasEmptyBody(index)) {
        const UByteArray& versionData = model->body(index);

        // Parse version section data
        // EFI_VERSION_SECTION contains a UINT16 BuildNumber
        if (versionData.size() >= sizeof(UINT16)) {
            UINT16 buildNumber = readUnaligned((const UINT16*)versionData.constData());
            result.buildNumber = usprintf("%u", buildNumber);
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
            if (!buildStr.isEmpty() && buildStr != "0") {
                result.buildNumber = buildStr;
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
                result.versionString = versionStr;
            }
        }
    }

    return result;
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
        // Also check for PE files in raw sections (some firmware stores PE files in raw sections)
        else if (sectionType == EFI_SECTION_RAW) {
            // Check if the raw section contains a PE file
            if (!model->hasEmptyBody(index)) {
                const UByteArray& bodyData = model->body(index);
                if (bodyData.size() >= 64 && bodyData[0] == 'M' && bodyData[1] == 'Z') {
                    // This raw section contains a PE file
                    SbomEntry peEntry = createPe32Entry(index, parentGuid, parentName, "");
                    peEntry.peSectionType = "RAW_PE";
                    peEntries.push_back(peEntry);
                    logProgress("Found PE file in RAW section");
                }
            }
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
    entry.version = "";  // Will be populated by version extraction if available
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
    // Removed checksumAlgorithm since it's always SHA256
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

    // Skip setting file path for PE file subtypes since the actual .efi files aren't physically extracted
    // PE subtypes include: PE32, TE, RAW_PE
    if (entry.subtype == "PE32" || entry.subtype == "TE" || entry.subtype == "RAW_PE") {
        entry.filePath = ""; // Leave empty for PE file subtypes
    } else {
        // Generate proper file path that points to the actual directory structure
        if (!basePath.isEmpty()) {
    entry.filePath = usprintf("%s/%s", basePath.toLocal8Bit(), entry.peFileName.toLocal8Bit());
        } else {
            // If no base path, we need to find the actual directory path for the parent component
            // First, try to find the parent component in the UEFI model tree
            UString actualParentPath = "";

            // Search through the model to find the parent component
            for (int i = 0; i < model->rowCount(); i++) {
                UModelIndex rootIndex = model->index(i, 0);
                if (rootIndex.isValid()) {
                    actualParentPath = findComponentPathInTree(rootIndex, parentGuid, parentName);
                    if (!actualParentPath.isEmpty()) {
                        break;
                    }
                }
            }

            if (!actualParentPath.isEmpty()) {
                entry.filePath = usprintf("%s/%s", actualParentPath.toLocal8Bit(), entry.peFileName.toLocal8Bit());
            } else {
                // Fallback: create a path that points to the parent component's directory
                UString dumpDir = "/Users/lanceware/Downloads/74.dump";
                UString parentPath = usprintf("%s/%s", dumpDir.toLocal8Bit(), parentName.toLocal8Bit());
                entry.filePath = usprintf("%s/%s", parentPath.toLocal8Bit(), entry.peFileName.toLocal8Bit());
            }
        }
    }

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
        // Don't recalculate hash - use the one already calculated
        entry.sha256Hash = entry.hash;

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
    // Removed checksumAlgorithm since it's always SHA256
    if (entry.securityAttributes.isEmpty()) entry.securityAttributes = "Standard";
    if (entry.compatibility.isEmpty()) entry.compatibility = "UEFI 2.x";
    if (entry.description.isEmpty()) entry.description = usprintf("PE32 executable from %s", parentName.toLocal8Bit());

    // Calculate hash
    entry.hash = calculateSha256(model->body(peSection));

    return entry;
}

UString FfsSbomParser::extractPeFileName(const UModelIndex& peSection, const UString& parentName)
{
    UString filename;

    // Try to extract filename from PE metadata first
    if (!model->hasEmptyBody(peSection)) {
        const UByteArray& peData = model->body(peSection);
        UString fileDesc = extractPeVersionResource(peData, "FileDescription");
        if (!fileDesc.isEmpty()) {
            // Clean up the file description to use as filename
            filename = fileDesc;
            // Replace spaces and special characters
            for (size_t i = 0; i < filename.length(); i++) {
                if (filename[i] == ' ' || filename[i] == '/' || filename[i] == '\\' || filename[i] == ':' || filename[i] == '*') {
                    filename[i] = '_';
                }
            }
        }
    }

    // If no filename from PE metadata, use fallback naming
    if (filename.isEmpty()) {
        UString sectionType = determinePeSectionType(peSection);
        if (sectionType == "PE32") {
            filename = parentName;
        } else if (sectionType == "TE") {
            filename = parentName + "_TE";
        } else if (sectionType == "RAW_PE") {
            filename = parentName + "_RAW";
        } else {
            filename = parentName + "_PE";
        }
    }

    // Always ensure .efi extension is present
    if (!filename.endsWith(".efi")) {
        filename += ".efi";
    }

    return filename;
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
    case EFI_SECTION_RAW:
        // Check if this raw section contains a PE file
        if (!model->hasEmptyBody(peSection)) {
            const UByteArray& bodyData = model->body(peSection);
            if (bodyData.size() >= 64 && bodyData[0] == 'M' && bodyData[1] == 'Z') {
                return "RAW_PE";
            }
        }
        return "RAW";
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

// Enhanced ME version/SKU/build date extraction
UString FfsSbomParser::extractMeVersionFromBody(const UByteArray& body) {
    // ME version is typically at offset 0x60 (4 bytes: major, minor, hotfix, build)
    if (body.size() < 0x64) return UString();
    UINT8 major = (UINT8)body[0x60];
    UINT8 minor = (UINT8)body[0x61];
    UINT8 hotfix = (UINT8)body[0x62];
    UINT8 build = (UINT8)body[0x63];
    return usprintf("%u.%u.%u.%u", major, minor, hotfix, build);
}

// Helper for ME SKU extraction (stub, can be improved)
UString FfsSbomParser::extractMeSkuFromBody(const UByteArray& body) {
    // SKU is not always at a fixed offset; this is a stub
    // In some images, SKU is at 0x48 (1 byte), but mapping is vendor-specific
    if (body.size() < 0x49) return UString();
    UINT8 sku = (UINT8)body[0x48];
    switch (sku) {
        case 0x01: return "Consumer";
        case 0x02: return "Corporate";
        case 0x03: return "Server";
        case 0x04: return "Ignition";
        case 0x05: return "Slim";
        default: return usprintf("Unknown (0x%02X)", sku);
    }
}

// Helper for ME build date extraction (stub, can be improved)
UString FfsSbomParser::extractMeBuildDateFromBody(const UByteArray& body) {
    // Build date is not always present; stub returns empty
    return UString();
}

// ENHANCED PE METADATA EXTRACTION HELPER FUNCTIONS (Python code equivalent)

UString FfsSbomParser::findPe32SectionInFfs(const UModelIndex& index)
{
    // NEW LOGIC: Only return PE32 sections if their file path matches *PE32*image*section* pattern
    if (model->type(index) == Types::Section) {
        UINT8 sectionType = model->subtype(index);
        if (sectionType == EFI_SECTION_PE32 || sectionType == EFI_SECTION_TE) {
            // Generate the file path for this section
            UString filePath = createSafeFilename(index, "");
            std::string pathStr = filePath.toLocal8Bit();

            // Check if the file path matches the PE32 section pattern
            size_t pe32Pos = pathStr.find("PE32");
            if (pe32Pos != std::string::npos) {
                size_t imagePos = pathStr.find("image", pe32Pos);
                if (imagePos != std::string::npos) {
                    size_t sectionPos = pathStr.find("section", imagePos);
                    if (sectionPos != std::string::npos) {
                        return filePath;
                    }
                }
            }
        }
    }

    // Recursively search children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            UString result = findPe32SectionInFfs(childIndex);
            if (!result.isEmpty()) {
                return result;
            }
        }
    }

    return UString();
}

PeMetadata FfsSbomParser::extractEnhancedPeMetadata(const UString& pePath)
{
    PeMetadata meta;

    // Try to find the actual PE file in the dump structure
    UString actualPePath = firstFileMatching(pePath, "*PE32*section*/*.bin");
    if (actualPePath.isEmpty()) {
        actualPePath = firstFileMatching(pePath, "*TE*section*/*.bin");
    }

    if (!actualPePath.isEmpty()) {
        // Extract enhanced PE metadata using existing functions
        // This would call your existing PE parsing functions with better error handling

        // For now, use the existing extraction methods
        // In a full implementation, you would add more sophisticated PE parsing here

        logProgress("Enhanced PE metadata extraction attempted for: " + actualPePath);
    }

    return meta;
}

UString FfsSbomParser::calculateSha256FromFile(const UString& filePath)
{
    // Calculate SHA-256 hash from file content
    // This is equivalent to: hashlib.sha256(pe_path.read_bytes()).hexdigest()

    std::ifstream file(filePath.toLocal8Bit(), std::ios::binary);
    if (!file.is_open()) {
        logProgress("Failed to open file for SHA-256 calculation: " + filePath, true);
        return UString();
    }

    // Read file content
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();

    // Use the existing SHA-256 calculation function
    UByteArray data(buffer.data(), buffer.size());
    return calculateSha256(data);
}

UString FfsSbomParser::firstFileMatching(const UString& dirPath, const UString& pattern)
{
    // This is equivalent to: first_file_matching(dir_path, "*PE32*section*/*.bin")
    // Search for files matching the pattern in the directory

    DIR* dir = opendir(dirPath.toLocal8Bit());
    if (!dir) {
        return UString();
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string fullPath = std::string(dirPath.toLocal8Bit()) + "/" + entry->d_name;
        struct stat statbuf;

        if (stat(fullPath.c_str(), &statbuf) == -1) {
            continue;
        }

        if (S_ISREG(statbuf.st_mode)) {
            // Check if file matches pattern
            std::string filename(entry->d_name);
            if (pattern.find("*PE32*") >= 0 &&
                (filename.find("PE32") != std::string::npos || filename.find("TE") != std::string::npos)) {
                closedir(dir);
                return UString(fullPath.c_str());
            }
        } else if (S_ISDIR(statbuf.st_mode)) {
            // Recursively search subdirectories
            UString result = firstFileMatching(UString(fullPath.c_str()), pattern);
            if (!result.isEmpty()) {
                closedir(dir);
                return result;
            }
        }
    }

    closedir(dir);
    return UString();
}

UString FfsSbomParser::searchForVersionInfoFile(const UModelIndex& index)
{
    // NEW LOGIC: Search for version sections within this FFS file

    // First, search for version sections as direct children of this FFS file
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid() && model->type(childIndex) == Types::Section) {
            UINT8 sectionType = model->subtype(childIndex);
            if (sectionType == EFI_SECTION_VERSION) {
                // Found a version section, get its path and look for info.txt
                UString versionPath = createSafeFilename(childIndex, "");
                std::string pathStr = versionPath.toLocal8Bit();

                // Use the actual dump directory path
                std::string dumpDir = "/Users/lanceware/Downloads/74.dump";
                std::string fullPath = dumpDir + "/" + pathStr;

                // Look for info.txt in this version section directory
                std::string infoPath = fullPath + "/info.txt";
                std::ifstream testFile(infoPath);
                if (testFile.good()) {
                    testFile.close();
                    logProgress("Found version info file: " + UString(infoPath.c_str()));
                    return UString(infoPath.c_str());
                } else {
                    logProgress("Version info file not found at: " + UString(infoPath.c_str()));
                }
            }
        }
    }

    // If not found in direct children, search recursively in nested sections
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            UString result = searchForVersionInfoFile(childIndex);
            if (!result.isEmpty()) {
                return result;
            }
        }
    }

    // FALLBACK: Search for the component in the actual dump directory structure
    // Get the component name and search for it in the dump directory
    UString componentName = model->name(index);
    std::string nameStr = componentName.toLocal8Bit();

    logProgress("Searching for component: " + UString(nameStr.c_str()));
    logProgress("Component name length: " + UString(std::to_string(nameStr.length()).c_str()));

    // Search for the component in the dump directory
    std::string dumpDir = "/Users/lanceware/Downloads/74.dump";

    // Search recursively in the dump directory for directories matching the component name
    DIR* rootDir = opendir(dumpDir.c_str());
    if (rootDir != nullptr) {
        struct dirent* entry;
        while ((entry = readdir(rootDir)) != nullptr) {
            if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                std::string regionPath = dumpDir + "/" + entry->d_name;

                // Search in this region for the component
                DIR* regionDir = opendir(regionPath.c_str());
                if (regionDir != nullptr) {
                    struct dirent* regionEntry;
                    while ((regionEntry = readdir(regionDir)) != nullptr) {
                        if (regionEntry->d_type == DT_DIR && strcmp(regionEntry->d_name, ".") != 0 && strcmp(regionEntry->d_name, "..") != 0) {
                            std::string guidPath = regionPath + "/" + regionEntry->d_name;

                            // Search in this GUID directory for the component
                            DIR* guidDir = opendir(guidPath.c_str());
                            if (guidDir != nullptr) {
                                struct dirent* guidEntry;
                                while ((guidEntry = readdir(guidDir)) != nullptr) {
                                    if (guidEntry->d_type == DT_DIR && strcmp(guidEntry->d_name, ".") != 0 && strcmp(guidEntry->d_name, "..") != 0) {
                                        std::string componentPath = guidPath + "/" + guidEntry->d_name;

                                        // Check if this directory name contains the component name
                                        if (strstr(guidEntry->d_name, nameStr.c_str()) != nullptr) {
                                            logProgress("Found component directory: " + UString(componentPath.c_str()));

                                            // Look for version sections in this component directory
                                            DIR* componentDir = opendir(componentPath.c_str());
                                            if (componentDir != nullptr) {
                                                struct dirent* componentEntry;
                                                while ((componentEntry = readdir(componentDir)) != nullptr) {
                                                    if (componentEntry->d_type == DT_DIR &&
                                                        strstr(componentEntry->d_name, " Version section") != nullptr) {
                                                        std::string versionDir = componentPath + "/" + componentEntry->d_name;
                                                        std::string infoPath = versionDir + "/info.txt";

                                                        logProgress("Found version section: " + UString(versionDir.c_str()));

                                                        std::ifstream testFile(infoPath);
                                                        if (testFile.good()) {
                                                            testFile.close();
                                                            logProgress("Found version info file: " + UString(infoPath.c_str()));
                                                            closedir(componentDir);
                                                            closedir(guidDir);
                                                            closedir(regionDir);
                                                            closedir(rootDir);
                                                            return UString(infoPath.c_str());
                                                        }
                                                    }
                                                }
                                                closedir(componentDir);
                                            }
                                        }
                                    }
                                }
                                closedir(guidDir);
                            }
                        }
                    }
                    closedir(regionDir);
                }
            }
        }
        closedir(rootDir);
    }

    return UString();
}

UString FfsSbomParser::extractVersionFromInfoFile(const UString& infoFilePath)
{
    // Extract version string from info.txt file
    std::ifstream file(infoFilePath.toLocal8Bit());
    if (!file.is_open()) {
        logProgress("Failed to open info.txt file: " + infoFilePath, true);
        return UString();
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("Version string:") != std::string::npos) {
            // Extract the version string after the colon
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string version = line.substr(colonPos + 1);
                // Remove leading/trailing whitespace
                version.erase(0, version.find_first_not_of(" \t"));
                version.erase(version.find_last_not_of(" \t") + 1);
                file.close();
                return UString(version.c_str());
            }
        }
    }
    file.close();
    return UString();
}

// Version extraction from Version sections

void FfsSbomParser::extractVersionFromVersionSections(const UModelIndex& index, SbomEntry& entry)
{
    if (!index.isValid()) {
        return;
    }

    // Search for version sections within this FFS file
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid() && model->type(childIndex) == Types::Section) {
            UINT8 sectionType = model->subtype(childIndex);
            if (sectionType == EFI_SECTION_VERSION) {
                // Found a version section, extract version string and update the main component
                UString versionString = extractVersionStringFromInfoFile(childIndex);
                if (!versionString.isEmpty()) {
                    entry.version = versionString;
                    logProgress("Updated version for component '" + entry.componentName + "' to: " + versionString);
                    return; // Found version, no need to search further
                }
            }
        }

        // Also search recursively in nested sections
        if (childIndex.isValid()) {
            extractVersionFromVersionSections(childIndex, entry);
            if (!entry.version.isEmpty()) {
                return; // Found version in nested section, no need to search further
            }
        }
    }
}

UString FfsSbomParser::extractVersionStringFromInfoFile(const UModelIndex& versionSection)
{
    // Try to extract version string from the version section body first
    if (!model->hasEmptyBody(versionSection)) {
        const UByteArray& versionData = model->body(versionSection);
        if (!versionData.isEmpty()) {
            // Parse version section data (UCS-2/UTF-16LE format)
            return uFromUcs2(versionData.constData());
        }
    }

    // If no version data in body, try to find info.txt file in the dump directory
    UString versionPath = createDumpMatchingPath(versionSection, "");
    std::string pathStr = versionPath.toLocal8Bit();

    // Look for info.txt in the version section directory
    std::string infoPath = pathStr + "/info.txt";
    std::ifstream testFile(infoPath);
    if (testFile.good()) {
        testFile.close();
        return extractVersionFromInfoFile(UString(infoPath.c_str()));
    }

    // If no info.txt found, try to extract from the section info
    UString info = model->info(versionSection);
    if (!info.isEmpty()) {
        // Look for version string in info
        size_t pos = info.find("Version string:");
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

void FfsSbomParser::processSubfolderForComponent(const UString& subfolderPath, SbomEntry& parentComponent)
{
    DIR* dir = opendir(subfolderPath.toLocal8Bit());
    if (!dir) return;

    struct dirent* entry;
    std::vector<UString> sectionInfo;
    bool hasRawTeVersion = false;
    bool hasInfoTxtOrBodyBin = false;

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            std::string dirName = entry->d_name;
            if (dirName != "." && dirName != "..") {
                // Check if this subfolder contains keywords
                if (dirName.find("Raw") != std::string::npos ||
                    dirName.find("TE") != std::string::npos ||
                    dirName.find("Version") != std::string::npos) {
                    hasRawTeVersion = true;
                }
            }
        } else if (entry->d_type == DT_REG) {
            std::string fileName = entry->d_name;
            if (fileName == "info.txt" || fileName == "body.bin") {
                hasInfoTxtOrBodyBin = true;
            }
        }
    }
    closedir(dir);

    // Always process subfolders - create components for all of them
    populateSubfolderChildren(parentComponent);
}

void FfsSbomParser::populateSubfolderChildren(SbomEntry& parentComponent)
{
    // Static set to track already processed file paths to prevent duplicates
    static std::set<UString> processedPaths;

    DIR* dir = opendir(parentComponent.filePath.toLocal8Bit());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            std::string dirName = entry->d_name;
            if (dirName != "." && dirName != "..") {
                // Create a subfolder component for ALL subfolders
                SbomEntry subfolderComponent;

                // Extract the GUID part and translate to friendly name
                UString originalName = UString(dirName.c_str());
                UString friendlyName = translateGuidToFriendlyName(originalName);

                subfolderComponent.componentName = friendlyName;
                subfolderComponent.guid = UString(dirName.c_str());
                subfolderComponent.filePath = parentComponent.filePath + "/" + UString(dirName.c_str());
                subfolderComponent.type = "";
                subfolderComponent.subtype = "";

                // Check if this path has already been processed to prevent duplicates
                if (processedPaths.find(subfolderComponent.filePath) != processedPaths.end()) {
                    // Skip this component as it's already been processed
                    continue;
                }

                // Read info.txt if it exists and harvest ALL available information
                UString infoPath = subfolderComponent.filePath + "/info.txt";
                std::ifstream infoFile(infoPath.toLocal8Bit());
                if (infoFile.is_open()) {
                    std::string line;
                    while (std::getline(infoFile, line)) {
                        // Read all available fields from info.txt
                        if (line.find("Text:") != std::string::npos) {
                            UString textStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(textStr);
                            if (!textStr.isEmpty()) {
                                subfolderComponent.componentName = textStr;
                            }
                        } else if (line.find("Name:") != std::string::npos) {
                            UString nameStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(nameStr);
                            if (!nameStr.isEmpty()) {
                                subfolderComponent.componentName = nameStr;
                            }
                        } else if (line.find("Type:") != std::string::npos) {
                            UString typeStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(typeStr);
                            subfolderComponent.type = typeStr;
                        } else if (line.find("Subtype:") != std::string::npos) {
                            UString subtypeStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(subtypeStr);
                            subfolderComponent.subtype = subtypeStr;
                        } else if (line.find("File GUID:") != std::string::npos) {
                            UString guidStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(guidStr);
                            subfolderComponent.guid = guidStr;
                        } else if (line.find("Version:") != std::string::npos) {
                            UString versionStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(versionStr);
                            subfolderComponent.version = versionStr;
                        } else if (line.find("Hash (SHA256):") != std::string::npos) {
                            UString hashStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(hashStr);
                            subfolderComponent.hash = hashStr;
                        } else if (line.find("License:") != std::string::npos) {
                            UString licenseStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(licenseStr);
                            subfolderComponent.license = licenseStr;
                        } else if (line.find("Component Type:") != std::string::npos) {
                            UString compTypeStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(compTypeStr);
                            subfolderComponent.componentType = compTypeStr;
                        } else if (line.find("Architecture:") != std::string::npos) {
                            UString archStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(archStr);
                            subfolderComponent.architecture = archStr;
                        } else if (line.find("Build Date:") != std::string::npos) {
                            UString buildDateStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(buildDateStr);
                            subfolderComponent.buildDate = buildDateStr;
                        } else if (line.find("Vendor:") != std::string::npos) {
                            UString vendorStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(vendorStr);
                            subfolderComponent.vendor = vendorStr;
                        } else if (line.find("Security Attributes:") != std::string::npos) {
                            UString secAttrStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(secAttrStr);
                            subfolderComponent.securityAttributes = secAttrStr;
                        } else if (line.find("Compatibility:") != std::string::npos) {
                            UString compatStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(compatStr);
                            subfolderComponent.compatibility = compatStr;
                        } else if (line.find("Description:") != std::string::npos) {
                            UString descStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(descStr);
                            subfolderComponent.description = descStr;
                        } else if (line.find("Source Location:") != std::string::npos) {
                            UString srcLocStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(srcLocStr);
                            subfolderComponent.sourceLocation = srcLocStr;
                        } else if (line.find("Contact Info:") != std::string::npos) {
                            UString contactStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(contactStr);
                            subfolderComponent.contactInfo = contactStr;
                        } else if (line.find("External References:") != std::string::npos) {
                            UString extRefStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(extRefStr);
                            subfolderComponent.externalReferences = extRefStr;
                        } else if (line.find("Company:") != std::string::npos) {
                            UString companyStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(companyStr);
                            subfolderComponent.company = companyStr;
                        } else if (line.find("File Description:") != std::string::npos) {
                            UString fileDescStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(fileDescStr);
                            subfolderComponent.fileDescription = fileDescStr;
                        } else if (line.find("File Version:") != std::string::npos) {
                            UString fileVerStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(fileVerStr);
                            subfolderComponent.fileVersion = fileVerStr;
                        } else if (line.find("Copyright:") != std::string::npos) {
                            UString copyrightStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(copyrightStr);
                            subfolderComponent.copyright = copyrightStr;
                        } else if (line.find("Digital Signer:") != std::string::npos) {
                            UString signerStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(signerStr);
                            subfolderComponent.signerCN = signerStr;
                        } else if (line.find("PE Version:") != std::string::npos) {
                            UString peVerStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(peVerStr);
                            subfolderComponent.peVersion = peVerStr;
                        } else if (line.find("SHA-256 Hash:") != std::string::npos) {
                            UString sha256Str = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(sha256Str);
                            subfolderComponent.sha256Hash = sha256Str;
                        }
                    }
                    infoFile.close();
                }

                // Process subfolders under this subfolder and add them as sections
                processSubfolderForComponent(subfolderComponent.filePath, subfolderComponent);

                // Recursively process deeper subfolders
                populateSubfolderChildren(subfolderComponent);

                // Check if this is a Version section and extract version string for parent
                if (subfolderComponent.subtype.find("Version") != std::string::npos) {
                    UString versionInfoPath = subfolderComponent.filePath + "/info.txt";
                    std::ifstream versionInfoFile(versionInfoPath.toLocal8Bit());
                    if (versionInfoFile.is_open()) {
                        std::string line;
                        UString versionString;
                        UString buildNumber;

                        while (std::getline(versionInfoFile, line)) {
                            if (line.find("Version string:") != std::string::npos) {
                                UString versionStr = UString(line.substr(line.find(":") + 1).c_str());
                                trimws(versionStr);
                                if (!versionStr.isEmpty()) {
                                    versionString = versionStr;
                                }
                            } else if (line.find("Build number:") != std::string::npos) {
                                UString buildStr = UString(line.substr(line.find(":") + 1).c_str());
                                trimws(buildStr);
                                if (!buildStr.isEmpty() && buildStr != "0") {
                                    buildNumber = buildStr;
                                }
                            }
                        }
                        versionInfoFile.close();

                        // Set version string and build number separately
                        if (!versionString.isEmpty() || !buildNumber.isEmpty()) {
                            if (!versionString.isEmpty()) {
                                parentComponent.version = versionString;
                            }
                            if (!buildNumber.isEmpty()) {
                                parentComponent.build = buildNumber;
                            }
                        }
                    }
                }

                // Add this subfolder as a child of the parent
                parentComponent.children.push_back(subfolderComponent);

                // Check if this is a section (contains "section" in the name) or a main component
                bool isSection = (dirName.find("section") != std::string::npos) ||
                                (dirName.find("Section") != std::string::npos);

                // Check if this is a volume free space component
                bool isVolumeFreeSpace = (dirName.find("Volume free space") != std::string::npos) ||
                                        (dirName.find("volume free space") != std::string::npos);

                // Check if this is a raw section component by reading the info.txt file
                bool isRawSection = false;
                UString rawInfoPath = subfolderComponent.filePath + "/info.txt";
                std::ifstream rawInfoFile(rawInfoPath.toLocal8Bit());
                if (rawInfoFile.is_open()) {
                    std::string line;
                    while (std::getline(rawInfoFile, line)) {
                        if (line.find("Subtype:") != std::string::npos) {
                            UString subtypeStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(subtypeStr);
                            if (subtypeStr.find("Raw") != std::string::npos) {
                                isRawSection = true;
                                break;
                            }
                        }
                    }
                    rawInfoFile.close();
                }

                // Check if this is a PE32 image section component by reading the info.txt file
                bool isPe32ImageSection = false;
                UString pe32InfoPath = subfolderComponent.filePath + "/info.txt";
                std::ifstream pe32InfoFile(pe32InfoPath.toLocal8Bit());
                if (pe32InfoFile.is_open()) {
                    std::string line;
                    while (std::getline(pe32InfoFile, line)) {
                        if (line.find("Subtype:") != std::string::npos) {
                            UString subtypeStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(subtypeStr);
                            logProgress("[DEBUG] Checking subtype: '" + subtypeStr + "' for path: " + subfolderComponent.filePath);
                            if (subtypeStr.find("PE32 image") != std::string::npos) {
                                isPe32ImageSection = true;
                                logProgress("[DEBUG] Found PE32 image section in: " + subfolderComponent.filePath);

                                // Flag the parent component as a PE image
                                parentComponent.isPe32File = true;
                                logProgress("[DEBUG] Flagged parent component " + parentComponent.componentName + " as PE image");

                                // Calculate SHA256 hash from the PE32 image section's body.bin file
                                UString bodyBinPath = subfolderComponent.filePath + "/body.bin";
                                logProgress("[DEBUG] Attempting to read body.bin from: " + bodyBinPath);
                                std::ifstream bodyBinFile(bodyBinPath.toLocal8Bit(), std::ios::binary);
                                if (bodyBinFile.is_open()) {
                                    logProgress("[DEBUG] Successfully opened body.bin file");
                                    // Read the entire file into memory
                                    bodyBinFile.seekg(0, std::ios::end);
                                    std::streamsize size = bodyBinFile.tellg();
                                    bodyBinFile.seekg(0, std::ios::beg);
                                    logProgress("[DEBUG] Body.bin file size: " + usprintf("%zu", size));

                                    std::vector<char> buffer(size);
                                    bodyBinFile.read(buffer.data(), size);
                                    bodyBinFile.close();

                                    // Calculate SHA256 hash
                                    UByteArray data(buffer.data(), buffer.size());
                                    UINT8 hash[32]; // SHA256 produces 32 bytes
                                    sha256(data.constData(), data.size(), hash);

                                    UString hashString;
                                    for (int i = 0; i < 32; i++) {
                                        hashString += usprintf("%02X", hash[i]);
                                    }

                                    // Store the hash in the parent component
                                    parentComponent.hash = hashString;
                                    logProgress("Calculated PE32 hash for component " + parentComponent.componentName + ": " + hashString);
                                } else {
                                    logProgress("Warning: Could not open body.bin file for PE32 image section: " + bodyBinPath, true);
                                }

                                break;
                            }
                        }
                    }
                    pe32InfoFile.close();
                } else {
                    logProgress("[DEBUG] Could not open info.txt file: " + pe32InfoPath);
                }

                // Check if this is a Freeform subtype GUID component by reading the info.txt file
                bool isFreeformSubtypeGuid = false;
                UString freeformInfoPath = subfolderComponent.filePath + "/info.txt";
                std::ifstream freeformInfoFile(freeformInfoPath.toLocal8Bit());
                if (freeformInfoFile.is_open()) {
                    std::string line;
                    while (std::getline(freeformInfoFile, line)) {
                        if (line.find("Subtype:") != std::string::npos) {
                            UString subtypeStr = UString(line.substr(line.find(":") + 1).c_str());
                            trimws(subtypeStr);
                            if (subtypeStr.find("Freeform subtype GUID") != std::string::npos) {
                                isFreeformSubtypeGuid = true;
                                break;
                            }
                        }
                    }
                    freeformInfoFile.close();
                }

                // Only add as a separate top-level SBOM component if it's NOT a section, NOT volume free space, NOT raw section, NOT PE32 image section, and NOT freeform subtype GUID
                // Sections, volume free space, raw sections, PE32 image sections, and freeform subtype GUIDs should only appear as children, not as top-level components
                if (!isSection && !isVolumeFreeSpace && !isRawSection && !isPe32ImageSection && !isFreeformSubtypeGuid) {
                    sbomEntries.push_back(subfolderComponent);
                    // Mark this path as processed to prevent duplicates
                    processedPaths.insert(subfolderComponent.filePath);
                }
            }
        }
    }
    closedir(dir);
}

UString FfsSbomParser::translateGuidToFriendlyName(const UString& guid)
{
    // Static map of known GUIDs to friendly names
    static std::map<UString, UString> guidMap = {
        // Common volume GUIDs
        {"7BEBD21A-A1E5-4C4C-9CA1-A0C168BCBD9D", "Firmware Volume"},
        {"1A803C55-F034-4E60-AD9E-9D3F32CE273C", "Intel FV TSN MAC Address"},
        {"4F1C52D3-D824-4D2A-A2F0-EC40C23C5916", "Firmware Volume"},
        {"5A0FBE31-FD07-4812-9977-96996F373872", "Firmware Volume"},
        {"47B18F92-5ADC-4739-8D70-9BFFCD9A2EC2", "Firmware Volume"},
        {"289EFB98-9F4C-47F5-9AC4-35A4D847B0A9", "Firmware Volume"},
        {"4409A1B5-8D3E-436C-B424-B0C9F7AF1C9F", "Firmware Volume"},
        {"8C8CE578-8A3D-4F1C-9935-896185C32DD3", "Firmware Volume"},
        {"3DA4F21C-189D-46A3-98C0-AF814EBF01B0", "Firmware Volume"},
        {"D45EB923-8B43-411F-BB1C-EE506FBA4BAE", "Firmware Volume"},
        {"AFDD39F1-19D7-4501-A730-CE5A27E1154B", "Firmware Volume"},
        {"8487985B-65AD-44D1-BA36-FD65190CEACD", "Firmware Volume"},
        {"61C0F511-A691-4F54-974F-B9A42172CE53", "Firmware Volume"},
        {"DC61629B-3CF8-4AA1-8FEF-1DD55E51684E", "Firmware Volume"},
        {"52F1AFB6-78A6-448F-8274-F370549AC5D0", "Firmware Volume"},
        {"B7A3CAAA-4E10-44A5-8C2C-D2F38D5B8083", "DXE Foundation"},
        {"FA4974FC-AF1D-4E5D-BDC5-DACD6D27BAEC", "NVRAM Volume"},

        // Common component GUIDs
        {"98DB68E0-5AB6-4A48-80C8-EAC6C51180FC", "Boot Guard Hash"},
        {"5B94E419-C795-414D-A0D4-B80A877BE5FE", "SEC Core"},
        {"912740BE-2284-4734-B971-84B027353F0C", "Raw Section"},
        {"70BCF6A5-FFB1-47D8-B1AE-EFE5508E23EA", "Raw Section"},
        {"17088572-377F-44EF-8F4E-B09FFF46A070", "Microcode"},
        {"77D3DC50-D42B-4916-AC80-8F469035D150", "NVRAM External Defaults"},

        // Common section GUIDs
        {"4C4D4F52-0001-0000-2800-000019000000", "ROM Layout"},
        {"C91C3C17-FC74-46E5-BDBE-6F486A5A9F3C", "ROM Layout FFS"},

        // Common variable GUIDs
        {"5241564E-0A63-FFFF-FF82-005365747570", "StdDefaults"},
        {"80E1202E-2697-4264-9CC9-80762C3E5863", "NVAR GUID Store"},
        {"4599D26F-1A11-49B8-B91F-858745CFF824", "NVAR GUID Store"},
        {"00FFD0EA-00F0-0000-0000-00000000272D", "Startup AP Data"},

        // Common FFS GUIDs
        {"7934156D-CFCE-460E-92F5-A07909A59ECA", "Bios Guard Module"},
        {"022803C6-5898-EE4E-1439-59429D6EDC7B", "LzmaCustomDecompressGuid"},
        {"Volume Top File", "Volume Top File"}
    };

    // Clean the GUID (remove any prefixes or suffixes)
    UString cleanGuid = guid;

    // Look for patterns like "12 7BEBD21A-A1E5-4C4C-9CA1-A0C168BCBD9D"
    // Find the first space followed by what looks like a GUID
    size_t spacePos = cleanGuid.find(" ");
    if (spacePos != std::string::npos && spacePos < cleanGuid.length() - 1) {
        UString afterSpace = cleanGuid.mid(spacePos + 1, cleanGuid.length() - spacePos - 1);
        // Check if what follows looks like a GUID (contains hyphens)
        if (afterSpace.find("-") != std::string::npos) {
            cleanGuid = afterSpace;
        }
    }

    // Look up the GUID in our map
    auto it = guidMap.find(cleanGuid);
    if (it != guidMap.end()) {
        return it->second;
    }

    // If not found, try the original string
    it = guidMap.find(guid);
    if (it != guidMap.end()) {
        return it->second;
    }

    // If still not found, return the cleaned GUID (without numeric prefix)
    return cleanGuid;
}

UString FfsSbomParser::findComponentPathInTree(const UModelIndex& index, const UString& targetGuid, const UString& targetName)
{
    // Check if this is the component we're looking for
    UString currentGuid = "";
    UString currentName = model->name(index);
    if (currentName.isEmpty()) {
        currentName = model->text(index);
    }

    // Extract GUID from header if available
    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        if (headerData.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)headerData.constData();
            currentGuid = guidToString(header->Name);
        }
    }

    // Check if this matches our target
    if ((!targetGuid.isEmpty() && currentGuid == targetGuid) ||
        (!targetName.isEmpty() && currentName == targetName)) {
        // Found the component, now build its path
        return createDumpMatchingPath(index, "");
    }

    // Recursively search children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (childIndex.isValid()) {
            UString result = findComponentPathInTree(childIndex, targetGuid, targetName);
            if (!result.isEmpty()) {
                return result;
            }
        }
    }

    return "";
}

void FfsSbomParser::checkForPe32ImageSectionsInChildren(const UModelIndex& index, SbomEntry& entry)
{
    if (!index.isValid()) {
        return;
    }

    // Recursively search children for PE32 image sections
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (!childIndex.isValid()) continue;

        // Check if this child is a PE32 image section
        if (model->type(childIndex) == Types::Section && model->subtype(childIndex) == EFI_SECTION_PE32) {
            // Flag the component as a PE image
            entry.isPe32File = true;
            logProgress("[DEBUG] Found PE32 image section in children for component: " + entry.componentName);

            // Calculate SHA256 hash from the PE32 section data
            if (!model->hasEmptyBody(childIndex)) {
                const UByteArray& peData = model->body(childIndex);
                logProgress("[DEBUG] PE32 section data size: " + usprintf("%d", peData.size()));
                UINT8 hash[32]; // SHA256 produces 32 bytes
                sha256(peData.constData(), peData.size(), hash);

                UString hashString;
                for (int i = 0; i < 32; i++) {
                    hashString += usprintf("%02X", hash[i]);
                }

                // Store the hash in the component
                entry.hash = hashString;
                logProgress("Calculated PE32 hash for component " + entry.componentName + ": " + hashString);
                return; // Found a PE32 image section, no need to continue searching
            } else {
                logProgress("[DEBUG] PE32 section has empty body for component: " + entry.componentName);
            }
        }

        // Recursively check children of this child
        checkForPe32ImageSectionsInChildren(childIndex, entry);
    }
}

void FfsSbomParser::postProcessPe32ImageComponents()
{
    logProgress("[DEBUG] Starting post-processing to find PE32 image components");

    // Iterate through all SBOM entries
    for (auto& entry : sbomEntries) {
        // Check if this component has PE32 image sections in its children
        bool hasPe32ImageSection = false;
        for (const auto& child : entry.children) {
            if (child.subtype.find("PE32 image") != std::string::npos) {
                hasPe32ImageSection = true;
                logProgress("[DEBUG] Found PE32 image section in children for component: " + entry.componentName);

                // Try to calculate hash from the PE32 image section's body.bin file
                UString pe32SectionPath = entry.filePath + "/1 PE32 image section";
                UString bodyBinPath = pe32SectionPath + "/body.bin";

                logProgress("[DEBUG] Attempting to read body.bin from: " + bodyBinPath);
                std::ifstream bodyBinFile(bodyBinPath.toLocal8Bit(), std::ios::binary);
                if (bodyBinFile.is_open()) {
                    logProgress("[DEBUG] Successfully opened body.bin file");
                    // Read the entire file into memory
                    bodyBinFile.seekg(0, std::ios::end);
                    std::streamsize size = bodyBinFile.tellg();
                    bodyBinFile.seekg(0, std::ios::beg);
                    logProgress("[DEBUG] Body.bin file size: " + usprintf("%zu", size));

                    std::vector<char> buffer(size);
                    bodyBinFile.read(buffer.data(), size);
                    bodyBinFile.close();

                    // Calculate SHA256 hash
                    UByteArray data(buffer.data(), buffer.size());
                    UINT8 hash[32]; // SHA256 produces 32 bytes
                    sha256(data.constData(), data.size(), hash);

                    UString hashString;
                    for (int i = 0; i < 32; i++) {
                        hashString += usprintf("%02X", hash[i]);
                    }

                    // Update the component
                    entry.isPe32File = true;
                    entry.hash = hashString;
                    logProgress("Post-processed PE32 hash for component " + entry.componentName + ": " + hashString);
                    break; // Found a PE32 image section, no need to continue
                } else {
                    logProgress("Warning: Could not open body.bin file for PE32 image section: " + bodyBinPath, true);
                }
                break;
            }
        }
    }

    logProgress("[DEBUG] Completed post-processing of PE32 image components");
}

// GUID database functionality (similar to guiddatabase.cpp)
GuidDatabase FfsSbomParser::buildGuidDatabaseFromTree(const UModelIndex& index)
{
    GuidDatabase db;

    if (!index.isValid())
        return db;

    for (int i = 0; i < model->rowCount(index); i++) {
        GuidDatabase tmpDb = buildGuidDatabaseFromTree(index.child(i, 0));
        db.insert(tmpDb.begin(), tmpDb.end());
    }

    if (model->type(index) == Types::File && !model->text(index).isEmpty()) {
        EFI_GUID guid = readUnaligned((const EFI_GUID*)model->header(index).left(16).constData());
        db[guid] = model->text(index);
    }

    return db;
}

USTATUS FfsSbomParser::exportGuidDatabaseToCsv(const UString& outputPath)
{
    std::ofstream outputFile(outputPath.toLocal8Bit(), std::ios::out | std::ios::trunc);
    if (!outputFile)
        return U_FILE_OPEN;

    for (GuidDatabase::iterator it = guidDatabase.begin(); it != guidDatabase.end(); it++) {
        std::string guid(guidToUString(it->first, false).toLocal8Bit());
        std::string name(it->second.toLocal8Bit());
        outputFile << guid << ',' << name << '\n';
    }

    return U_SUCCESS;
}

UString FfsSbomParser::extractGuidFromHeader(const UModelIndex& index)
{
    if (model->type(index) == Types::File && !model->hasEmptyHeader(index)) {
        const UByteArray& header = model->header(index);
        if (header.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* ffsHeader = (const EFI_FFS_FILE_HEADER*)header.constData();
            return guidToUString(ffsHeader->Name);
        }
    }
    return UString();
}

USTATUS FfsSbomParser::generateEnhancedSbom(const UModelIndex& index, const UString& outputPath)
{
    // First, build the GUID database
    logProgress("Building GUID database from firmware tree...");
    guidDatabase = buildGuidDatabaseFromTree(index);
    logProgress("Found " + usprintf("%zu", guidDatabase.size()) + " GUID entries");

    // Export GUID database to CSV
    UString guidCsvPath = outputPath + ".guids.csv";
    USTATUS result = exportGuidDatabaseToCsv(guidCsvPath);
    if (result == U_SUCCESS) {
        logProgress("GUID database exported to: " + guidCsvPath);
    } else {
        logProgress("Failed to export GUID database", true);
    }

    // Parse SBOM with enhanced information
    logProgress("Parsing SBOM with enhanced GUID information...");
    result = parseSbomRecursive(index, outputPath);
    if (result != U_SUCCESS) {
        return result;
    }

    // Post-process components to find PE32 image sections and calculate hashes
    postProcessPe32ImageComponents();

    // Enhance each component with GUID database information
    logProgress("Enhancing components with GUID database information...");
    for (auto& entry : sbomEntries) {
        populateComponentFromGuidDatabase(entry);
    }

    return U_SUCCESS;
}

void FfsSbomParser::populateComponentFromGuidDatabase(SbomEntry& entry)
{
    // If we have a GUID, try to find additional information from the GUID database
    if (!entry.guid.isEmpty()) {
        // Convert GUID string to EFI_GUID for lookup
        EFI_GUID guid;
        if (ustringToGuid(entry.guid, guid)) {
            auto it = guidDatabase.find(guid);
            if (it != guidDatabase.end()) {
                // If component name is empty or generic, use the name from GUID database
                if (entry.componentName.isEmpty() ||
                    entry.componentName == "Unknown" ||
                    entry.componentName.find("GUID_") == 0) {
                    entry.componentName = it->second;
                }

                // Add GUID database name to description if not already present
                if (entry.description.isEmpty()) {
                    entry.description = "GUID Database Name: " + it->second;
                } else if (entry.description.find("GUID Database Name:") == std::string::npos) {
                    entry.description += " (GUID DB: " + it->second + ")";
                }
            }
        }
    }

    // Enhanced version extraction from Version sections
    if (entry.version.isEmpty()) {
        // Try to find version information in the component's sections
        for (const auto& section : entry.sections) {
            if (section.subtype.find("Version") != std::string::npos) {
                // This would require additional parsing of the Version section
                // For now, we'll mark that version information is available
                if (entry.description.isEmpty()) {
                    entry.description = "Version section found";
                } else {
                    entry.description += " (Version section available)";
                }
                break;
            }
        }
    }

    // Enhanced license detection from PE32 sections
    if (entry.license.isEmpty() && entry.isPe32File) {
        // Try to extract license information from PE32 metadata
        for (const auto& section : entry.sections) {
            if (section.subtype.find("PE32") != std::string::npos ||
                section.subtype.find("TE") != std::string::npos) {
                // This would require parsing the PE32 section for license strings
                // For now, we'll mark that PE32 information is available
                if (entry.description.isEmpty()) {
                    entry.description = "PE32 executable with potential license info";
                } else {
                    entry.description += " (PE32 executable)";
                }
                break;
            }
        }
    }
}

// New GUID-centric SBOM generation
USTATUS FfsSbomParser::generateGuidBasedSbom(const UModelIndex& index, const UString& outputPath)
{
    logProgress("Starting GUID-based SBOM generation...");

    // Clear any existing entries
    sbomEntries.clear();
    processedGuids.clear();
    processedComponents.clear();

    // Step 1: Build GUID database using existing function
    logProgress("Building GUID database from firmware tree...");
    guidDatabase = buildGuidDatabaseFromTree(index);
    logProgress("Found " + usprintf("%zu", guidDatabase.size()) + " GUID entries");

    // Export GUID database to CSV
    UString guidCsvPath = outputPath + ".guids.csv";
    USTATUS result = exportGuidDatabaseToCsv(guidCsvPath);
    if (result == U_SUCCESS) {
        logProgress("GUID database exported to: " + guidCsvPath);
    } else {
        logProgress("Failed to export GUID database", true);
    }

    // Step 2: For each GUID in the database, create an SBOM entry
    logProgress("Processing each GUID to create SBOM entries...");
    for (const auto& guidEntry : guidDatabase) {
        const EFI_GUID& guid = guidEntry.first;
        const UString& name = guidEntry.second;

        // Find the tree node for this GUID
        UModelIndex node = findNodeByGuid(index, guid);
        if (!node.isValid()) {
            logProgress("Warning: Could not find tree node for GUID " + guidToUString(guid));
            continue;
        }

        // Create SBOM entry for this GUID
        SbomEntry entry = createSbomEntryFromGuid(guid, name, node);

        // Extract version information
        extractVersionFromNode(node, entry);

        // Extract PE32/TE information
        extractPe32InfoFromNode(node, entry);

        // Add to SBOM entries
        sbomEntries.push_back(entry);
        processedGuids.insert(guidToUString(guid));
    }

    logProgress("Generated " + usprintf("%zu", sbomEntries.size()) + " SBOM entries");
    return U_SUCCESS;
}

UModelIndex FfsSbomParser::findNodeByGuid(const UModelIndex& index, const EFI_GUID& targetGuid)
{
    if (!index.isValid()) {
        return UModelIndex();
    }

    // Check if this node is a File type and matches the target GUID
    if (model->type(index) == Types::File && !model->hasEmptyHeader(index)) {
        const UByteArray& header = model->header(index);
        if (header.size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* ffsHeader = (const EFI_FFS_FILE_HEADER*)header.constData();
            EFI_GUID nodeGuid = readUnaligned((const EFI_GUID*)&ffsHeader->Name);
            if (memcmp(&nodeGuid, &targetGuid, sizeof(EFI_GUID)) == 0) {
                return index;
            }
        }
    }

    // Recursively search children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex result = findNodeByGuid(index.child(i, 0), targetGuid);
        if (result.isValid()) {
            return result;
        }
    }

    return UModelIndex();
}

SbomEntry FfsSbomParser::createSbomEntryFromGuid(const EFI_GUID& guid, const UString& name, const UModelIndex& node)
{
    SbomEntry entry;

    // Basic information
    entry.componentName = name;
    entry.guid = guidToUString(guid);
    entry.offset = model->offset(node);
    entry.size = model->body(node).size() + model->header(node).size();

    // Type and subtype from FFS header
    entry.type = itemTypeToUString(model->type(node));
    entry.subtype = itemSubtypeToUString(model->type(node), model->subtype(node));

    // Component type classification
    entry.componentType = extractComponentType(node);

    // Basic hash calculation
    entry.hash = calculateHash(node);
    entry.sha256Hash = entry.hash;

    // Initialize other fields
    entry.version = "";  // Will be populated by version extraction if available
    entry.build = "";
    entry.license = "Unknown";
    entry.architecture = "";
    entry.buildDate = "";
    entry.vendor = "";
    entry.securityAttributes = "";
    entry.compatibility = "";
    entry.description = name;
    entry.sourceLocation = "";
    entry.contactInfo = "";
    entry.externalReferences = "";
    entry.company = "";
    entry.fileDescription = name;
    entry.fileVersion = "";
    entry.copyright = "";
    entry.signerCN = "";
    entry.peVersion = "";
    entry.parentFfsGuid = "";
    entry.parentFfsName = "";
    entry.peFileName = "";
    entry.peSectionType = "";
    entry.peSectionOffset = 0;
    entry.peSectionSize = 0;
    entry.isPe32File = false;

    return entry;
}

void FfsSbomParser::extractVersionFromNode(const UModelIndex& index, SbomEntry& entry)
{
    if (!index.isValid()) {
        return;
    }

    // Search for Version sections in children
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex child = index.child(i, 0);
        if (!child.isValid()) continue;

        if (model->type(child) == Types::Section && model->subtype(child) == EFI_SECTION_VERSION) {
            // Found a version section
            if (!model->hasEmptyBody(child)) {
                const UByteArray& versionData = model->body(child);
                if (versionData.size() >= 2) {
                    // Parse version string from Version section
                    UString versionString = uFromUcs2(versionData.constData());
                    if (!versionString.isEmpty()) {
                        entry.version = versionString;
                        logProgress("Extracted version info for " + entry.componentName + ": " + entry.version);
                        return;
                    }
                }
            }
        }

        // Recursively search in children
        extractVersionFromNode(child, entry);
        if (!entry.version.isEmpty()) {
            return; // Found version, stop searching
        }
    }
}

void FfsSbomParser::extractPe32InfoFromNode(const UModelIndex& index, SbomEntry& entry)
{
    if (!index.isValid()) {
        return;
    }

    // Search for PE32 or TE image sections
    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex child = index.child(i, 0);
        if (!child.isValid()) continue;

        if (model->type(child) == Types::Section) {
            UINT8 sectionType = model->subtype(child);

            if (sectionType == EFI_SECTION_PE32 || sectionType == EFI_SECTION_TE) {
                // Found PE32 or TE section
                entry.isPe32File = true;
                entry.peSectionType = (sectionType == EFI_SECTION_PE32) ? "PE32" : "TE";
                entry.peSectionOffset = model->offset(child);
                entry.peSectionSize = model->body(child).size();

                // Extract PE32/TE specific information
                if (!model->hasEmptyBody(child)) {
                    const UByteArray& peData = model->body(child);

                    // Calculate hash of PE section
                    UINT8 hash[32];
                    sha256(peData.constData(), peData.size(), hash);
                    UString peHashString;
                    for (int j = 0; j < 32; j++) {
                        peHashString += usprintf("%02X", hash[j]);
                    }
                    entry.hash = peHashString;
                    entry.sha256Hash = peHashString;

                    // Set PE32-specific attributes based on component name
                    entry.license = detectLicenseFromComponentName(entry.componentName);
                    entry.securityAttributes = "Standard";
                    entry.compatibility = "UEFI 2.x";
                    entry.description = "PE32 executable: " + entry.componentName;
                    entry.peFileName = entry.componentName + (sectionType == EFI_SECTION_PE32 ? ".efi" : "_TE.efi");

                    // Try to extract architecture from PE header
                    if (peData.size() >= 64 && peData[0] == 'M' && peData[1] == 'Z') {
                        UINT32 peOffset = readUnaligned((const UINT32*)(peData.constData() + 60));
                        if (peOffset + 24 <= peData.size()) {
                            if (peData[peOffset] == 'P' && peData[peOffset + 1] == 'E') {
                                UINT16 machine = readUnaligned((const UINT16*)(peData.constData() + peOffset + 4));
                                switch (machine) {
                                case 0x014c: entry.architecture = "x86"; break;
                                case 0x8664: entry.architecture = "x64"; break;
                                case 0x01c0: entry.architecture = "ARM"; break;
                                case 0xaa64: entry.architecture = "ARM64"; break;
                                case 0x01f0: entry.architecture = "RISC-V"; break;
                                default: entry.architecture = "Unknown"; break;
                                }
                            }
                        }
                    }

                    logProgress("Extracted PE32 info for " + entry.componentName + ": " + entry.peSectionType + " section, " + usprintf("%d", entry.peSectionSize) + " bytes");
                }
                return; // Found PE section, stop searching
            }
        }

        // Recursively search in children
        extractPe32InfoFromNode(child, entry);
        if (entry.isPe32File) {
            return; // Found PE info, stop searching
        }
    }
}

UString FfsSbomParser::detectLicenseFromComponentName(const UString& componentName)
{
    // Detect license based on component name patterns
    if (componentName.find("Intel") != (size_t)-1 ||
        componentName.find("intel") != (size_t)-1) {
        return "Intel Proprietary";
    }

    if (componentName.find("Ami") != (size_t)-1 ||
        componentName.find("AMI") != (size_t)-1) {
        return "AMI Proprietary";
    }

    if (componentName.find("Microsoft") != (size_t)-1 ||
        componentName.find("MSFT") != (size_t)-1) {
        return "Microsoft Proprietary";
    }

    if (componentName.find("Phoenix") != (size_t)-1) {
        return "Phoenix Proprietary";
    }

    // Default for PE32 files
    return "Proprietary";
}