/* ffssbomparser.h

Copyright (c) 2024, LongSoft. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#ifndef FFSSBOMPARSER_H
#define FFSSBOMPARSER_H

#include <vector>
#include <map>
#include <set>

#include "../common/basetypes.h"
#include "../common/ustring.h"
#include "../common/treemodel.h"
#include "../common/ffs.h"
#include "../common/peimage.h"
#include "../common/filesystem.h"
#include "../common/utility.h"
#include "../common/digest/sha2.h"

struct SbomEntry {
    UString componentName;
    UString guid;
    UString version;
    UString hash;
    UString license;
    std::vector<UString> dependencies;
    UString filePath;
    UString type;
    UString subtype;
    UINT32 offset;
    UINT32 size;

    // Additional SBOM fields based on UEFI best practices
    UString componentType;        // Driver, Application, Library, etc.
    UString architecture;         // x64, ARM64, etc.
    UString buildDate;           // Build date/time
    UString vendor;              // Vendor/Publisher
    UString checksumAlgorithm;   // SHA256, SHA384, etc.
    UString securityAttributes;  // Secure boot, measured boot, etc.
    UString compatibility;       // UEFI version compatibility
    UString description;         // Component description
    UString sourceLocation;      // Source code location if available
    UString contactInfo;         // Contact information
    UString externalReferences;  // External references/URLs

    // PE metadata fields
    UString company;             // Company name from PE version info
    UString fileDescription;     // File description from PE version info
    UString fileVersion;         // File version from PE version info
    UString copyright;           // Copyright from PE version info
    UString signerCN;            // Digital signature common name
    UString peVersion;           // PE version string
    UString sha256Hash;          // SHA-256 hash of PE file

    // PE32 file tracking fields
    UString parentFfsGuid;       // GUID of parent FFS file
    UString parentFfsName;       // Name of parent FFS file
    UString peFileName;          // Name of the PE file (e.g., GopDriver.efi)
    UString peSectionType;       // Type of PE section (PE32, TE, etc.)
    UINT32 peSectionOffset;      // Offset of PE section within FFS
    UINT32 peSectionSize;        // Size of PE section
    bool isPe32File;             // Whether this entry represents a PE32 file
    std::vector<UString> containedPeFiles; // List of PE files contained in this FFS
};

class FfsSbomParser
{
public:
    explicit FfsSbomParser(TreeModel* treeModel);
    ~FfsSbomParser();

    // Main parsing function
    USTATUS parseSbom(const UModelIndex& root, const UString& outputPath);

    // Get parsed SBOM entries
    const std::vector<SbomEntry>& getSbomEntries() const { return sbomEntries; }

    // Export SBOM to different formats
    USTATUS exportToText(const UString& filepath);
    USTATUS exportToCsv(const UString& filepath);
    USTATUS exportToJson(const UString& filepath);

    // Main parsing methods
    bool parseFfsFile(const UModelIndex& index, const UString& basePath);
    void parseFfsFileRecursive(const UModelIndex& index, const UString& basePath);
    bool extractPeMetadataFromFfs(const UModelIndex& index, SbomEntry& entry);

    // PE metadata extraction helpers
    UString extractPeVersionResource(const UByteArray& peData, const UString& resourceName);
    UString extractPeDigitalSignature(const UByteArray& peData);
    UString calculateSha256(const UByteArray& data);
    bool isPeExecutable(const UModelIndex& index);
    void searchForPeSections(const UModelIndex& index, SbomEntry& entry, bool& metadataFound);
    void extractPeMetadataFromSection(const UModelIndex& index, SbomEntry& entry, bool& metadataFound);
    UString extractArchitectureFromPeData(const UByteArray& peData);
    UString extractBuildDateFromPeData(const UByteArray& peData);
    UString extractVersionFromVersionSection(const UModelIndex& index);
    UString searchForVersionSection(const UModelIndex& index);
    UString parseVersionSection(const UModelIndex& index);

    // PE32 file identification and parsing
    void identifyPe32FilesInFfs(const UModelIndex& index, SbomEntry& ffsEntry);
    std::vector<SbomEntry> extractPe32FilesFromFfs(const UModelIndex& index, const UString& parentGuid, const UString& parentName);
    SbomEntry createPe32Entry(const UModelIndex& peSection, const UString& parentGuid, const UString& parentName, const UString& basePath);
    UString extractPeFileName(const UModelIndex& peSection, const UString& parentName);
    UString determinePeSectionType(const UModelIndex& peSection);
    void updateFfsEntryWithPeFiles(SbomEntry& ffsEntry, const std::vector<SbomEntry>& peEntries);

    // Extract version string from Version section body (UCS-2/UTF-16LE)
    UString extractVersionStringFromVersionSection(const UModelIndex& ffsIndex);

    UString extractPeVersionFromIndex(const UModelIndex& index);

private:
    TreeModel* model;
    std::vector<SbomEntry> sbomEntries;
    std::map<UString, UString> guidToNameMap;
    std::set<UString> processedGuids;

    // Recursive parsing
    USTATUS parseSbomRecursive(const UModelIndex& index, const UString& basePath);

    // Extract component information
    UString extractComponentName(const UModelIndex& index);
    UString extractVersion(const UModelIndex& index);
    UString calculateHash(const UModelIndex& index);
    UString extractLicense(const UModelIndex& index);
    std::vector<UString> extractDependencies(const UModelIndex& index);

    // Extract additional SBOM fields
    UString extractComponentType(const UModelIndex& index);
    UString extractArchitecture(const UModelIndex& index);
    UString extractBuildDate(const UModelIndex& index);
    UString extractVendor(const UModelIndex& index);
    UString extractSecurityAttributes(const UModelIndex& index);
    UString extractCompatibility(const UModelIndex& index);
    UString extractDescription(const UModelIndex& index);
    UString extractSourceLocation(const UModelIndex& index);
    UString extractContactInfo(const UModelIndex& index);
    UString extractExternalReferences(const UModelIndex& index);

    // Extract PE metadata
    UString extractCompany(const UModelIndex& index);
    UString extractFileDescription(const UModelIndex& index);
    UString extractFileVersion(const UModelIndex& index);
    UString extractCopyright(const UModelIndex& index);
    UString extractSignerCN(const UModelIndex& index);
    UString extractPeVersion(const UModelIndex& index);
    UString calculateSha256Hash(const UModelIndex& index);

    // PE image parsing helpers
    UString extractPeComponentName(const UByteArray& peData);
    UString extractPeVersion(const UByteArray& peData);
    UString extractUiString(const UModelIndex& index);
    std::vector<UString> parseDepexSection(const UModelIndex& index);

    // String analysis for license detection
    UString detectLicenseFromStrings(const UByteArray& data);

    // GUID utilities
    UString guidToString(const EFI_GUID& guid);
    UString findGuidName(const UString& guid);

    // File utilities
    UString createSafeFilename(const UModelIndex& index, const UString& basePath);

    // Logging
    void logProgress(const UString& message, bool isError = false);
};

#endif // FFSSBOMPARSER_H