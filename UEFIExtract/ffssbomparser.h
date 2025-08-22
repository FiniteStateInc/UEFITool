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
#include "../common/guiddatabase.h"

struct SectionInfo {
    UString type;
    UString subtype;
    UINT32 offset;
    UINT32 size;
    UString description;
};

struct SbomEntry {
    // Basic SBOM fields
    UString componentName;       // Component name
    UString guid;               // Component GUID
    UString version;            // Component version
    UString build;              // Build number (separate from version)
    UString hash;               // Component hash
    UString license;            // License information
    std::vector<UString> dependencies; // Component dependencies
    UString type;               // Component type
    UString subtype;            // Component subtype
    UINT32 offset;              // Component offset
    UINT32 size;                // Component size
    UString filePath;           // File path

    // Additional SBOM fields based on UEFI best practices
    UString componentType;        // Driver, Application, Library, etc.
    UString architecture;         // x64, ARM64, etc.
    UString buildDate;           // Build date/time
    UString vendor;              // Vendor/Publisher
    // Removed checksumAlgorithm since it's always SHA256
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
    std::vector<SectionInfo> sections; // List of sections contained in this FFS

    // ME region metadata
    UString meSku;        // ME SKU/Type (e.g., Corporate, Consumer)
    UString meBuildDate;  // ME Build Date (if available)

    // FFSv2 specific fields
    UString filesystemGuid;  // Filesystem GUID for FFSv2 volumes
    UString volumeGuid;      // Volume GUID for FFSv2 volumes
    UString attributes;      // Attributes for FFSv2 volumes
    UString signature;       // Signature for FFSv2 volumes
    UString checksum;        // Checksum for FFSv2 volumes

    // Region metadata
    UString base;            // Base address for regions
    UString address;         // Address for regions
    UString fixed;           // Fixed status for regions
    UString fullSize;        // Full size for regions
    std::vector<SbomEntry> children; // Children components for regions
    std::vector<UString> sectionInfo;   // Section information from info.txt and body.bin files
};

// PE metadata structure for enhanced extraction
struct PeMetadata {
    UString fileName;        // Name of the PE file
    UString version;         // PE version
    UString company;
    UString fileDescription;
    UString fileVersion;
    UString signerCN;
    UString copyright;
};

// Structure to hold version information
struct VersionInfo {
    UString versionString;
    UString buildNumber;
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
    USTATUS exportToStdout();
    USTATUS exportToCsv(const UString& filepath);
    USTATUS exportToJsonStdout();

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
    VersionInfo searchForVersionSection(const UModelIndex& index);
    VersionInfo parseVersionSection(const UModelIndex& index);

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

    void checkForPe32ImageSectionsInChildren(const UModelIndex& index, SbomEntry& entry);
    void postProcessPe32ImageComponents();

private:
    TreeModel* model;
    std::vector<SbomEntry> sbomEntries;
    std::map<UString, UString> guidToNameMap;
    std::set<UString> processedGuids;
    std::set<UString> processedComponents;  // For deduplication by component name + offset
    GuidDatabase guidDatabase;  // GUID database for enhanced SBOM generation

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

    // ME region support
    UString extractMeVersionFromBody(const UByteArray& body);
    UString extractMeSkuFromBody(const UByteArray& body);
    UString extractMeBuildDateFromBody(const UByteArray& body);

    // Extract PE metadata
    UString extractCompany(const UModelIndex& index);
    UString extractFileDescription(const UModelIndex& index);
    UString extractFileVersion(const UModelIndex& index);
    UString extractCopyright(const UModelIndex& index);
    UString extractSignerCN(const UModelIndex& index);
    UString extractPeVersion(const UModelIndex& index);
    // Removed calculateSha256Hash - using calculateHash instead

    // PE image parsing helpers
    UString extractPeComponentName(const UByteArray& peData);
    UString extractPeVersion(const UByteArray& peData);
    UString extractUiString(const UModelIndex& index);
    std::vector<UString> parseDepexSection(const UModelIndex& index);

    // Enhanced PE metadata extraction (Python code equivalent)
    UString findPe32SectionInFfs(const UModelIndex& index);
    PeMetadata extractEnhancedPeMetadata(const UString& pePath);
    UString calculateSha256FromFile(const UString& filePath);
    UString firstFileMatching(const UString& dirPath, const UString& pattern);

    // Version section extraction
    UString findVersionSectionInFfs(const UModelIndex& index);
    UString extractVersionFromInfoFile(const UString& infoFilePath);
    UString searchForVersionInfoFile(const UModelIndex& index);

    // Version extraction from Version sections
    void extractVersionFromVersionSections(const UModelIndex& index, SbomEntry& entry);
    UString extractVersionStringFromInfoFile(const UModelIndex& versionSection);

    // String analysis for license detection
    UString detectLicenseFromStrings(const UByteArray& data);

    // GUID utilities
    UString guidToString(const EFI_GUID& guid);
    UString findGuidName(const UString& guid);

    // File utilities
    UString createSafeFilename(const UModelIndex& index, const UString& basePath);
    UString createDumpMatchingPath(const UModelIndex& index, const UString& basePath);
    UString findComponentPathInTree(const UModelIndex& index, const UString& targetGuid, const UString& targetName);
    bool validateFilePath(const UString& filePath);
    UString findActualFilePath(const UString& expectedPath);
    UString findComponentInDump(const UModelIndex& index);
    UString searchForComponentInDump(const std::string& dumpDir, const UString& componentId);
    std::string findMatchingDirectory(const std::string& parentPath, const std::string& expectedName);

    // BIOS Region hierarchy
    void createBiosRegionHierarchy();
    void trim(UString& str);

    // FFSv2 metadata extraction
    void extractFfsv2Metadata(const UString& infoFilePath, SbomEntry& entry);
    void deduplicateContainedPeFiles(SbomEntry& entry);

    // Region children population
    void populateRegionChildren(SbomEntry& regionEntry);
    void processSubfolderForComponent(const UString& subfolderPath, SbomEntry& parentComponent);
    void populateSubfolderChildren(SbomEntry& parentComponent);

    // PE metadata extraction from files
    bool extractPeMetadataFromFile(const std::string& filePath, PeMetadata& peData);

    // GUID to friendly name translation
    UString translateGuidToFriendlyName(const UString& guid);

    // GUID database functionality (similar to guiddatabase.cpp)
    GuidDatabase buildGuidDatabaseFromTree(const UModelIndex& index);
    USTATUS exportGuidDatabaseToCsv(const UString& outputPath);
    UString extractGuidFromHeader(const UModelIndex& index);

    // Logging
    void logProgress(const UString& message, bool isError = false);

public:
    // Enhanced SBOM with GUID database integration
    USTATUS generateEnhancedSbom(const UModelIndex& index, const UString& outputPath);
    void populateComponentFromGuidDatabase(SbomEntry& entry);

    // New GUID-centric SBOM generation
    USTATUS generateGuidBasedSbom(const UModelIndex& index, const UString& outputPath);
    UModelIndex findNodeByGuid(const UModelIndex& index, const EFI_GUID& targetGuid);
    void extractVersionFromNode(const UModelIndex& index, SbomEntry& entry);
    void extractPe32InfoFromNode(const UModelIndex& index, SbomEntry& entry);
    SbomEntry createSbomEntryFromGuid(const EFI_GUID& guid, const UString& name, const UModelIndex& node);
    UString detectLicenseFromComponentName(const UString& componentName);};

#endif // FFSSBOMPARSER_H
