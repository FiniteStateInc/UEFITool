/* ffsfocusedextractor.cpp

Copyright (c) 2024, LongSoft. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#include "ffsfocusedextractor.h"
#include "../common/types.h"
#include "../common/ffs.h"
#include "../common/utility.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>

FfsFocusedExtractor::FfsFocusedExtractor(TreeModel* treeModel, ExtractionMode mode)
    : model(treeModel), extractionMode(mode)
{
}

FfsFocusedExtractor::~FfsFocusedExtractor()
{
}

USTATUS FfsFocusedExtractor::extract(const UModelIndex& root, const UString& outputPath, bool enableConcurrency)
{
    if (!root.isValid()) {
        logProgress("Invalid root index provided", true);
        return U_INVALID_PARAMETER;
    }

    // Create output directory
    if (!changeDirectory(outputPath) && !makeDirectory(outputPath)) {
        printf("Cannot create directory \"%s\".\n", (const char*)outputPath.toLocal8Bit());
        return U_DIR_CREATE;
    }

    logProgress("Starting FFS/FD focused extraction...");

    USTATUS result = extractRegionRecursive(root, outputPath, enableConcurrency);

    if (result == U_SUCCESS) {
        logProgress("Extraction completed successfully");
        printf("Extraction Statistics:\n");
        printf("  FFS Regions Found: %d\n", stats.ffsRegionsFound.load());
        printf("  FD Regions Found: %d\n", stats.fdRegionsFound.load());
        printf("  FFS Regions Extracted: %d\n", stats.ffsRegionsExtracted.load());
        printf("  FD Regions Extracted: %d\n", stats.fdRegionsExtracted.load());
        printf("  Errors Encountered: %d\n", stats.errorsEncountered.load());
        printf("  Skipped Compressed: %d\n", stats.skippedCompressed.load());
        printf("  Skipped Corrupt: %d\n", stats.skippedCorrupt.load());
    } else {
        logProgress("Extraction failed", true);
    }

    return result;
}

USTATUS FfsFocusedExtractor::extractRegionRecursive(const UModelIndex& index, const UString& path, bool enableConcurrency)
{
    if (!index.isValid())
        return U_INVALID_PARAMETER;

    // Check if this item has already been processed
    {
        std::lock_guard<std::mutex> lock(outputMutex);
        if (processedItems.find(index) != processedItems.end()) {
            return U_SUCCESS; // Already processed
        }
        processedItems.insert(index);
    }

    USTATUS result = U_SUCCESS;

    // Check if this is a region we should extract
    if (shouldExtractRegion(index)) {
        if (isValidFfsOrFdRegion(index)) {
            // Ensure the directory exists before extraction
            if (!changeDirectory(path) && !makeDirectory(path)) {
                logProgress("Cannot create directory: " + path, true);
                return U_DIR_CREATE;
            }

            if (enableConcurrency && model->rowCount(index) > 1) {
                // Use concurrent extraction for regions with multiple children
                result = extractRegionConcurrent(index, path);
            } else {
                // Use sequential extraction for simple regions
                result = extractSingleRegion(index, path);
            }
        }
    }

    // Recursively process children
    std::vector<std::future<USTATUS>> futures;
    std::vector<UString> childPaths;

    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (!childIndex.isValid())
            continue;

        UString childPath = path;
        if (enableConcurrency && model->rowCount(childIndex) > 0) {
            // Create unique path for concurrent processing
            UString name = usprintf("%d_%s", i, model->name(childIndex).toLocal8Bit());
            // Replace spaces and special characters
            for (size_t j = 0; j < name.length(); j++) {
                if (name[j] == ' ' || name[j] == '/' || name[j] == '\\' || name[j] == ':' || name[j] == '*') {
                    name[j] = '_';
                }
            }
            fixFileName(name, false);
            childPath = usprintf("%s/%s", path.toLocal8Bit(), name.toLocal8Bit());
            childPaths.push_back(childPath);

            // Start concurrent extraction
            futures.push_back(std::async(std::launch::async,
                [this, childIndex, childPath, enableConcurrency]() {
                    return extractRegionRecursive(childIndex, childPath, enableConcurrency);
                }));
        } else {
            // Sequential processing
            result = extractRegionRecursive(childIndex, childPath, enableConcurrency);
            if (result != U_SUCCESS) {
                stats.errorsEncountered++;
                logProgress("Error in recursive extraction", true);
            }
        }
    }

    // Wait for concurrent operations to complete
    for (auto& future : futures) {
        USTATUS futureResult = future.get();
        if (futureResult != U_SUCCESS) {
            result = futureResult;
            stats.errorsEncountered++;
        }
    }

    return result;
}

USTATUS FfsFocusedExtractor::extractSingleRegion(const UModelIndex& index, const UString& path)
{
    if (!index.isValid())
        return U_INVALID_PARAMETER;

    UINT8 type = model->type(index);

    switch (type) {
    case Types::Volume:
        return extractFfsRegion(index, path);
    case Types::Region:
        return extractFdRegion(index, path);
    default:
        return U_SUCCESS; // Skip other types
    }
}

USTATUS FfsFocusedExtractor::extractFfsRegion(const UModelIndex& index, const UString& path)
{
    stats.ffsRegionsFound++;

    if (extractionMode == EXTRACT_FD_ONLY) {
        return U_SUCCESS; // Skip FFS in FD-only mode
    }

    UString filename = createSafeFilename(index, path, "ffs");
    USTATUS result = U_SUCCESS;

    // Create combined FFS file (header + body)
    UString combinedFile = filename + ".ffs";
    std::ofstream file(combinedFile.toLocal8Bit(), std::ofstream::binary);
    if (!file.is_open()) {
        stats.errorsEncountered++;
        logProgress("Cannot open combined FFS file for writing: " + combinedFile, true);
        return U_FILE_OPEN;
    }

    // Write header first
    if (!model->hasEmptyHeader(index)) {
        const UByteArray& headerData = model->header(index);
        file.write(headerData.constData(), headerData.size());
        if (!file.good()) {
            stats.errorsEncountered++;
            logProgress("Failed to write FFS header to combined file", true);
            return U_FILE_WRITE;
        }
    }

    // Write body
    if (!model->hasEmptyBody(index)) {
        if (isCompressedRegion(index)) {
            stats.skippedCompressed++;
            logProgress("Skipping compressed FFS region (decompression not implemented)");
            file.close();
            return U_SUCCESS;
        }

        const UByteArray& bodyData = model->body(index);
        file.write(bodyData.constData(), bodyData.size());
        if (!file.good()) {
            stats.errorsEncountered++;
            logProgress("Failed to write FFS body to combined file", true);
            return U_FILE_WRITE;
        }
    }

    // Write tail if present
    if (!model->hasEmptyTail(index)) {
        const UByteArray& tailData = model->tail(index);
        file.write(tailData.constData(), tailData.size());
        if (!file.good()) {
            stats.errorsEncountered++;
            logProgress("Failed to write FFS tail to combined file", true);
            return U_FILE_WRITE;
        }
    }

    file.close();

    // Write info file
    UString infoFile = filename + "_info.txt";
    std::ofstream info(infoFile.toLocal8Bit());
    if (info.is_open()) {
        info << "Type: " << itemTypeToUString(model->type(index)).toLocal8Bit() << "\n";
        info << "Subtype: " << itemSubtypeToUString(model->type(index), model->subtype(index)).toLocal8Bit() << "\n";
        info << "Offset: 0x" << std::hex << model->offset(index) << "\n";
        info << "Header Size: " << std::dec << model->header(index).size() << " bytes\n";
        info << "Body Size: " << std::dec << model->body(index).size() << " bytes\n";
        info << "Tail Size: " << std::dec << model->tail(index).size() << " bytes\n";
        info << "Total Size: " << std::dec << (model->header(index).size() + model->body(index).size() + model->tail(index).size()) << " bytes\n";
        if (!model->text(index).isEmpty()) {
            info << "Text: " << model->text(index).toLocal8Bit() << "\n";
        }
        info << model->info(index).toLocal8Bit() << "\n";
        info.close();
    }

    stats.ffsRegionsExtracted++;
    logProgress("Extracted FFS region: " + model->name(index));

    return U_SUCCESS;
}

USTATUS FfsFocusedExtractor::extractFdRegion(const UModelIndex& index, const UString& path)
{
    stats.fdRegionsFound++;

    if (extractionMode == EXTRACT_FFS_ONLY) {
        return U_SUCCESS; // Skip FD in FFS-only mode
    }

    UString filename = createSafeFilename(index, path, "fd");
    USTATUS result = U_SUCCESS;

    // Extract header
    if (!model->hasEmptyHeader(index)) {
        UString headerFile = filename + "_header.bin";
        result = writeRegionData(model->header(index), headerFile);
        if (result != U_SUCCESS) {
            stats.errorsEncountered++;
            logProgress("Failed to write FD header", true);
            return result;
        }
    }

    // Extract body
    if (!model->hasEmptyBody(index)) {
        UString bodyFile = filename + "_body.bin";
        result = writeRegionData(model->body(index), bodyFile);
        if (result != U_SUCCESS) {
            stats.errorsEncountered++;
            logProgress("Failed to write FD body", true);
            return result;
        }
    }

    // Write info file
    UString infoFile = filename + "_info.txt";
    std::ofstream info(infoFile.toLocal8Bit());
    if (info.is_open()) {
        info << "Type: " << itemTypeToUString(model->type(index)).toLocal8Bit() << "\n";
        info << "Subtype: " << itemSubtypeToUString(model->type(index), model->subtype(index)).toLocal8Bit() << "\n";
        info << "Offset: 0x" << std::hex << model->offset(index) << "\n";
        info << "Size: " << std::dec << model->body(index).size() << " bytes\n";
        if (!model->text(index).isEmpty()) {
            info << "Text: " << model->text(index).toLocal8Bit() << "\n";
        }
        info << model->info(index).toLocal8Bit() << "\n";
        info.close();
    }

    stats.fdRegionsExtracted++;
    logProgress("Extracted FD region: " + model->name(index));

    return U_SUCCESS;
}

USTATUS FfsFocusedExtractor::extractRegionConcurrent(const UModelIndex& index, const UString& path)
{
    // Create directory for concurrent extraction
    if (!changeDirectory(path) && !makeDirectory(path)) {
        logProgress("Cannot create directory for concurrent extraction", true);
        return U_DIR_CREATE;
    }

    // Extract the region itself first
    USTATUS result = extractSingleRegion(index, path);

    // Then process children concurrently
    std::vector<std::future<USTATUS>> futures;

    for (int i = 0; i < model->rowCount(index); i++) {
        UModelIndex childIndex = index.child(i, 0);
        if (!childIndex.isValid())
            continue;

        UString childPath = usprintf("%s/child_%d", path.toLocal8Bit(), i);

        futures.push_back(std::async(std::launch::async,
            [this, childIndex, childPath]() {
                return extractRegionRecursive(childIndex, childPath, false); // Disable nested concurrency
            }));
    }

    // Wait for all child extractions to complete
    for (auto& future : futures) {
        USTATUS futureResult = future.get();
        if (futureResult != U_SUCCESS) {
            result = futureResult;
            stats.errorsEncountered++;
        }
    }

    return result;
}

USTATUS FfsFocusedExtractor::writeRegionData(const UByteArray& data, const UString& filepath)
{
    std::ofstream file(filepath.toLocal8Bit(), std::ofstream::binary);
    if (!file.is_open()) {
        logProgress("Cannot open file for writing: " + filepath, true);
        return U_FILE_OPEN;
    }

    // Use buffered I/O for memory efficiency
    const size_t bufferSize = 64 * 1024; // 64KB buffer
    const char* dataPtr = data.constData();
    size_t remaining = data.size();

    while (remaining > 0) {
        size_t toWrite = std::min(remaining, bufferSize);
        file.write(dataPtr, toWrite);

        if (!file.good()) {
            logProgress("Error writing to file: " + filepath, true);
            return U_FILE_WRITE;
        }

        dataPtr += toWrite;
        remaining -= toWrite;
    }

    file.close();
    return U_SUCCESS;
}

UString FfsFocusedExtractor::createSafeFilename(const UModelIndex& index, const UString& basePath, const UString& suffix)
{
    UString name = model->name(index);
    if (name.isEmpty()) {
        name = usprintf("region_0x%08X", model->offset(index));
    }

    // Replace spaces and special characters with underscores
    for (size_t i = 0; i < name.length(); i++) {
        if (name[i] == ' ' || name[i] == '/' || name[i] == '\\' || name[i] == ':' || name[i] == '*') {
            name[i] = '_';
        }
    }

    fixFileName(name, false);
    return usprintf("%s/%s_%s", basePath.toLocal8Bit(), name.toLocal8Bit(), suffix.toLocal8Bit());
}

bool FfsFocusedExtractor::shouldExtractRegion(const UModelIndex& index) const
{
    if (!index.isValid())
        return false;

    UINT8 type = model->type(index);

    switch (extractionMode) {
    case EXTRACT_FFS_ONLY:
        return (type == Types::Volume);
    case EXTRACT_FD_ONLY:
        return (type == Types::Region);
    case EXTRACT_FFS_AND_FD:
        return (type == Types::Volume || type == Types::Region);
    default:
        return false;
    }
}

bool FfsFocusedExtractor::isValidFfsOrFdRegion(const UModelIndex& index) const
{
    if (!index.isValid())
        return false;

    UINT8 type = model->type(index);

    if (type == Types::Volume) {
        // Check if it's a valid FFS volume
        UINT8 subtype = model->subtype(index);
        return (subtype == Subtypes::Ffs2Volume || subtype == Subtypes::Ffs3Volume);
    } else if (type == Types::Region) {
        // Check if it's a valid FD region (BiosRegion, etc.)
        UINT8 subtype = model->subtype(index);
        return (subtype == Subtypes::BiosRegion ||
                subtype == Subtypes::Bios2Region ||
                subtype == Subtypes::DescriptorRegion);
    }

    return false;
}

bool FfsFocusedExtractor::isCompressedRegion(const UModelIndex& index) const
{
    return model->compressed(index);
}

void FfsFocusedExtractor::logProgress(const UString& message, bool isError)
{
    std::lock_guard<std::mutex> lock(outputMutex);
    if (isError) {
        fprintf(stderr, "ERROR: %s\n", (const char*)message.toLocal8Bit());
    } else {
        fprintf(stderr, "INFO: %s\n", (const char*)message.toLocal8Bit());
    }
}