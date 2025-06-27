/* ffsfocusedextractor.h

Copyright (c) 2024, LongSoft. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#ifndef FFSFOCUSEDEXTRACTOR_H
#define FFSFOCUSEDEXTRACTOR_H

#include <vector>
#include <future>
#include <mutex>
#include <atomic>
#include <set>

#include "../common/basetypes.h"
#include "../common/ustring.h"
#include "../common/treemodel.h"
#include "../common/ffs.h"
#include "../common/filesystem.h"
#include "../common/utility.h"

class FfsFocusedExtractor
{
public:
    enum ExtractionMode {
        EXTRACT_FFS_ONLY,      // Extract only FFS regions
        EXTRACT_FD_ONLY,       // Extract only FD regions
        EXTRACT_FFS_AND_FD     // Extract both FFS and FD regions
    };

    struct ExtractionStats {
        std::atomic<int> ffsRegionsFound{0};
        std::atomic<int> fdRegionsFound{0};
        std::atomic<int> ffsRegionsExtracted{0};
        std::atomic<int> fdRegionsExtracted{0};
        std::atomic<int> errorsEncountered{0};
        std::atomic<int> skippedCompressed{0};
        std::atomic<int> skippedCorrupt{0};
    };

    explicit FfsFocusedExtractor(TreeModel* treeModel, ExtractionMode mode = EXTRACT_FFS_AND_FD);
    ~FfsFocusedExtractor();

    // Main extraction function
    USTATUS extract(const UModelIndex& root, const UString& outputPath, bool enableConcurrency = true);

    // Get extraction statistics
    const ExtractionStats& getStats() const { return stats; }

    // Check if a region should be extracted based on current mode
    bool shouldExtractRegion(const UModelIndex& index) const;

    // Check if a region is a valid FFS or FD region
    bool isValidFfsOrFdRegion(const UModelIndex& index) const;

private:
    TreeModel* model;
    ExtractionMode extractionMode;
    ExtractionStats stats;
    std::mutex outputMutex;
    std::set<UModelIndex> processedItems;

    // Recursive extraction with concurrency support
    USTATUS extractRegionRecursive(const UModelIndex& index, const UString& path, bool enableConcurrency);

    // Extract a single region
    USTATUS extractSingleRegion(const UModelIndex& index, const UString& path);

    // Extract FFS region
    USTATUS extractFfsRegion(const UModelIndex& index, const UString& path);

    // Extract FD region
    USTATUS extractFdRegion(const UModelIndex& index, const UString& path);

    // Handle compressed sections
    USTATUS handleCompressedSection(const UModelIndex& index, const UString& path);

    // Create safe filename for output
    UString createSafeFilename(const UModelIndex& index, const UString& basePath, const UString& suffix);

    // Write region data to file with buffered I/O
    USTATUS writeRegionData(const UByteArray& data, const UString& filepath);

    // Check if region is compressed
    bool isCompressedRegion(const UModelIndex& index) const;

    // Log extraction progress
    void logProgress(const UString& message, bool isError = false);

    // Concurrent extraction worker
    USTATUS extractRegionConcurrent(const UModelIndex& index, const UString& path);
};

#endif // FFSFOCUSEDEXTRACTOR_H