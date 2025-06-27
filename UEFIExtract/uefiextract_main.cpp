/* uefiextract_main.cpp
Copyright (c) 2018, LongSoft. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php
THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
*/

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <set>

#include "../version.h"
#include "../common/basetypes.h"
#include "../common/ustring.h"
#include "../common/filesystem.h"
#include "../common/ffsparser.h"
#include "../common/ffsreport.h"
#include "../common/guiddatabase.h"
#include "ffsdumper.h"
#include "uefidump.h"
#include "ffsfocusedextractor.h"
#include "ffssbomparser.h"

enum ReadType {
    READ_INPUT,
    READ_OUTPUT,
    READ_MODE,
    READ_SECTION
};

void print_usage()
{
    std::cout << "UEFIExtract " PROGRAM_VERSION << std::endl
        << "Usage: UEFIExtract {-h | --help | -v | --version} - show help and/or version information." << std::endl
        << "       UEFIExtract imagefile        - generate report and GUID database, then dump only leaf tree items into .dump folder." << std::endl
        << "       UEFIExtract imagefile all    - generate report and GUID database, then dump all tree items into .dump folder." << std::endl
        << "       UEFIExtract imagefile unpack - generate report, then dump all tree items into a single .dump folder (legacy UEFIDump compatibility mode)." << std::endl
        << "       UEFIExtract imagefile dump   - only generate dump, no report or GUID database needed." << std::endl
        << "       UEFIExtract imagefile report - only generate report, no dump or GUID database needed." << std::endl
        << "       UEFIExtract imagefile guids  - only generate GUID database, no dump or report needed." << std::endl
        << "       UEFIExtract imagefile [all|dump|unpack] [--outdir DIR|-d DIR] - specify output directory for extraction." << std::endl
        << "       UEFIExtract imagefile GUID_1 ... [ -o FILE_1 ... ] [ -m MODE_1 ... ] [ -t TYPE_1 ... ] -" << std::endl
        << "         Dump only FFS file(s) with specific GUID(s), without report or GUID database." << std::endl
        << "         Type is section type or FF to ignore. Mode is one of: all, body, unc_data, header, info, file." << std::endl
        << "         Return value is a bit mask where 0 at position N means that file with GUID_N was found and unpacked, 1 otherwise." << std::endl
        << "       UEFIExtract --ffs-fd-only imagefile [--outdir DIR|-d DIR]  - extract only top-level FD and embedded FFS regions into specified folder." << std::endl
        << "         This mode is memory-efficient, concurrent, and skips compressed or corrupt regions." << std::endl
        << "       UEFIExtract --sbom imagefile  - parse image and generate SBOM text file (Software Bill of Materials) for all FFS modules." << std::endl
        << "       --outdir DIR, -d DIR   Specify output directory for extraction (default: <imagefile>.dump)" << std::endl;
}

void extractFlatFfsFdOnly(TreeModel* model, const UModelIndex& index, const UString& outDir, std::set<UString>& usedNames) {
    if (!index.isValid()) return;
    UINT8 type = model->type(index);
    UString filename;
    if (type == Types::File) {
        // FFS file
        if (!model->hasEmptyHeader(index) && model->header(index).size() >= sizeof(EFI_FFS_FILE_HEADER)) {
            const EFI_FFS_FILE_HEADER* header = (const EFI_FFS_FILE_HEADER*)model->header(index).constData();
            UString guid = guidToUString(header->Name);
            filename = usprintf("%s_%08X.ffs", guid.toLocal8Bit(), model->offset(index));
        } else {
            filename = usprintf("UNKNOWN_%08X.ffs", model->offset(index));
        }
    } else if (type == Types::Region) {
        // FD region
        filename = usprintf("%08X.fd", model->offset(index));
    }
    if (!filename.isEmpty()) {
        // Ensure unique filename
        UString base = filename;
        int n = 1;
        while (usedNames.count(filename)) {
            filename = base + usprintf("_%d", n++);
        }
        usedNames.insert(filename);
        // Write body
        const UByteArray& body = model->body(index);
        if (!body.isEmpty()) {
            std::ofstream file((outDir + "/" + filename).toLocal8Bit(), std::ios::binary);
            file.write(body.constData(), body.size());
            file.close();
        }
    }
    // Recurse into children
    for (int i = 0; i < model->rowCount(index); ++i) {
        extractFlatFfsFdOnly(model, index.child(i, 0), outDir, usedNames);
    }
}

int main(int argc, char *argv[])
{
    initGuidDatabase("guids.csv");

    if (argc <= 1) {
        print_usage();
        return 1;
    }

    // Help and version
    if (argc == 2) {
        UString arg = UString(argv[1]);
        if (arg == UString("-h") || arg == UString("--help")) {
            print_usage();
            return 0;
        }
        else if (arg == UString("-v") || arg == UString("--version")) {
            std::cout << PROGRAM_VERSION << std::endl;
            return 0;
        }
    }

    // Check for new --ffs-fd-only option
    if (argc >= 3 && !std::strcmp(argv[1], "--ffs-fd-only")) {
        UString path = getAbsPath(argv[2]);
        UString outDir;
        for (int i = 3; i < argc; i++) {
            if (!std::strcmp(argv[i], "--outdir") || !std::strcmp(argv[i], "-d")) {
                if (i + 1 < argc) {
                    outDir = UString(argv[i + 1]);
                    break;
                }
            }
        }
        UByteArray buffer;
        if (false == readFileIntoBuffer(path, buffer))
            return U_FILE_OPEN;
        TreeModel model;
        FfsParser ffsParser(&model);
        USTATUS result = ffsParser.parse(buffer);
        if (result)
            return (int)result;
        UString outPath = outDir.isEmpty() ? path + UString(".dump_ffs_fd_only") : outDir;
        makeDirectory(outPath);
        std::set<UString> usedNames;
        extractFlatFfsFdOnly(&model, model.index(0, 0), outPath, usedNames);
        return 0;
    }

    // Check for new --sbom option
    if (argc >= 3 && !std::strcmp(argv[1], "--sbom")) {
        UString path = getAbsPath(argv[2]);
        UByteArray buffer;
        if (false == readFileIntoBuffer(path, buffer))
            return U_FILE_OPEN;
        TreeModel model;
        FfsParser ffsParser(&model);
        USTATUS result = ffsParser.parse(buffer);
        if (result)
            return (int)result;
        FfsSbomParser sbomParser(&model);
        result = sbomParser.parseSbom(model.index(0, 0), path + UString(".sbom"));
        if (result)
            return (int)result;
        return sbomParser.exportToText(path + UString(".sbom.txt"));
    }

    // Check that input file exists
    USTATUS result;
    UByteArray buffer;
    UString path = getAbsPath(argv[1]);
    if (false == readFileIntoBuffer(path, buffer))
        return U_FILE_OPEN;

    // Hack to support legacy UEFIDump mode
    if (argc == 3 && !std::strcmp(argv[2], "unpack")) {
        UEFIDumper uefidumper;
        return (uefidumper.dump(buffer, UString(argv[1])) != U_SUCCESS);
    }

    // Create model and ffsParser
    TreeModel model;
    FfsParser ffsParser(&model);
    // Parse input buffer
    result = ffsParser.parse(buffer);
    if (result)
        return (int)result;

    ffsParser.outputInfo();

    // Create ffsDumper
    FfsDumper ffsDumper(&model);

    // Dump only leaf elements, no report or GUID database
    if (argc == 3 && !std::strcmp(argv[2], "dump")) {
        UString dumpPath = path + UString(".dump");
        makeDirectory(dumpPath);
        std::set<UString> usedNames;
        extractFlatFfsFdOnly(&model, model.index(0, 0), dumpPath, usedNames);
        return 0;
    }
    // Dump named GUIDs found in the image, no dump or report
    else if (argc == 3 && !std::strcmp(argv[2], "guids")) {
        GuidDatabase db = guidDatabaseFromTreeRecursive(&model, model.index(0, 0));
        if (!db.empty()) {
            return (int)guidDatabaseExportToFile(path + UString(".guids.csv"), db);
        }
    }
    // Generate report, no dump or GUID database
    else if (argc == 3 && !std::strcmp(argv[2], "report")) {
        FfsReport ffsReport(&model);
        std::vector<UString> report = ffsReport.generate();
        if (report.size()) {
            std::ofstream file;
            file.open((path + UString(".report.txt")).toLocal8Bit());
            for (size_t i = 0; i < report.size(); i++)
                file << report[i].toLocal8Bit() << '\n';
            return 0;
        }
        return 1;
    }
    // Either default or all mode
    else if (argc == 2 || (argc == 3 && !std::strcmp(argv[2], "all"))) {
        // Generate report
        FfsReport ffsReport(&model);
        std::vector<UString> report = ffsReport.generate();
        if (report.size()) {
            std::ofstream file;
            file.open((path + UString(".report.txt")).toLocal8Bit());
            for (size_t i = 0; i < report.size(); i++)
                file << report[i].toLocal8Bit() << '\n';
        }

        // Create GUID database
        GuidDatabase db = guidDatabaseFromTreeRecursive(&model, model.index(0, 0));
        if (!db.empty()) {
            guidDatabaseExportToFile(path + UString(".guids.csv"), db);
        }

        // Dump all non-leaf elements, with report and GUID database, default
        if (argc == 2) {
            UString dumpPath = path + UString(".dump");
            makeDirectory(dumpPath);
            std::set<UString> usedNames;
            extractFlatFfsFdOnly(&model, model.index(0, 0), dumpPath, usedNames);
            return 0;
        }
        else if (argc == 3 && !std::strcmp(argv[2], "all")) { // Dump every element with report and GUID database
            UString dumpPath = path + UString(".dump");
            makeDirectory(dumpPath);
            std::set<UString> usedNames;
            extractFlatFfsFdOnly(&model, model.index(0, 0), dumpPath, usedNames);
            return 0;
        }
    }
    // Dump specific files, without report or GUID database
    else {
        std::vector<UString> inputs, outputs;
        std::vector<FfsDumper::DumpMode> modes;
        std::vector<UINT8> sectionTypes;
        ReadType readType = READ_INPUT;
        for (int i = 2; i < argc; i++) {
            const char *arg = argv[i];
            if (!std::strcmp(arg, "-i")) {
                readType = READ_INPUT;
                continue;
            } else if (!std::strcmp(arg, "-o")) {
                readType = READ_OUTPUT;
                continue;
            } else if (!std::strcmp(arg, "-m")) {
                readType = READ_MODE;
                continue;
            } else if (!std::strcmp(arg, "-t")) {
                readType = READ_SECTION;
                continue;
            }

            if (readType == READ_INPUT) {
                inputs.push_back(arg);
            } else if (readType == READ_OUTPUT) {
                outputs.push_back(getAbsPath(arg));
            } else if (readType == READ_MODE) {
                if (!std::strcmp(arg, "all"))
                    modes.push_back(FfsDumper::DUMP_ALL);
                else if (!std::strcmp(arg, "body"))
                    modes.push_back(FfsDumper::DUMP_BODY);
                else if (!std::strcmp(arg, "unc_data"))
                    modes.push_back(FfsDumper::DUMP_UNC_DATA);
                else if (!std::strcmp(arg, "header"))
                    modes.push_back(FfsDumper::DUMP_HEADER);
                else if (!std::strcmp(arg, "info"))
                    modes.push_back(FfsDumper::DUMP_INFO);
                else if (!std::strcmp(arg, "file"))
                    modes.push_back(FfsDumper::DUMP_FILE);
                else
                    return U_INVALID_PARAMETER;
            } else if (readType == READ_SECTION) {
                char *converted = const_cast<char *>(arg);
                UINT8 sectionType = (UINT8)std::strtol(arg, &converted, 16);
                if (converted == arg)
                    return U_INVALID_PARAMETER;
                sectionTypes.push_back(sectionType);
            }
        }
        if (inputs.empty() || (!outputs.empty() && inputs.size() != outputs.size()) ||
            (!modes.empty() && inputs.size() != modes.size()) ||
            (!sectionTypes.empty() && inputs.size() != sectionTypes.size()))
            return U_INVALID_PARAMETER;

        USTATUS lastError = U_SUCCESS;
        for (size_t i = 0; i < inputs.size(); i++) {
            UString outPath = outputs.empty() ? path + UString(".dump") : outputs[i];
            FfsDumper::DumpMode mode = modes.empty() ? FfsDumper::DUMP_ALL : modes[i];
            UINT8 type = sectionTypes.empty() ? FfsDumper::IgnoreSectionType : sectionTypes[i];
            result = ffsDumper.dump(model.index(0, 0), outPath, mode, type, inputs[i]);
            if (result) {
                std::cout << "Guid " << inputs[i].toLocal8Bit() << " failed with " << result << " code!" << std::endl;
                lastError = result;
            }
        }

        return (int)lastError;
    }

    // If parameters are different, show version and usage information
    print_usage();
    return 1;
}
