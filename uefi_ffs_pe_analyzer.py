#!/usr/bin/env python3
"""
UEFI FFS PE Analyzer - SBOM Generator

This utility processes UEFI firmware images, extracts FFS files and embedded PE files,
and generates comprehensive SBOM metadata including version, publisher, description,
and PE version information.

Usage:
    python uefi_ffs_pe_analyzer.py <firmware_file> [--output <output_file>] [--format <text|csv|json>]
"""

import argparse
import json
import csv
import hashlib
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

# Try to import optional dependencies
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("Warning: pefile library not available. Install with: pip install pefile")
    print("PE metadata extraction will be limited.")

try:
    import uefi_firmware
    UEFI_FIRMWARE_AVAILABLE = True
except ImportError:
    UEFI_FIRMWARE_AVAILABLE = False
    print("Warning: uefi_firmware library not available. Install with: pip install uefi-firmware")
    print("UEFI parsing will be limited.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class PEFileInfo:
    """Information extracted from a PE file"""
    version: str = ""
    publisher: str = ""
    description: str = ""
    pe_version: str = ""
    company: str = ""
    copyright: str = ""
    digital_signer: str = ""
    architecture: str = ""
    build_date: str = ""
    sha256_hash: str = ""
    file_size: int = 0
    entry_point: int = 0
    subsystem: str = ""
    machine_type: str = ""

@dataclass
class FFSFileInfo:
    """Information extracted from an FFS file"""
    guid: str = ""
    name: str = ""
    type: str = ""
    subtype: str = ""
    offset: int = 0
    size: int = 0
    version: str = ""
    hash: str = ""
    description: str = ""
    vendor: str = ""
    license: str = ""
    architecture: str = ""
    build_date: str = ""
    security_attributes: str = ""
    compatibility: str = ""
    dependencies: List[str] = None
    contained_pe_files: List[PEFileInfo] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.contained_pe_files is None:
            self.contained_pe_files = []

class UEFIFFSPEAnalyzer:
    """Main analyzer class for UEFI FFS and PE files"""

    def __init__(self):
        self.ffs_files: List[FFSFileInfo] = []
        self.pe_files: List[PEFileInfo] = []

        # UEFI FFS file types
        self.ffs_file_types = {
            0x01: "Raw",
            0x02: "Freeform",
            0x03: "SEC core",
            0x04: "PEI core",
            0x05: "DXE core",
            0x06: "PEI module",
            0x07: "DXE driver",
            0x08: "Combined PEI/DXE",
            0x09: "Application",
            0x0A: "SMM module",
            0x0B: "Volume image",
            0x0C: "Combined SMM/DXE",
            0x0D: "SMM core",
            0x0E: "MM standalone module",
            0x0F: "MM standalone core",
            0xF0: "Pad"
        }

        # UEFI section types
        self.section_types = {
            0x10: "PE32 image",
            0x11: "PIC image",
            0x12: "TE image",
            0x13: "DXE dependency",
            0x14: "Version",
            0x15: "UI",
            0x16: "16-bit image",
            0x17: "Volume image",
            0x18: "Freeform subtype GUID",
            0x19: "Raw",
            0x1B: "PEI dependency",
            0x1C: "MM dependency"
        }

        # PE machine types
        self.machine_types = {
            0x014c: "x86",
            0x8664: "x64",
            0x01c0: "ARM",
            0x01c2: "ARM Thumb",
            0x01c4: "ARMv7 Thumb",
            0x01c6: "Apple ARM",
            0x01f0: "PowerPC",
            0x01f1: "PowerPC FP",
            0x0200: "Itanium",
            0x0ebc: "EFI Byte Code",
            0xaa64: "ARM64",
            0x5032: "RISC-V 32",
            0x5064: "RISC-V 64",
            0x5128: "RISC-V 128",
            0x6232: "LoongArch 32",
            0x6264: "LoongArch 64"
        }

        # PE subsystems
        self.subsystems = {
            0: "Unknown",
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI",
            5: "OS/2 CUI",
            7: "POSIX CUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "SAL Runtime Driver"
        }

    def analyze_firmware(self, firmware_path: str) -> bool:
        """Analyze a UEFI firmware image"""
        try:
            firmware_path = Path(firmware_path)
            if not firmware_path.exists():
                logger.error(f"Firmware file not found: {firmware_path}")
                return False

            logger.info(f"Analyzing firmware: {firmware_path}")

            # Read firmware file
            with open(firmware_path, 'rb') as f:
                firmware_data = f.read()

            # Try different parsing approaches
            if UEFI_FIRMWARE_AVAILABLE:
                return self._analyze_with_uefi_firmware(firmware_data, firmware_path.name)
            else:
                return self._analyze_manual(firmware_data, firmware_path.name)

        except Exception as e:
            logger.error(f"Error analyzing firmware: {e}")
            return False

    def _analyze_with_uefi_firmware(self, firmware_data: bytes, filename: str) -> bool:
        """Analyze using uefi_firmware library"""
        try:
            from uefi_firmware import Firmware

            firmware = Firmware(firmware_data)
            firmware.parse()

            for volume in firmware.volumes:
                logger.info(f"Found volume: {volume.name}")
                for file in volume.files:
                    ffs_info = self._extract_ffs_info(file, volume)
                    if ffs_info:
                        self.ffs_files.append(ffs_info)

            return True

        except Exception as e:
            logger.error(f"Error with uefi_firmware parsing: {e}")
            return False

    def _analyze_manual(self, firmware_data: bytes, filename: str) -> bool:
        """Manual firmware parsing when uefi_firmware is not available"""
        logger.info("Using manual firmware parsing")

        # Look for FFS volumes (simplified approach)
        offset = 0
        while offset < len(firmware_data) - 0x40:
            # Look for FFS volume signature
            if firmware_data[offset:offset+4] == b'_FVH':
                logger.info(f"Found FFS volume at offset 0x{offset:08X}")
                self._parse_ffs_volume(firmware_data, offset, filename)
            offset += 0x1000  # Search in 4KB increments

        return len(self.ffs_files) > 0

    def _parse_ffs_volume(self, data: bytes, offset: int, filename: str):
        """Parse an FFS volume manually"""
        try:
            # This is a simplified FFS volume parser
            # In a real implementation, you'd parse the full FFS volume structure

            # Look for FFS files in the volume
            volume_end = min(offset + 0x1000000, len(data))  # Assume max 16MB volume

            file_offset = offset + 0x200  # Skip volume header
            while file_offset < volume_end - 0x20:
                # Look for FFS file header
                if self._is_ffs_file_header(data, file_offset):
                    ffs_info = self._extract_ffs_file_info(data, file_offset, filename)
                    if ffs_info:
                        self.ffs_files.append(ffs_info)

                file_offset += 0x1000  # Move to next potential file

        except Exception as e:
            logger.error(f"Error parsing FFS volume: {e}")

    def _is_ffs_file_header(self, data: bytes, offset: int) -> bool:
        """Check if data at offset looks like an FFS file header"""
        if offset + 0x20 > len(data):
            return False

        # Check for valid GUID (non-zero)
        guid = data[offset:offset+16]
        return any(b != 0 for b in guid)

    def _extract_ffs_file_info(self, data: bytes, offset: int, filename: str) -> Optional[FFSFileInfo]:
        """Extract FFS file information"""
        try:
            if offset + 0x20 > len(data):
                return None

            # Parse FFS file header (simplified)
            guid_bytes = data[offset:offset+16]
            guid = self._bytes_to_guid(guid_bytes)

            file_type = data[offset+16] if offset+16 < len(data) else 0
            file_type_str = self.ffs_file_types.get(file_type, f"Unknown (0x{file_type:02X})")

            # Estimate file size (this is simplified)
            file_size = 0x1000  # Default assumption

            ffs_info = FFSFileInfo(
                guid=guid,
                name=f"FFS_{guid[:8]}",
                type="FFS File",
                subtype=file_type_str,
                offset=offset,
                size=file_size,
                vendor="Unknown",
                license="Proprietary",
                architecture="Unknown",
                build_date="Unknown",
                security_attributes="Standard",
                compatibility="UEFI 2.x"
            )

            # Try to extract PE files from this FFS file
            self._extract_pe_files_from_ffs(data, offset, ffs_info)

            return ffs_info

        except Exception as e:
            logger.error(f"Error extracting FFS file info: {e}")
            return None

    def _extract_pe_files_from_ffs(self, data: bytes, ffs_offset: int, ffs_info: FFSFileInfo):
        """Extract PE files from an FFS file"""
        try:
            # Look for PE sections in the FFS file body
            body_offset = ffs_offset + 0x20  # Skip FFS header
            body_end = min(ffs_offset + ffs_info.size, len(data))

            offset = body_offset
            while offset < body_end - 0x10:
                # Look for section headers
                if self._is_section_header(data, offset):
                    section_type = data[offset+3] if offset+3 < len(data) else 0

                    if section_type in [0x10, 0x11, 0x12]:  # PE32, PIC, TE
                        pe_info = self._extract_pe_info(data, offset, ffs_info)
                        if pe_info:
                            ffs_info.contained_pe_files.append(pe_info)
                            self.pe_files.append(pe_info)

                offset += 0x100  # Move to next potential section

        except Exception as e:
            logger.error(f"Error extracting PE files from FFS: {e}")

    def _is_section_header(self, data: bytes, offset: int) -> bool:
        """Check if data at offset looks like a section header"""
        if offset + 4 > len(data):
            return False

        # Check for valid section size (non-zero)
        size_bytes = data[offset:offset+3]
        size = struct.unpack('<I', size_bytes + b'\x00')[0]
        return 0 < size < 0x1000000  # Reasonable size range

    def _extract_pe_info(self, data: bytes, offset: int, ffs_info: FFSFileInfo) -> Optional[PEFileInfo]:
        """Extract PE file information"""
        try:
            # Find the PE data (skip section header)
            section_size = struct.unpack('<I', data[offset:offset+3] + b'\x00')[0]
            pe_offset = offset + 4  # Skip section header

            if pe_offset + 0x40 > len(data):
                return None

            pe_data = data[pe_offset:pe_offset+section_size-4]

            if not self._is_pe_file(pe_data):
                return None

            pe_info = PEFileInfo()

            # Extract basic PE information
            self._extract_pe_basic_info(pe_data, pe_info)

            # Extract version resources if available
            if PEFILE_AVAILABLE:
                self._extract_pe_version_info(pe_data, pe_info)

            # Calculate hash
            pe_info.sha256_hash = hashlib.sha256(pe_data).hexdigest()

            return pe_info

        except Exception as e:
            logger.error(f"Error extracting PE info: {e}")
            return None

    def _is_pe_file(self, data: bytes) -> bool:
        """Check if data is a valid PE file"""
        if len(data) < 64:
            return False

        # Check DOS header
        if data[:2] != b'MZ':
            return False

        # Check PE header
        try:
            pe_offset = struct.unpack('<I', data[60:64])[0]
            if pe_offset + 4 > len(data):
                return False

            return data[pe_offset:pe_offset+2] == b'PE'
        except:
            return False

    def _extract_pe_basic_info(self, pe_data: bytes, pe_info: PEFileInfo):
        """Extract basic PE file information"""
        try:
            # Get PE header offset
            pe_offset = struct.unpack('<I', pe_data[60:64])[0]

            # File header
            machine = struct.unpack('<H', pe_data[pe_offset+4:pe_offset+6])[0]
            pe_info.machine_type = self.machine_types.get(machine, f"Unknown (0x{machine:04X})")
            pe_info.architecture = self.machine_types.get(machine, "Unknown")

            # Optional header
            opt_header_offset = pe_offset + 24
            if opt_header_offset + 2 < len(pe_data):
                magic = struct.unpack('<H', pe_data[opt_header_offset:opt_header_offset+2])[0]

                if magic == 0x10b:  # PE32
                    subsystem_offset = opt_header_offset + 68
                elif magic == 0x20b:  # PE32+
                    subsystem_offset = opt_header_offset + 92
                else:
                    return

                if subsystem_offset + 2 < len(pe_data):
                    subsystem = struct.unpack('<H', pe_data[subsystem_offset:subsystem_offset+2])[0]
                    pe_info.subsystem = self.subsystems.get(subsystem, f"Unknown ({subsystem})")

            # File size
            pe_info.file_size = len(pe_data)

        except Exception as e:
            logger.error(f"Error extracting basic PE info: {e}")

    def _extract_pe_version_info(self, pe_data: bytes, pe_info: PEFileInfo):
        """Extract version information from PE file using pefile library"""
        try:
            import pefile

            # Create a temporary file or use BytesIO
            import io
            pe = pefile.PE(data=pe_data)

            # Extract version info
            if hasattr(pe, 'VS_VERSIONINFO'):
                for version_info in pe.VS_VERSIONINFO:
                    if hasattr(version_info, 'StringFileInfo'):
                        for string_file_info in version_info.StringFileInfo:
                            for string_table in string_file_info.StringTable:
                                for entry in string_table.entries.items():
                                    key, value = entry
                                    if key == 'CompanyName':
                                        pe_info.publisher = value.decode('utf-16le', errors='ignore').strip('\x00')
                                    elif key == 'FileDescription':
                                        pe_info.description = value.decode('utf-16le', errors='ignore').strip('\x00')
                                    elif key == 'FileVersion':
                                        pe_info.version = value.decode('utf-16le', errors='ignore').strip('\x00')
                                        pe_info.pe_version = value.decode('utf-16le', errors='ignore').strip('\x00')
                                    elif key == 'LegalCopyright':
                                        pe_info.copyright = value.decode('utf-16le', errors='ignore').strip('\x00')

            pe.close()

        except Exception as e:
            logger.debug(f"Error extracting PE version info: {e}")

    def _bytes_to_guid(self, guid_bytes: bytes) -> str:
        """Convert bytes to GUID string"""
        if len(guid_bytes) != 16:
            return "00000000-0000-0000-0000-000000000000"

        # GUID is stored in little-endian format
        parts = struct.unpack('<IHHBBBBBB', guid_bytes)
        return f"{parts[0]:08X}-{parts[1]:04X}-{parts[2]:04X}-{parts[3]:02X}{parts[4]:02X}-{parts[5]:02X}{parts[6]:02X}{parts[7]:02X}{parts[8]:02X}{parts[9]:02X}"

    def export_text(self, output_file: str):
        """Export analysis results to text file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("UEFI FFS PE Analyzer - SBOM Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total FFS Files: {len(self.ffs_files)}\n")
                f.write(f"Total PE Files: {len(self.pe_files)}\n\n")

                for i, ffs in enumerate(self.ffs_files, 1):
                    f.write(f"FFS File {i}: {ffs.guid}\n")
                    f.write(f"  Component Name: {ffs.name}\n")
                    f.write(f"  GUID: {ffs.guid}\n")
                    f.write(f"  Version: {ffs.version}\n")
                    f.write(f"  Hash: {ffs.hash}\n")
                    f.write(f"  License: {ffs.license}\n")
                    f.write(f"  Type: {ffs.type}\n")
                    f.write(f"  Subtype: {ffs.subtype}\n")
                    f.write(f"  Offset: 0x{ffs.offset:08X}\n")
                    f.write(f"  Size: {ffs.size} bytes\n")
                    f.write(f"  Architecture: {ffs.architecture}\n")
                    f.write(f"  Build Date: {ffs.build_date}\n")
                    f.write(f"  Vendor: {ffs.vendor}\n")
                    f.write(f"  Security Attributes: {ffs.security_attributes}\n")
                    f.write(f"  Compatibility: {ffs.compatibility}\n")
                    f.write(f"  Description: {ffs.description}\n")

                    if ffs.contained_pe_files:
                        f.write(f"  Contained PE Files:\n")
                        for j, pe in enumerate(ffs.contained_pe_files, 1):
                            f.write(f"    PE File {j}: {pe.description or 'Unknown'}\n")
                            f.write(f"      Version: {pe.version}\n")
                            f.write(f"      Publisher: {pe.publisher}\n")
                            f.write(f"      Description: {pe.description}\n")
                            f.write(f"      PE Version: {pe.pe_version}\n")
                            f.write(f"      Company: {pe.company}\n")
                            f.write(f"      Copyright: {pe.copyright}\n")
                            f.write(f"      Digital Signer: {pe.digital_signer}\n")
                            f.write(f"      Architecture: {pe.architecture}\n")
                            f.write(f"      Build Date: {pe.build_date}\n")
                            f.write(f"      SHA-256 Hash: {pe.sha256_hash}\n")
                            f.write(f"      File Size: {pe.file_size} bytes\n")
                            f.write(f"      Subsystem: {pe.subsystem}\n")
                            f.write(f"      Machine Type: {pe.machine_type}\n")

                    f.write("\n")

            logger.info(f"Text report exported to: {output_file}")
            return True

        except Exception as e:
            logger.error(f"Error exporting text report: {e}")
            return False

    def export_csv(self, output_file: str):
        """Export analysis results to CSV file"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write header
                writer.writerow([
                    'FFS_GUID', 'FFS_Name', 'FFS_Type', 'FFS_Subtype', 'FFS_Offset', 'FFS_Size',
                    'FFS_Version', 'FFS_Vendor', 'FFS_Architecture', 'FFS_BuildDate',
                    'PE_Description', 'PE_Version', 'PE_Publisher', 'PE_PEVersion',
                    'PE_Company', 'PE_Copyright', 'PE_Architecture', 'PE_Subsystem',
                    'PE_MachineType', 'PE_FileSize', 'PE_SHA256'
                ])

                # Write data
                for ffs in self.ffs_files:
                    if ffs.contained_pe_files:
                        for pe in ffs.contained_pe_files:
                            writer.writerow([
                                ffs.guid, ffs.name, ffs.type, ffs.subtype, f"0x{ffs.offset:08X}", ffs.size,
                                ffs.version, ffs.vendor, ffs.architecture, ffs.build_date,
                                pe.description, pe.version, pe.publisher, pe.pe_version,
                                pe.company, pe.copyright, pe.architecture, pe.subsystem,
                                pe.machine_type, pe.file_size, pe.sha256_hash
                            ])
                    else:
                        # FFS file without PE files
                        writer.writerow([
                            ffs.guid, ffs.name, ffs.type, ffs.subtype, f"0x{ffs.offset:08X}", ffs.size,
                            ffs.version, ffs.vendor, ffs.architecture, ffs.build_date,
                            '', '', '', '', '', '', '', '', '', '', ''
                        ])

            logger.info(f"CSV report exported to: {output_file}")
            return True

        except Exception as e:
            logger.error(f"Error exporting CSV report: {e}")
            return False

    def export_json(self, output_file: str):
        """Export analysis results to JSON file"""
        try:
            # Convert dataclasses to dictionaries
            ffs_data = []
            for ffs in self.ffs_files:
                ffs_dict = asdict(ffs)
                ffs_dict['contained_pe_files'] = [asdict(pe) for pe in ffs.contained_pe_files]
                ffs_data.append(ffs_dict)

            pe_data = [asdict(pe) for pe in self.pe_files]

            report = {
                'metadata': {
                    'generated': datetime.now().isoformat(),
                    'total_ffs_files': len(self.ffs_files),
                    'total_pe_files': len(self.pe_files),
                    'analyzer_version': '1.0.0'
                },
                'ffs_files': ffs_data,
                'pe_files': pe_data
            }

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            logger.info(f"JSON report exported to: {output_file}")
            return True

        except Exception as e:
            logger.error(f"Error exporting JSON report: {e}")
            return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="UEFI FFS PE Analyzer - Extract SBOM metadata from UEFI firmware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python uefi_ffs_pe_analyzer.py firmware.bin
  python uefi_ffs_pe_analyzer.py firmware.bin --output report.txt --format text
  python uefi_ffs_pe_analyzer.py firmware.bin --output report.csv --format csv
  python uefi_ffs_pe_analyzer.py firmware.bin --output report.json --format json
        """
    )

    parser.add_argument('firmware_file', help='Path to UEFI firmware file')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['text', 'csv', 'json'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check dependencies
    if not PEFILE_AVAILABLE:
        logger.warning("pefile library not available. PE metadata extraction will be limited.")
    if not UEFI_FIRMWARE_AVAILABLE:
        logger.warning("uefi_firmware library not available. UEFI parsing will be limited.")

    # Create analyzer
    analyzer = UEFIFFSPEAnalyzer()

    # Analyze firmware
    if not analyzer.analyze_firmware(args.firmware_file):
        logger.error("Failed to analyze firmware file")
        sys.exit(1)

    # Generate output filename if not provided
    if not args.output:
        base_name = Path(args.firmware_file).stem
        args.output = f"{base_name}_sbom.{args.format}"

    # Export results
    success = False
    if args.format == 'text':
        success = analyzer.export_text(args.output)
    elif args.format == 'csv':
        success = analyzer.export_csv(args.output)
    elif args.format == 'json':
        success = analyzer.export_json(args.output)

    if success:
        logger.info(f"Analysis complete. Results saved to: {args.output}")
        logger.info(f"Found {len(analyzer.ffs_files)} FFS files and {len(analyzer.pe_files)} PE files")
    else:
        logger.error("Failed to export results")
        sys.exit(1)

if __name__ == '__main__':
    main()