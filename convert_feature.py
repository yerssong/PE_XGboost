# Developed YES

# import peutils
import peutils_using_richheader as peutil
import pefile

def dos_header_convert(dos_list: list, pe_stream):
    dos_flag = list()

    # DosHeader - e_magic
    if dos_list[0] == 23117:
        dos_flag.append(1)
    else:
        dos_flag.append(0)

    # DosHeader - e_ifanew
    check_header = pe_stream[dos_list[1]:dos_list[1] + 2]

    # 0x50400000 == 17744(decimal)
    if check_header == b'PE':
        dos_flag.append(1)
    else:
        dos_flag.append(0)

    return dos_flag

def file_header_convert(file_list: list):
    file_flag = list()
    cpu_architecture = [0x014c, 0x0162, 0x0166, 0x0168, 0x0169, 0x0184, 0x01F0, 0x01a2, 0x01a4,
                        0x01a6, 0x01a8, 0x01c0, 0x01c2, 0x01c4, 0x01d3, 0x01f0, 0x01f1, 0x0200,
                        0x0266, 0x0284, 0x0366, 0x0466, 0x0520]
    character_list = [0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000]

    # NTHeader - Signature
    if file_list[0] == 17744:               # 0x50400000 == 17744(decimal)
        file_flag.append(1)
    else:
        file_flag.append(0)

    if file_list[1] in cpu_architecture:
        file_flag.append(1)
    else:
        file_flag.append(0)

    if file_list[2] == 0:
        file_flag.append(0)
    else:
        file_flag.append(1)

    # timestamp
    file_flag.append(file_list[3])

    # optional header size
    file_flag.append(file_list[4])

    # character_list
    if file_list[5] in character_list:
        file_flag.append(1)
    else:
        file_flag.append(0)

    return file_flag

def optional_header_magic_convert(optional_magic):

    if optional_magic == 267 or optional_magic == 523: # 32bit = 0x10B: 267 / 64bit = 0x20b: 523
        option_flag = 1
    else:
        option_flag = 0

    return option_flag

def rich_header_convert(rich_list: dict):
    try:
        if b'DanS' == rich_list['clear_data'][0:4]:
            richheader = 1
        else:
            richheader = 0

    except:
        richheader = 0

    try:
        if rich_list['checksum'] != 0:
            rich_checksum = 1
        else:
            rich_checksum = 0
    except:
        rich_checksum = 0

    return [richheader, rich_checksum]

def packer_parsing(filepath):
    signatures = peutil.SignatureDatabase('./userdb.txt')

    try:
        pe = pefile.PE(filepath)
        flag = signatures.match_all(pe)

        if flag:
            packer_flag = 1
        else:
            packer_flag = 0
    except:
        packer_flag = 0
        flag = None

    return packer_flag

def extract_pe_features(pe, filepath, filename, pe_stream):

    # add filename
    row = [filename]
    # add DOS_HEADER
    dos_header_feature = dos_header_convert([pe.DOS_HEADER.e_magic, pe.DOS_HEADER.e_lfanew], pe_stream)
    row.extend(dos_header_feature)
    # add NT_HEADERS and FILE_HEADER
    nt_file_header_feature = file_header_convert(
                            [pe.NT_HEADERS.Signature, pe.FILE_HEADER.Machine,
                             pe.FILE_HEADER.NumberOfSections, pe.FILE_HEADER.TimeDateStamp,
                             pe.FILE_HEADER.SizeOfOptionalHeader, pe.FILE_HEADER.Characteristics])
    row.extend(nt_file_header_feature)
    # add OPTIONAL_HEADER
    optional_header_feature = [optional_header_magic_convert(pe.OPTIONAL_HEADER.Magic),
                pe.OPTIONAL_HEADER.AddressOfEntryPoint, pe.OPTIONAL_HEADER.ImageBase,
                pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment,
                pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.Subsystem]
    row.extend(optional_header_feature)

    # add CompareNumberOfSections
    total_section_number = 0
    for section in pe.sections:
        total_section_number += 1
    if pe.FILE_HEADER.NumberOfSections == total_section_number:
        row.extend([1]) #1 is true
    else:
        row.extend([0]) #0 is false

    packer_flag = packer_parsing(filepath + filename)
    row.extend([packer_flag])

    # add Rich Header
    rich_feature = rich_header_convert(pe.parse_rich_header())
    row.extend(rich_feature)

    # add .text features
    text_number = 0
    for section in pe.sections:
        try:
            if section.Name == b".text\x00\x00\x00":
                text_number += 1
                row.extend([section.Misc_VirtualSize, section.SizeOfRawData, section.PointerToRawData,
                            section.Characteristics])
                break
        except AttributeError:
            row.extend(["Error", "Error", "Error", "Error"])
    if text_number == 0:
        row.extend([0, 0, 0, 0])

    # add .data features
    data_number = 0
    for section in pe.sections:
        try:
            if section.Name == b".data\x00\x00\x00":
                data_number += 1
                row.extend([section.Misc_VirtualSize,section.SizeOfRawData, section.PointerToRawData,
                            section.Characteristics])
                break
        except AttributeError:
            row.extend(["Error", "Error", "Error", "Error"])
    if data_number == 0:
        row.extend([0, 0, 0, 0])

    # add .rsrc features
    rsrc_number = 0
    for section in pe.sections:
        try:
            if section.Name == b".rsrc\x00\x00\x00":
                rsrc_number += 1
                row.extend([section.Misc_VirtualSize, section.SizeOfRawData, section.PointerToRawData,
                            section.Characteristics])
                break
        except AttributeError:
            row.extend(["Error", "Error", "Error", "Error"])
    if rsrc_number == 0:
        row.extend([0, 0, 0, 0])

    # add .rdata features
    rdata_number = 0
    for section in pe.sections:
        try:
            if section.Name == b".rdata\x00\x00":
                rdata_number += 1
                row.extend([section.Misc_VirtualSize, section.SizeOfRawData, section.PointerToRawData,
                            section.Characteristics])
                break
        except AttributeError:
            row.extend(["Error", "Error", "Error", "Error"])
    if rdata_number == 0:
        row.extend([0, 0, 0, 0])

    # add .reloc features
    reloc_number = 0
    for section in pe.sections:
        try:
            if section.Name == b".reloc\x00\x00":
                reloc_number += 1
                row.extend([section.Misc_VirtualSize, section.SizeOfRawData, section.PointerToRawData,
                            section.Characteristics])
                break
        except AttributeError:
            row.extend(["Error", "Error", "Error", "Error"])
    if reloc_number == 0:
        row.extend([0, 0, 0, 0])

    return row

