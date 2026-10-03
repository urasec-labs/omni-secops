// Sovereign Security Archive - PE/COFF executable headers
// purpose: triage a binary dropped by a living-off-the-land technique
// source:  Microsoft PE/COFF Specification
// usage:   imhex --pattern pe-executable.hexpat <file>

#pragma endian little

struct DosHeader {
    u16 e_magic;      // 0x5A4D "MZ"
    u16 e_cblp;
    u16 e_cp;
    u16 e_crlc;
    u16 e_cparhdr;
    u16 e_minalloc;
    u16 e_maxalloc;
    u16 e_ss;
    u16 e_sp;
    u16 e_csum;
    u16 e_ip;
    u16 e_cs;
    u16 e_lfarlc;
    u16 e_ovno;
    u16 e_res[4];
    u16 e_oemid;
    u16 e_oeminfo;
    u16 e_res2[10];
    u32 e_lfanew;     // offset to PE signature
};

struct FileHeader {
    u16 machine;
    u16 numberOfSections;
    u32 timeDateStamp;
    u32 pointerToSymbolTable;
    u32 numberOfSymbols;
    u16 sizeOfOptionalHeader;
    u16 characteristics;
};

struct OptionalHeader32 {
    u16 magic;        // 0x10B PE32 / 0x20B PE32+
    u8  majorLinkerVersion;
    u8  minorLinkerVersion;
    u32 sizeOfCode;
    u32 sizeOfInitializedData;
    u32 sizeOfUninitializedData;
    u32 addressOfEntryPoint;
    u32 baseOfCode;
    u32 baseOfData;
    u32 imageBase;
    u32 sectionAlignment;
    u32 fileAlignment;
    u16 majorOperatingSystemVersion;
    u16 minorOperatingSystemVersion;
    u16 majorImageVersion;
    u16 minorImageVersion;
    u16 majorSubsystemVersion;
    u16 minorSubsystemVersion;
    u32 win32VersionValue;
    u32 sizeOfImage;
    u32 sizeOfHeaders;
    u32 checkSum;
    u16 subsystem;
    u16 dllCharacteristics;
    u32 sizeOfStackReserve;
    u32 sizeOfStackCommit;
    u32 sizeOfHeapReserve;
    u32 sizeOfHeapCommit;
    u32 loaderFlags;
    u32 numberOfRvaAndSizes;
};

struct SectionHeader {
    char name[8];
    u32 virtualSize;
    u32 virtualAddress;
    u32 sizeOfRawData;
    u32 pointerToRawData;
    u32 pointerToRelocations;
    u32 pointerToLinenumbers;
    u16 numberOfRelocations;
    u16 numberOfLinenumbers;
    u32 characteristics;
};

struct CoffFile {
    DosHeader       dos       @ 0x00;
    char            pe_sig[4] @ dos.e_lfanew;   // "PE\0\0"
    FileHeader      file      @ $;
    OptionalHeader32 opt      @ $;
    SectionHeader   sections[file.numberOfSections] @ $;
};

CoffFile pe @ 0x00;

// Suspicion helpers (evaluate manually, never auto-report)
bool hasExecSections = false;
for (u32 i = 0, n = pe.file.numberOfSections; i < n; ++i) {
    u32 c = pe.sections[i].characteristics;
    if ((c & 0x20000000) && (c & 0x80000000)) hasExecSections = true; // CODE|EXEC
    if (c & 0x80000000) {}                                            // MEM_EXECUTE
}
