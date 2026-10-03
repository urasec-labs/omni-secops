// Sovereign Security Archive - ZIP central directory
// purpose: detect zip-slip and absolute-path entries during upload analysis
// source:  PKWARE APPNOTE.TXT, section 4.3.16 (central file header)
//
// flag bits (general purpose): 0x0001 encrypted, 0x0008 data descriptor,
// 0x0800 UTF-8 names. Report entries whose name contains "..", a drive letter,
// a leading "/", or a NUL byte.

#pragma endian little

struct Zip64EndOfCentralDirectory {
    u32 signature;       // 0x06064b50
    u64 sizeOfZip64EndOfCentralDirectoryRecord;
    u16 versionMadeBy;
    u16 versionNeededToExtract;
    u32 diskNumber;
    u32 diskWithStartOfCentralDirectory;
    u64 centralDirectoryDiskEntriesOnThisDisk;
    u64 centralDirectoryEntriesOnThisDisk;
    u64 sizeOfCentralDirectory;
    u64 offsetOfStartOfCentralDirectory;
};

struct ZipCentralFileHeader {
    u32 signature;                       // 0x02014b50
    u16 versionMadeBy;
    u16 versionNeeded;
    u16 generalPurposeBitFlag;
    u16 compressionMethod;
    u16 lastModFileTime;
    u16 lastModFileDate;
    u32 crc32;
    u32 compressedSize;
    u32 uncompressedSize;
    u16 fileNameLength;
    u16 extraFieldLength;
    u16 fileCommentLength;
    u16 diskNumberStart;
    u16 internalFileAttributes;
    u32 externalFileAttributes;
    u32 relativeOffsetOfLocalHeader;
    char fileName[fileNameLength];
    u8  extraField[extraFieldLength];
    u8  fileComment[fileCommentLength];
};

Zip64EndOfCentralDirectory eocd @ 0x00;
ZipCentralFileHeader     cdh[while(!feof())] @ eocd.offsetOfStartOfCentralDirectory;

// Tripwires a human reviewer must inspect
//   1. fileName containing "../"            -> zip-slip
//   2. fileName containing ":" or leading / -> absolute path
//   3. externalFileAttributes with unix mode 04755 -> setuid inside archive
//   4. fileName containing a NUL byte       -> truncation / parser confusion
