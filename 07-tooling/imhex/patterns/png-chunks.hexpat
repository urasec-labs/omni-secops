// Sovereign Security Archive - PNG chunk structure
// purpose: locate tEXt/iTXt/zTXt chunks used to hide exfiltrated data
// source:  PNG (Portable Network Graphics) Specification, section 5.6
// usage:   imhex --pattern png-chunks.hexpat <file>

#pragma endian little

struct ChunkHeader {
    u32 length;
    char type[4];
};

struct PngChunk {
    ChunkHeader header;
    u8         data[header.length];
    u32        crc;
};

struct PngImage {
    u8   signature[8];      // 89 50 4E 47 0D 0A 1A 0A
    PngChunk chunks[while(!feof())];
};

PngImage png @ 0x00;
