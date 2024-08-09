use handshake::primitives::{ContentType, ProtocolVersion, U16};
use handshake::record::OpaqueRecord;
use handshake::traits::Deserializable;

const CLIENT_HELLO_BYTES: [u8; 243] = [
    0x16, 0x03, 0x01, 0x00, 0xEE, 0x01, 0x00, 0x00, 0xEA, 0x03, 0x03, 0x30, 0x3E, 0xB7, 0xF6, 0x6F,
    0xAC, 0x63, 0x01, 0xFE, 0x65, 0x33, 0xB1, 0xB6, 0xCC, 0xBC, 0x63, 0x63, 0x67, 0x46, 0x17, 0x6B,
    0xEC, 0x1A, 0x47, 0x2B, 0xB3, 0x8C, 0xBE, 0xFC, 0x84, 0xAD, 0x11, 0x20, 0x3E, 0x80, 0xEA, 0xAB,
    0x85, 0x9A, 0xD5, 0x3C, 0x6B, 0xFA, 0x3A, 0xB3, 0x41, 0x41, 0x67, 0x41, 0xF1, 0x0C, 0x5F, 0x5F,
    0xCE, 0x12, 0x67, 0x05, 0xD5, 0xF3, 0xB4, 0x91, 0xC3, 0xED, 0x73, 0x06, 0x00, 0x14, 0x13, 0x02,
    0x13, 0x01, 0x13, 0x03, 0xC0, 0x2C, 0xC0, 0x2B, 0xCC, 0xA9, 0xC0, 0x30, 0xC0, 0x2F, 0xCC, 0xA8,
    0x00, 0xFF, 0x01, 0x00, 0x00, 0x8D, 0x00, 0x0D, 0x00, 0x16, 0x00, 0x14, 0x06, 0x03, 0x05, 0x03,
    0x04, 0x03, 0x08, 0x07, 0x08, 0x06, 0x08, 0x05, 0x08, 0x04, 0x06, 0x01, 0x05, 0x01, 0x04, 0x01,
    0x00, 0x0B, 0x00, 0x02, 0x01, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x2D, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20, 0xC9,
    0x95, 0x87, 0x67, 0xE3, 0x8D, 0x0D, 0x6E, 0xF9, 0x5A, 0x71, 0x97, 0xAE, 0xF7, 0x95, 0x23, 0x6A,
    0x0E, 0xB3, 0x4B, 0x30, 0x43, 0x9B, 0x93, 0xBF, 0xAF, 0x25, 0xAB, 0x75, 0xEF, 0x40, 0x10, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x00, 0x00, 0x13,
    0x00, 0x11, 0x00, 0x00, 0x0E, 0x61, 0x70, 0x69, 0x2E, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2E,
    0x63, 0x6F, 0x6D,
];

const SERVER_HELLO_BYTES: [u8; 3481] = [
    0x16, 0x03, 0x03, 0x00, 0x7A, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0x1E, 0x66, 0x21, 0x9C, 0x6B,
    0xE7, 0x03, 0x5E, 0xB7, 0xB0, 0x52, 0x72, 0xFE, 0x17, 0x70, 0x1E, 0x6E, 0x83, 0x57, 0x50, 0xFF,
    0x42, 0xD1, 0x9D, 0xEB, 0xA1, 0x29, 0xEF, 0x43, 0x4E, 0x7C, 0x07, 0x20, 0x3E, 0x80, 0xEA, 0xAB,
    0x85, 0x9A, 0xD5, 0x3C, 0x6B, 0xFA, 0x3A, 0xB3, 0x41, 0x41, 0x67, 0x41, 0xF1, 0x0C, 0x5F, 0x5F,
    0xCE, 0x12, 0x67, 0x05, 0xD5, 0xF3, 0xB4, 0x91, 0xC3, 0xED, 0x73, 0x06, 0x13, 0x01, 0x00, 0x00,
    0x2E, 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20, 0xBE,
    0x6D, 0xF2, 0xDA, 0xCF, 0x0D, 0x2A, 0x45, 0x75, 0xED, 0xEA, 0x27, 0xA7, 0xDE, 0x51, 0x49, 0x8F,
    0xB9, 0x89, 0x17, 0xF0, 0x59, 0x4F, 0xA4, 0x45, 0xB0, 0x98, 0x8B, 0x0B, 0x5F, 0x8E, 0x56, 0x14,
    0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x1B, 0xAB, 0xFF, 0x99, 0xC3, 0xCB, 0xCB,
    0x3F, 0x87, 0xD6, 0x93, 0x70, 0x7E, 0x34, 0xCC, 0xA7, 0x03, 0xEC, 0xEF, 0x0E, 0xA2, 0x78, 0xE7,
    0x47, 0xB3, 0xF6, 0xAF, 0x0E, 0x17, 0x03, 0x03, 0x0C, 0x51, 0xC1, 0x07, 0x9B, 0xB1, 0xE5, 0xE0,
    0x7C, 0xE1, 0x30, 0x1F, 0xAE, 0xA6, 0xB9, 0x33, 0x5E, 0xCC, 0x20, 0xE5, 0xC3, 0x1D, 0xDD, 0xE4,
    0x5D, 0x98, 0xDF, 0x9A, 0xCE, 0xC7, 0x23, 0x49, 0x18, 0x2B, 0x21, 0x75, 0x17, 0x5C, 0xBE, 0xCF,
    0xE5, 0xFC, 0xEA, 0x2E, 0xFC, 0x10, 0x21, 0xD7, 0xCF, 0xC9, 0xD3, 0xB4, 0x3B, 0xEE, 0xF1, 0xF2,
    0xF7, 0x16, 0x8B, 0x1F, 0xDA, 0x63, 0xDD, 0x37, 0x25, 0x02, 0xC3, 0x79, 0x90, 0xF2, 0xC2, 0xCE,
    0x1D, 0x8B, 0xF9, 0xF8, 0x91, 0x25, 0xE2, 0x54, 0x1B, 0xED, 0xEB, 0x8E, 0x91, 0x44, 0x4F, 0x37,
    0xB2, 0x0B, 0x65, 0x65, 0xD8, 0x75, 0xE0, 0xD4, 0xB0, 0xA4, 0x02, 0x7B, 0x3B, 0xBA, 0xBA, 0x6F,
    0xB4, 0x30, 0x24, 0x82, 0xEE, 0x23, 0x5B, 0x22, 0x5D, 0xB7, 0x46, 0x4E, 0xC6, 0x25, 0x4F, 0x83,
    0xED, 0x13, 0x17, 0x1A, 0x9A, 0x76, 0x05, 0xA9, 0xE6, 0x4A, 0xCB, 0x98, 0x41, 0xB4, 0x17, 0x42,
    0xB1, 0xC4, 0x08, 0xA2, 0x5D, 0x45, 0xD5, 0xB3, 0x82, 0xB2, 0x7F, 0xCB, 0x24, 0x94, 0x0A, 0x1E,
    0x77, 0xD5, 0xC0, 0x6B, 0x07, 0x4A, 0x81, 0xB9, 0xF2, 0x4D, 0x5E, 0xDE, 0x29, 0xC1, 0xA4, 0x9B,
    0xF1, 0x6C, 0xEB, 0x08, 0xBF, 0x5B, 0x5F, 0x76, 0xF2, 0x2C, 0xFA, 0x8A, 0xDD, 0x5F, 0x6F, 0x28,
    0x3A, 0x20, 0x9D, 0xA1, 0x57, 0x98, 0xA2, 0x10, 0xBC, 0x5B, 0xDF, 0x78, 0x69, 0xD7, 0x08, 0xEF,
    0xBC, 0xBD, 0x2D, 0xED, 0x61, 0xB9, 0xD2, 0x10, 0x75, 0xFC, 0x17, 0x1B, 0x4B, 0xF4, 0xA9, 0x38,
    0x62, 0xE5, 0x43, 0xC5, 0x14, 0x4F, 0x97, 0x6E, 0xEF, 0x16, 0x0E, 0x7D, 0x3A, 0x9E, 0x08, 0xDB,
    0x6D, 0x26, 0x1C, 0xAA, 0xDF, 0x02, 0xC8, 0x97, 0x92, 0x03, 0x15, 0xB1, 0x34, 0xFC, 0xD4, 0x1A,
    0x9F, 0x7C, 0x5C, 0xC3, 0x03, 0x9D, 0x15, 0x58, 0xDD, 0x05, 0xC8, 0xA2, 0xAC, 0x51, 0xAE, 0x04,
    0xDB, 0x0F, 0xF2, 0x93, 0x72, 0xC7, 0x76, 0x3D, 0xA2, 0xFF, 0x50, 0x8A, 0x04, 0x75, 0xA1, 0x07,
    0x4C, 0x73, 0x74, 0xE1, 0x58, 0x53, 0x91, 0xEF, 0x1C, 0xB0, 0xD5, 0xF4, 0xA0, 0x76, 0x09, 0x3C,
    0xDF, 0x49, 0x7E, 0x98, 0x14, 0xE7, 0x74, 0x02, 0xF6, 0x3A, 0x40, 0x58, 0x46, 0x08, 0x26, 0x5F,
    0x9A, 0x39, 0xA4, 0x03, 0x24, 0xF5, 0xBD, 0x24, 0x71, 0xAE, 0xAE, 0x49, 0x61, 0xB0, 0xC9, 0x94,
    0xFA, 0x36, 0x52, 0x3B, 0x3B, 0xDD, 0x7A, 0x38, 0x59, 0x33, 0x90, 0x08, 0x1F, 0x67, 0xFF, 0xEC,
    0xA2, 0x73, 0x16, 0x2C, 0xEA, 0x83, 0x7F, 0xB4, 0x03, 0x09, 0x10, 0x4E, 0xB2, 0xA2, 0x0B, 0x99,
    0xE9, 0x99, 0x32, 0x0B, 0x6C, 0xFD, 0x3B, 0x18, 0xD3, 0x30, 0x60, 0x98, 0x21, 0x1D, 0x23, 0x4F,
    0x47, 0x89, 0xAF, 0xCB, 0xF5, 0xD2, 0x63, 0x79, 0x8B, 0x66, 0x36, 0xED, 0xAC, 0xD7, 0x17, 0xEA,
    0xAE, 0x95, 0xB6, 0x4E, 0x9B, 0x80, 0x15, 0xFE, 0x28, 0xFB, 0x55, 0xD1, 0x79, 0x11, 0x31, 0xB4,
    0x67, 0xDD, 0x36, 0x83, 0x3A, 0xE4, 0x96, 0xB7, 0xAF, 0x76, 0x43, 0xEB, 0x7A, 0xFF, 0x55, 0x62,
    0xDF, 0xD4, 0xEF, 0x9B, 0x95, 0xCA, 0x2B, 0x14, 0xD4, 0xB6, 0x65, 0xFF, 0x49, 0x08, 0xE9, 0x48,
    0x08, 0xEF, 0x17, 0x72, 0x07, 0x51, 0x6E, 0x04, 0x6D, 0x12, 0x81, 0x99, 0x61, 0xC4, 0x9F, 0xF7,
    0xE9, 0xCA, 0x40, 0x4F, 0x62, 0xCA, 0xC1, 0x64, 0x21, 0x52, 0x85, 0x13, 0x29, 0x37, 0x31, 0x25,
    0x9D, 0x68, 0xB1, 0xF6, 0x4E, 0xA5, 0xB4, 0x51, 0x40, 0x83, 0x6B, 0xDF, 0x50, 0x4D, 0x0C, 0x1A,
    0x79, 0xCF, 0xE5, 0x12, 0x17, 0x89, 0xDF, 0x2A, 0xD2, 0x07, 0x2E, 0x24, 0x21, 0xAB, 0x13, 0x52,
    0x23, 0x14, 0xF9, 0xF5, 0x9B, 0xB7, 0x07, 0x11, 0x52, 0xCB, 0xCD, 0xB0, 0x27, 0x8C, 0xD5, 0x88,
    0x63, 0xE2, 0xDA, 0x83, 0x24, 0xFB, 0xB5, 0xD2, 0x0E, 0xAB, 0x2B, 0xD1, 0x14, 0x25, 0x23, 0xE0,
    0xF6, 0xD4, 0x46, 0x1C, 0xE2, 0x58, 0xE7, 0x76, 0xD2, 0x91, 0x5A, 0xB4, 0x19, 0xA8, 0x6D, 0x7E,
    0x88, 0xCC, 0x3F, 0x85, 0x9A, 0x94, 0x57, 0x5C, 0x80, 0xC8, 0x6C, 0xD1, 0x68, 0x65, 0x3C, 0x7B,
    0xBA, 0xC7, 0x79, 0x8B, 0xE4, 0xCC, 0x14, 0x59, 0xCA, 0x32, 0x59, 0x69, 0x05, 0xF8, 0x9D, 0x9B,
    0xDF, 0x47, 0x6E, 0x80, 0x9B, 0x07, 0xD1, 0xEC, 0xB9, 0xC0, 0xA8, 0xDB, 0xDE, 0x4C, 0xB5, 0x01,
    0xC8, 0x22, 0x0F, 0x3A, 0x27, 0xAB, 0x47, 0xE6, 0x56, 0xB2, 0x99, 0x19, 0x68, 0x80, 0x62, 0x9F,
    0x47, 0x99, 0xD0, 0x98, 0xAE, 0xA9, 0xE0, 0x17, 0x81, 0x2B, 0xB6, 0x59, 0xE8, 0x2A, 0x7F, 0xBC,
    0x47, 0x96, 0xDB, 0x7C, 0x14, 0xE5, 0x5E, 0x99, 0x5F, 0xFD, 0x78, 0xBC, 0x05, 0x10, 0x12, 0xA4,
    0x11, 0x12, 0xA4, 0x86, 0xCF, 0x97, 0x12, 0xC2, 0xA3, 0x49, 0x12, 0x27, 0xD4, 0xAE, 0x60, 0x8E,
    0x5C, 0x21, 0xA4, 0xCA, 0x5B, 0xC0, 0x0E, 0xE3, 0xAA, 0x4F, 0xD2, 0x16, 0x9B, 0xAC, 0x35, 0xD6,
    0xF7, 0x65, 0x5C, 0x18, 0x4F, 0x05, 0xB4, 0x4D, 0xC4, 0x72, 0xC1, 0x55, 0x65, 0xFD, 0xDF, 0x7B,
    0x44, 0xD6, 0xC4, 0xDA, 0xC4, 0xC8, 0xCF, 0xB4, 0xE5, 0xDF, 0xE0, 0xE6, 0x2F, 0xD9, 0xA3, 0x19,
    0xE3, 0xB9, 0x1A, 0xDE, 0x51, 0xE7, 0xEB, 0x52, 0xB6, 0xBF, 0x75, 0x77, 0x4B, 0x86, 0x7C, 0x50,
    0xB4, 0xB1, 0x00, 0x44, 0x40, 0x18, 0xB9, 0x14, 0xDD, 0x7A, 0x96, 0xE0, 0x9B, 0x14, 0x48, 0xB3,
    0x9C, 0x03, 0x54, 0x3B, 0x1F, 0xA5, 0xDA, 0x07, 0x47, 0xFB, 0x27, 0xA7, 0xD6, 0x93, 0xFE, 0x7B,
    0xD9, 0x27, 0xB5, 0x23, 0x9D, 0x43, 0xE1, 0xAF, 0xDD, 0xAC, 0xDC, 0xBA, 0x7F, 0x0E, 0x97, 0xF5,
    0xC0, 0x44, 0x4D, 0x53, 0x74, 0x63, 0xD1, 0x15, 0xD1, 0x9B, 0x0A, 0x4C, 0xD9, 0x5A, 0xAD, 0x98,
    0x6C, 0x76, 0x28, 0xD4, 0x16, 0x6E, 0x51, 0xCF, 0xA0, 0x79, 0xC6, 0x93, 0x62, 0x39, 0x27, 0x88,
    0xDC, 0x3A, 0xDC, 0xDC, 0x2C, 0xD4, 0xDA, 0x74, 0xFD, 0xC7, 0x33, 0x2F, 0x64, 0x90, 0x3C, 0xBD,
    0xC2, 0xA1, 0x3B, 0x66, 0xC8, 0xA3, 0xC4, 0x07, 0xA2, 0x09, 0xF3, 0x3E, 0xAD, 0xE5, 0x57, 0xE0,
    0xE0, 0xD2, 0x35, 0x21, 0xFB, 0xA5, 0x0B, 0x2E, 0x95, 0x99, 0xBE, 0xF6, 0xED, 0x83, 0xC2, 0x26,
    0xC4, 0x0D, 0x5A, 0x01, 0xFA, 0xC5, 0x12, 0x22, 0xA4, 0xA5, 0x75, 0xC5, 0x7B, 0x16, 0x75, 0x3A,
    0x04, 0x25, 0xA6, 0x45, 0x29, 0xAB, 0x41, 0xEF, 0x82, 0xB6, 0x28, 0x59, 0x88, 0x4B, 0x5E, 0xD4,
    0xB9, 0xEA, 0x3D, 0xB0, 0x37, 0x15, 0xA5, 0x0F, 0x58, 0xA4, 0xB2, 0x01, 0x92, 0x94, 0xF2, 0x88,
    0x7A, 0xF3, 0x02, 0xD6, 0x2A, 0x25, 0xAC, 0x88, 0xA0, 0xDC, 0x4E, 0x01, 0x4F, 0x2A, 0xD8, 0xE6,
    0x8F, 0x03, 0x8F, 0xF4, 0xE4, 0xA4, 0xA6, 0x58, 0xCA, 0x14, 0x48, 0x88, 0x9C, 0x63, 0x2C, 0xE0,
    0x66, 0xC1, 0xA9, 0x9F, 0x29, 0x8E, 0x55, 0xB8, 0x9B, 0xEA, 0x49, 0x3D, 0xAC, 0xC8, 0x24, 0xEE,
    0x56, 0x56, 0x2B, 0x98, 0x47, 0xE4, 0x7F, 0x1B, 0x56, 0x1B, 0x97, 0x13, 0x92, 0x80, 0x53, 0x6D,
    0x30, 0x55, 0xD2, 0x17, 0x6C, 0x83, 0x1A, 0x99, 0x62, 0x45, 0x2B, 0x3E, 0xAC, 0x59, 0x74, 0xA4,
    0xC5, 0x41, 0xEB, 0xF5, 0x68, 0x41, 0xF0, 0x2D, 0x9A, 0x40, 0x97, 0x73, 0xD6, 0x0E, 0xDA, 0xE9,
    0x24, 0x4F, 0x48, 0x77, 0x0A, 0x7F, 0x34, 0xAD, 0x3C, 0x64, 0x80, 0x71, 0x39, 0x6D, 0x0C, 0x28,
    0x09, 0xE8, 0x4B, 0xC4, 0x2C, 0x3F, 0x81, 0x78, 0x01, 0xBD, 0x87, 0xEF, 0x0F, 0x16, 0xD0, 0x19,
    0x8A, 0x33, 0xD0, 0xB7, 0x3A, 0xB4, 0x1E, 0x7A, 0xE7, 0xA2, 0x27, 0x49, 0xF4, 0x68, 0x24, 0xEC,
    0xCB, 0x11, 0x23, 0xB5, 0x19, 0x64, 0xC3, 0xA4, 0x24, 0x2D, 0x74, 0xE2, 0xF0, 0x95, 0x75, 0xED,
    0x13, 0xD7, 0x90, 0xC5, 0x0C, 0x0E, 0x89, 0x06, 0xE2, 0x4A, 0x98, 0x96, 0x9F, 0xC7, 0xCD, 0x32,
    0xAA, 0xAB, 0x92, 0xBD, 0xC2, 0xD0, 0xA3, 0xFC, 0x08, 0x98, 0x79, 0xF8, 0x51, 0xB2, 0xC9, 0x64,
    0x8C, 0x94, 0xF2, 0x16, 0x8A, 0xDE, 0xCC, 0xEC, 0xE3, 0x72, 0x4F, 0xF6, 0xCF, 0xA7, 0xFB, 0x47,
    0xDF, 0x0E, 0x63, 0x74, 0xA0, 0x86, 0x2E, 0xA1, 0xB1, 0xF9, 0x0B, 0x2C, 0x5A, 0x5A, 0xB2, 0x0C,
    0xB8, 0x36, 0x51, 0x21, 0xAF, 0x64, 0x53, 0xFA, 0x8C, 0x75, 0x4C, 0x3D, 0xC6, 0xCE, 0x71, 0x47,
    0x2B, 0x91, 0x25, 0x7A, 0xBF, 0x8F, 0xCF, 0x75, 0x7E, 0x03, 0xAA, 0x77, 0x29, 0xAE, 0xA4, 0xB6,
    0x49, 0x7E, 0xB6, 0x69, 0x75, 0x90, 0x98, 0x54, 0xD0, 0x04, 0xDF, 0xCC, 0x0D, 0x74, 0xD2, 0xB2,
    0x02, 0x32, 0x47, 0x1C, 0x47, 0xD5, 0x73, 0x75, 0x46, 0x8C, 0xB2, 0xA1, 0x33, 0x0E, 0x9D, 0x16,
    0x4A, 0x8C, 0x8C, 0x96, 0xC7, 0x74, 0xDD, 0x8B, 0x31, 0xA1, 0xBA, 0x15, 0x68, 0x02, 0xE5, 0xAF,
    0xCF, 0x60, 0x4A, 0x31, 0x67, 0x5E, 0x0B, 0x16, 0xA9, 0x3B, 0xA4, 0x03, 0x6B, 0x5D, 0x1C, 0x38,
    0x49, 0x82, 0x0D, 0x10, 0x3A, 0x52, 0x6F, 0x48, 0x66, 0x76, 0xE1, 0xA7, 0xC8, 0x5E, 0x42, 0x52,
    0x1A, 0x0D, 0x33, 0x95, 0xB3, 0x7C, 0xBE, 0xFB, 0xAC, 0x70, 0x39, 0x2B, 0xDB, 0x34, 0x35, 0xF6,
    0xD0, 0x59, 0x04, 0xE5, 0x8B, 0x19, 0x99, 0x86, 0x4E, 0xF6, 0x66, 0x0B, 0xBB, 0x3F, 0x7C, 0x4B,
    0x12, 0x11, 0x77, 0xB8, 0xE9, 0x48, 0x72, 0x09, 0xF0, 0xFF, 0x62, 0xC6, 0x29, 0xE1, 0xF2, 0x38,
    0x0B, 0x1F, 0xFD, 0xA2, 0x6C, 0xC4, 0x5D, 0xBA, 0x9D, 0x41, 0xB2, 0x96, 0x32, 0x7C, 0x57, 0x46,
    0xAF, 0x72, 0x06, 0x04, 0x3A, 0x19, 0xBD, 0x47, 0x66, 0x77, 0x29, 0x08, 0x42, 0xBF, 0xAA, 0xA7,
    0x4B, 0xDA, 0x75, 0xB0, 0x4E, 0xFF, 0xE3, 0x19, 0x2E, 0x9F, 0xCE, 0x8B, 0xE3, 0xA0, 0x58, 0xA1,
    0xB1, 0x5B, 0x55, 0x3C, 0x6A, 0xDB, 0x05, 0x65, 0xF6, 0x30, 0xC8, 0x2A, 0x7F, 0xE0, 0xDC, 0x09,
    0x1B, 0x90, 0x89, 0xBF, 0x3C, 0xE9, 0xC7, 0x49, 0x48, 0xB4, 0x52, 0x8B, 0xB7, 0x97, 0x6D, 0xB6,
    0x25, 0x34, 0x5E, 0xAF, 0x94, 0xAF, 0x57, 0xA0, 0xD9, 0xF3, 0xEA, 0x26, 0x4E, 0x64, 0x54, 0xB8,
    0x1D, 0x48, 0x43, 0x0B, 0xB0, 0xD0, 0x63, 0xB8, 0x25, 0x51, 0x6D, 0x15, 0x63, 0x1B, 0x5D, 0xE7,
    0x4D, 0xF6, 0x5F, 0x2F, 0x16, 0xA5, 0xA8, 0x82, 0x2E, 0x88, 0x92, 0x6F, 0x0B, 0xF2, 0x34, 0x05,
    0x1D, 0xE7, 0xE1, 0xDA, 0x9F, 0xAE, 0x1C, 0x3D, 0x14, 0x40, 0x5A, 0x7B, 0x3C, 0x5F, 0x87, 0x51,
    0xBB, 0x89, 0x73, 0x4D, 0x3D, 0xF6, 0x07, 0xBD, 0x71, 0xED, 0xE5, 0x15, 0x73, 0x64, 0x3F, 0x73,
    0x2A, 0xA0, 0xA8, 0x9F, 0x35, 0x47, 0x7B, 0x78, 0xD7, 0x48, 0x57, 0xE7, 0xE3, 0x05, 0x1B, 0xE9,
    0xD0, 0x26, 0x09, 0x5F, 0x72, 0xA2, 0x7B, 0x7E, 0x1C, 0xCF, 0x94, 0xA7, 0xC5, 0xE9, 0x1C, 0x57,
    0xA1, 0x0C, 0x13, 0xD6, 0xCE, 0x19, 0x40, 0x7E, 0x0A, 0xC4, 0x63, 0x9C, 0x9A, 0x4A, 0x73, 0x0F,
    0xBD, 0xCB, 0xA9, 0x96, 0xE6, 0x06, 0x43, 0xEC, 0xD0, 0x1C, 0x92, 0xFF, 0x11, 0xFA, 0x03, 0x7C,
    0xB1, 0x38, 0x8E, 0x0C, 0xB8, 0xDE, 0xAE, 0xAB, 0xC1, 0x46, 0xEB, 0xB2, 0x0B, 0x32, 0xDD, 0xAD,
    0x11, 0x11, 0x6F, 0xC3, 0x95, 0x89, 0x17, 0x57, 0x7B, 0xC2, 0x79, 0x3D, 0x90, 0xE5, 0xB4, 0x00,
    0x15, 0x13, 0xE4, 0x21, 0x29, 0x39, 0x41, 0x7D, 0x34, 0x78, 0x66, 0x6C, 0x25, 0x80, 0x1A, 0x9E,
    0x04, 0x30, 0x1A, 0x9B, 0xE5, 0x24, 0x33, 0x74, 0xAE, 0x5A, 0xD3, 0xFD, 0x8F, 0x2D, 0xDA, 0xAA,
    0x93, 0x1D, 0x12, 0x8C, 0x06, 0xC0, 0xDA, 0x42, 0x77, 0xF8, 0xA7, 0xA3, 0xAF, 0x0E, 0xB6, 0x9D,
    0x6E, 0x13, 0x46, 0x30, 0x9E, 0x2B, 0xEB, 0x8F, 0x98, 0x73, 0x6D, 0x9B, 0x2D, 0xEE, 0xB9, 0xAC,
    0xD6, 0x3A, 0x4B, 0xBA, 0x66, 0x0E, 0x37, 0x0F, 0xED, 0xDA, 0xFC, 0x83, 0x31, 0xC1, 0x6B, 0x07,
    0x83, 0xA1, 0x1D, 0x0E, 0x16, 0x33, 0x91, 0x90, 0x94, 0x4B, 0x42, 0xD8, 0xBC, 0x54, 0x3C, 0xA3,
    0xE7, 0x61, 0x59, 0x40, 0x50, 0xD7, 0x15, 0x73, 0x7B, 0xB5, 0x97, 0xE1, 0xAF, 0xD3, 0xB5, 0x9C,
    0x4E, 0x18, 0x38, 0xD8, 0xEA, 0x8B, 0x31, 0x4B, 0x8C, 0x7B, 0x18, 0xE8, 0xCB, 0x4E, 0x5D, 0xD6,
    0xD9, 0xDC, 0x80, 0x8E, 0xA6, 0xF6, 0x74, 0x3C, 0x39, 0xD9, 0x64, 0x1F, 0xDF, 0xE5, 0x25, 0x6D,
    0x1C, 0x9A, 0xAC, 0x50, 0xCB, 0xC7, 0xC2, 0xB3, 0xD9, 0xE5, 0x02, 0x72, 0x71, 0xFC, 0x9F, 0x3D,
    0x05, 0xEF, 0xE1, 0xEE, 0xF4, 0x69, 0xEC, 0x4A, 0xEF, 0x7C, 0xA2, 0x6C, 0xB4, 0x77, 0xB7, 0x50,
    0xAE, 0xA5, 0x63, 0xDA, 0x10, 0xED, 0x8C, 0x9C, 0xA0, 0x79, 0x2F, 0xB9, 0x9D, 0x01, 0xED, 0xD9,
    0x5A, 0xA3, 0x51, 0x60, 0xDC, 0x41, 0xFE, 0x83, 0x32, 0x1D, 0xFB, 0x22, 0x4A, 0x41, 0x0F, 0x01,
    0xDA, 0x89, 0x56, 0xCE, 0xB3, 0x4D, 0xA5, 0x8E, 0x65, 0xDF, 0xBE, 0xA7, 0x98, 0x17, 0xAF, 0xAE,
    0x72, 0x01, 0xC7, 0xAC, 0x6B, 0xF2, 0xD6, 0x48, 0x94, 0x60, 0xC1, 0xD1, 0xEE, 0xE1, 0xED, 0x2F,
    0x6C, 0xBA, 0x9E, 0xDE, 0x97, 0xEF, 0x6F, 0xFE, 0x36, 0xBC, 0xF8, 0x3B, 0x06, 0x9A, 0xC9, 0x6A,
    0x00, 0x54, 0x7A, 0xED, 0x60, 0xF8, 0xC8, 0xEB, 0xB1, 0x5E, 0xF0, 0x38, 0x92, 0x7D, 0xE9, 0x41,
    0xCA, 0x3E, 0xF9, 0x1A, 0x26, 0x02, 0xA3, 0x93, 0x12, 0x27, 0x65, 0xEA, 0xB7, 0xBC, 0x2F, 0x20,
    0x68, 0x89, 0xD2, 0x54, 0x54, 0x05, 0xB3, 0xC0, 0x8C, 0xCE, 0x3E, 0x39, 0xC6, 0x29, 0xB7, 0x48,
    0x9E, 0x43, 0xD2, 0x76, 0x90, 0xC9, 0x1B, 0xCA, 0x03, 0x7B, 0x46, 0x3F, 0xC3, 0xAC, 0x57, 0x06,
    0xB8, 0x9D, 0xE2, 0x2A, 0x4F, 0xD2, 0x24, 0xCE, 0xF5, 0x88, 0xAA, 0x27, 0xBF, 0x02, 0x2C, 0xCA,
    0x3E, 0x98, 0x8D, 0x59, 0x35, 0xBF, 0x11, 0x3C, 0x8C, 0x52, 0x6D, 0x96, 0x10, 0xC1, 0xF8, 0x14,
    0xCB, 0xD0, 0xDF, 0x75, 0x71, 0x14, 0x8B, 0x48, 0x74, 0xC8, 0x85, 0x8B, 0x8D, 0x43, 0x3F, 0x73,
    0x90, 0x61, 0x26, 0x0E, 0x20, 0xFA, 0xCE, 0x69, 0x2D, 0x29, 0x36, 0x11, 0xFE, 0x4D, 0xCD, 0xA2,
    0x6D, 0x50, 0x68, 0x3C, 0x63, 0x53, 0xC3, 0x48, 0x2B, 0x89, 0xFD, 0x05, 0x50, 0x2A, 0x80, 0x41,
    0xD4, 0xDE, 0xFE, 0xC7, 0xFB, 0x91, 0xC5, 0xB9, 0x78, 0xDC, 0xBE, 0xF9, 0x97, 0xC0, 0x0B, 0x3F,
    0x3B, 0xF3, 0x68, 0xCB, 0x9E, 0x24, 0xB8, 0x29, 0x13, 0xA3, 0x05, 0x2C, 0x39, 0x6F, 0xAE, 0x77,
    0x02, 0xEA, 0xA2, 0x96, 0x2A, 0xD3, 0xEE, 0xF2, 0xFF, 0x44, 0xB7, 0x32, 0xA8, 0x1B, 0xA5, 0x09,
    0x26, 0xF8, 0x65, 0x7F, 0x20, 0x17, 0x4C, 0x3F, 0x47, 0x95, 0x3A, 0x7C, 0x7C, 0x98, 0x11, 0xAF,
    0xA8, 0x12, 0x9C, 0xC3, 0x89, 0x90, 0x64, 0x38, 0xAE, 0x2E, 0x67, 0x41, 0xC4, 0x7D, 0x66, 0x50,
    0x12, 0x9D, 0x1E, 0xB5, 0xF2, 0xC0, 0xC8, 0x1B, 0xAB, 0x90, 0x8B, 0xF4, 0x2E, 0x07, 0x96, 0x6E,
    0x38, 0x23, 0x2A, 0x66, 0xD0, 0x83, 0xBD, 0x3E, 0x4E, 0x53, 0x63, 0x4D, 0x98, 0x8D, 0x1B, 0x7E,
    0x74, 0x3D, 0x05, 0xCA, 0x29, 0x90, 0xB2, 0x50, 0x3A, 0x6D, 0xF4, 0x95, 0xAD, 0x26, 0xEA, 0xE0,
    0xCE, 0xD5, 0xD1, 0xA3, 0x7D, 0x2E, 0xC1, 0xAE, 0xC6, 0x81, 0x1A, 0x61, 0xE6, 0x91, 0x60, 0x3E,
    0x60, 0x48, 0x02, 0xDE, 0xF3, 0x93, 0xD9, 0xF6, 0xC9, 0x3B, 0xEE, 0x98, 0x9F, 0xAB, 0x82, 0xCC,
    0xE8, 0xE5, 0x78, 0xEB, 0xBA, 0x89, 0xA7, 0x18, 0xF4, 0xD5, 0x95, 0xE5, 0xE9, 0x90, 0x91, 0x29,
    0xBE, 0x31, 0xC0, 0x0C, 0xFF, 0xB7, 0xDB, 0xB3, 0xAB, 0xA3, 0xF3, 0x5D, 0x5F, 0x43, 0x06, 0xB2,
    0x5C, 0xD4, 0x1B, 0xBB, 0x4D, 0x74, 0x50, 0x1D, 0xB0, 0x8D, 0x66, 0x29, 0x9B, 0xF3, 0xEB, 0x6F,
    0xA4, 0x9A, 0x57, 0x7C, 0x99, 0x1E, 0xFC, 0x4D, 0xE0, 0x84, 0xC0, 0xE4, 0xBB, 0x5D, 0xE7, 0x79,
    0xB8, 0xF1, 0xB4, 0xB5, 0x01, 0x60, 0x39, 0x4F, 0x27, 0x61, 0xFE, 0x99, 0x63, 0x90, 0x9E, 0x55,
    0xFA, 0xBF, 0x12, 0x7E, 0x47, 0xFE, 0xD3, 0x0D, 0x29, 0x94, 0x93, 0x4E, 0xD2, 0xBC, 0xC8, 0xB7,
    0xBC, 0x88, 0xD6, 0xFA, 0xCD, 0x2F, 0xF3, 0x16, 0x49, 0x95, 0xB7, 0x1C, 0x7A, 0x59, 0x65, 0x6F,
    0xD1, 0x02, 0xE1, 0x65, 0x83, 0xC8, 0xDB, 0x5B, 0xEC, 0x0C, 0x5C, 0x30, 0x4D, 0x39, 0xFB, 0x29,
    0x1A, 0x6B, 0xF2, 0xA7, 0xDA, 0xD9, 0x2C, 0x5D, 0x7D, 0x06, 0x5F, 0xF5, 0x20, 0x21, 0x2B, 0x95,
    0x73, 0x03, 0xF6, 0xFB, 0xE9, 0x3F, 0x9C, 0x41, 0x87, 0x8F, 0x16, 0x95, 0x1E, 0x6D, 0xC4, 0x3A,
    0x42, 0x30, 0xF5, 0x4D, 0xE9, 0x4D, 0x66, 0xA5, 0x12, 0x08, 0x68, 0x6E, 0x43, 0xCC, 0x4B, 0x2F,
    0x8C, 0x0D, 0xDC, 0x98, 0x27, 0x34, 0x8E, 0x19, 0xCA, 0x51, 0x4C, 0x20, 0xD3, 0xDC, 0x23, 0x1E,
    0x9C, 0xF9, 0xAB, 0xC3, 0x68, 0x92, 0x62, 0xB8, 0x79, 0xF9, 0x46, 0x35, 0xDF, 0xEE, 0x5E, 0x90,
    0x3C, 0x99, 0x27, 0xE7, 0xE2, 0xCB, 0xF9, 0xB8, 0xA9, 0xE8, 0xFA, 0xFE, 0xA5, 0x4B, 0x90, 0x33,
    0x2B, 0x21, 0x49, 0x29, 0xF6, 0x3A, 0xCC, 0x47, 0x94, 0xE2, 0xB5, 0x68, 0xAE, 0x0D, 0x98, 0xD4,
    0x19, 0xC8, 0x8A, 0x81, 0xBA, 0x50, 0x19, 0xA3, 0xF9, 0x65, 0xB6, 0x44, 0x9D, 0x54, 0x8D, 0x91,
    0xA7, 0x30, 0xA4, 0x47, 0xFF, 0x48, 0x55, 0xB1, 0xAF, 0xF6, 0xFB, 0x12, 0xEB, 0xFF, 0xCD, 0x98,
    0x49, 0x75, 0xA6, 0x1B, 0xF1, 0xFA, 0x6C, 0x4B, 0x93, 0xE2, 0x92, 0xB3, 0x21, 0x13, 0x3C, 0x2F,
    0x15, 0xBE, 0x0A, 0xBF, 0xE1, 0xC6, 0x73, 0x4A, 0xE7, 0x66, 0x38, 0x7C, 0xC4, 0xC0, 0x4B, 0x2F,
    0xB9, 0x4B, 0x27, 0xED, 0x85, 0x8C, 0x17, 0x3F, 0x97, 0x6A, 0xEE, 0x8A, 0x56, 0x81, 0x1C, 0x09,
    0x6C, 0x89, 0x4D, 0x01, 0xC7, 0x92, 0x0A, 0x9B, 0x2E, 0xC8, 0x20, 0x6C, 0x81, 0x8D, 0x27, 0x7B,
    0x5A, 0x59, 0xB4, 0xF1, 0xEA, 0xCA, 0x0B, 0xB0, 0xBB, 0x07, 0xE7, 0x2B, 0x80, 0x2B, 0xF1, 0x70,
    0xB0, 0xD0, 0xF6, 0x8C, 0x88, 0xD8, 0xE6, 0x2A, 0xC2, 0xF7, 0xCC, 0x2B, 0x9D, 0x47, 0xC1, 0xC2,
    0xA9, 0x94, 0xB9, 0xF1, 0x3C, 0xE6, 0xFA, 0x62, 0x5B, 0xCE, 0x16, 0xD8, 0xDC, 0xFE, 0xEA, 0xF4,
    0x28, 0xE3, 0xE5, 0x38, 0x16, 0x54, 0x19, 0x00, 0x28, 0x43, 0xEA, 0xA7, 0xAD, 0x60, 0xEF, 0x7F,
    0xEA, 0x28, 0xF0, 0x91, 0xD6, 0xDD, 0x7E, 0x7A, 0x0D, 0x6D, 0x9F, 0x3F, 0x61, 0xC6, 0xE4, 0x7B,
    0x8C, 0x80, 0xBC, 0xE1, 0x2A, 0x53, 0x9C, 0xFA, 0xB2, 0xA6, 0x3C, 0xB2, 0xDE, 0x55, 0xE6, 0x8D,
    0x60, 0x33, 0x66, 0xF6, 0xE5, 0xC6, 0x23, 0x11, 0xF4, 0x34, 0x3C, 0x6D, 0x48, 0x80, 0xDB, 0x2B,
    0xDA, 0xCA, 0x94, 0x99, 0xFD, 0x4F, 0x73, 0x91, 0xD1, 0xD2, 0x98, 0x4B, 0xA7, 0x17, 0xC9, 0x19,
    0xB0, 0xF2, 0xC0, 0xB1, 0x7F, 0x51, 0xF4, 0x1D, 0xC8, 0x51, 0x85, 0xB8, 0x3F, 0x4A, 0x86, 0x53,
    0xC0, 0x0F, 0x2A, 0xF0, 0xF5, 0x88, 0xCA, 0xD2, 0x36, 0x7C, 0x39, 0xD5, 0x4B, 0xEF, 0xC1, 0xC8,
    0x91, 0x13, 0x8D, 0x63, 0x8E, 0x60, 0x6B, 0x13, 0x7B, 0xBB, 0x0A, 0x28, 0xB0, 0x51, 0x7F, 0xE0,
    0x0E, 0x67, 0x10, 0x8E, 0x8B, 0x5A, 0xAF, 0x13, 0xAE, 0xCC, 0xE1, 0x05, 0x29, 0xD0, 0xC2, 0xDF,
    0xC4, 0xD9, 0x3D, 0x9E, 0x49, 0x85, 0x52, 0x3B, 0xFD, 0x4D, 0x92, 0x51, 0x99, 0xC2, 0xDA, 0x58,
    0x62, 0xEB, 0xAC, 0x4A, 0x0B, 0x0F, 0x7D, 0x96, 0x8A, 0x45, 0xCC, 0xFE, 0x27, 0x92, 0x81, 0x0C,
    0x24, 0x7C, 0x96, 0xBD, 0xC5, 0xA4, 0x6A, 0xFF, 0x5D, 0xEF, 0x6D, 0x25, 0xB9, 0x8D, 0x40, 0x79,
    0x9D, 0xF3, 0xC2, 0xB3, 0x47, 0xF2, 0x2E, 0xC8, 0x0B, 0x7C, 0xA5, 0xBC, 0x3B, 0x9D, 0xF5, 0xF6,
    0x48, 0x92, 0x25, 0x6E, 0x4B, 0x4B, 0x62, 0x96, 0xDA, 0x4C, 0xDD, 0x97, 0x3D, 0x68, 0x4A, 0x91,
    0x62, 0x40, 0x12, 0x3F, 0x76, 0x1C, 0xE2, 0x2B, 0x8F, 0xC6, 0x18, 0x67, 0x7C, 0x9B, 0xAA, 0xDD,
    0xDA, 0xF4, 0x15, 0xFA, 0xB6, 0x46, 0x06, 0x6B, 0xC2, 0xE7, 0x0C, 0x0F, 0x88, 0xB5, 0xB8, 0x81,
    0x52, 0xD9, 0x88, 0x43, 0x8C, 0xFA, 0x45, 0x07, 0x44, 0x76, 0x06, 0xD3, 0x5B, 0xE6, 0x84, 0x0D,
    0x01, 0xA2, 0x7C, 0xBC, 0xAB, 0xFC, 0x7D, 0x06, 0xC9, 0x88, 0x11, 0x32, 0x98, 0x8F, 0xC7, 0xED,
    0x57, 0x59, 0x6A, 0xDD, 0x9A, 0x79, 0x79, 0x26, 0xFC, 0x1E, 0x50, 0x15, 0x13, 0xEE, 0x10, 0x23,
    0xBA, 0x02, 0x03, 0x95, 0x94, 0xB8, 0xD6, 0xF0, 0xCF, 0xA5, 0x74, 0x0F, 0xED, 0x77, 0x04, 0xDE,
    0x73, 0xA7, 0xD1, 0x3D, 0x04, 0xE5, 0xBC, 0xE0, 0x63, 0x3B, 0x50, 0x17, 0x08, 0x3D, 0x66, 0x35,
    0x1D, 0x69, 0x28, 0xA8, 0x5B, 0xF2, 0x37, 0xD6, 0x3D, 0x1F, 0x54, 0x0E, 0xA4, 0x70, 0x5D, 0x91,
    0x9F, 0x3C, 0x20, 0x8D, 0x13, 0xA6, 0xB5, 0x57, 0x88, 0x92, 0x66, 0xB3, 0x63, 0xE0, 0x84, 0xDC,
    0xB3, 0x6B, 0x35, 0xF1, 0xF9, 0x71, 0xC9, 0xB1, 0xF6, 0x0A, 0x75, 0x61, 0x92, 0x37, 0x95, 0xD9,
    0x1B, 0xF2, 0x6E, 0x60, 0xF3, 0x87, 0xD8, 0x08, 0x49, 0x6B, 0x3D, 0x26, 0x53, 0xCE, 0xF5, 0x04,
    0x62, 0x97, 0x5A, 0xAA, 0x7C, 0x62, 0xF8, 0xD2, 0xE8, 0x93, 0x7E, 0xD4, 0xFA, 0x97, 0x1F, 0xB1,
    0xD3, 0xA7, 0x9C, 0xEA, 0xFB, 0x3E, 0x01, 0x77, 0x47, 0xC3, 0xB6, 0x1C, 0x67, 0xF8, 0x52, 0xD7,
    0x21, 0xC8, 0x12, 0x67, 0xF2, 0xAC, 0x15, 0x95, 0x74, 0x4B, 0x93, 0x15, 0xE7, 0x3F, 0x0D, 0x38,
    0x3A, 0xCB, 0xBA, 0x0E, 0xC9, 0xCD, 0x13, 0x7F, 0x06, 0x3E, 0x82, 0xE6, 0xB1, 0x76, 0x3C, 0xA8,
    0xE2, 0xED, 0x30, 0x2A, 0xFA, 0xB6, 0x53, 0xA1, 0xBA, 0x4C, 0xDB, 0x87, 0x0F, 0x54, 0x5A, 0x39,
    0x11, 0xCA, 0x30, 0x32, 0x59, 0x9D, 0x72, 0x39, 0xE1, 0xB2, 0x68, 0x7A, 0x31, 0xB1, 0x46, 0x3D,
    0x5E, 0xE5, 0x67, 0x68, 0x9D, 0x4A, 0x0D, 0x12, 0x30, 0x72, 0xB5, 0x93, 0x37, 0x0E, 0xDB, 0x30,
    0x2E, 0x5A, 0xA9, 0x3E, 0x03, 0xA1, 0xFA, 0x09, 0x66, 0xEE, 0x8E, 0xA4, 0x07, 0x38, 0xC4, 0x7D,
    0x6F, 0xFC, 0x93, 0xAE, 0xCF, 0x8D, 0x73, 0x09, 0xC5, 0x8B, 0xF8, 0xDD, 0x37, 0xC0, 0xEA, 0x69,
    0x66, 0xF7, 0xF5, 0x41, 0x9A, 0x21, 0x5E, 0x85, 0xBE, 0x3C, 0xD4, 0x23, 0xAB, 0xBC, 0xF2, 0x28,
    0x8F, 0xEC, 0xA5, 0x20, 0x31, 0xE2, 0xE8, 0x3A, 0xBE, 0x7D, 0xC3, 0x1C, 0xD0, 0xF6, 0x84, 0x76,
    0xA8, 0x70, 0xFE, 0xA0, 0xB1, 0xCC, 0xC1, 0x07, 0x08, 0x6B, 0x63, 0x55, 0x1A, 0x15, 0x5A, 0x40,
    0x3F, 0x39, 0xAF, 0xF9, 0xEB, 0x8F, 0xFC, 0x89, 0x55, 0x0B, 0xAA, 0xBF, 0x9C, 0x0F, 0xE7, 0xD5,
    0xE6, 0x62, 0x80, 0xE7, 0x97, 0x57, 0x93, 0x43, 0xED, 0x5D, 0x33, 0x8C, 0xED, 0xCB, 0x38, 0xB5,
    0xAC, 0xB6, 0xA4, 0xD0, 0xF0, 0x20, 0x85, 0x32, 0x88, 0x46, 0x2E, 0x73, 0x3F, 0xF8, 0x13, 0xE0,
    0x8F, 0x88, 0xE5, 0x32, 0x9C, 0xC5, 0xAE, 0x15, 0x71, 0xE3, 0x2C, 0x29, 0x2C, 0x87, 0xF2, 0xAB,
    0x15, 0x10, 0x7A, 0xD6, 0xE6, 0xA9, 0x45, 0xD1, 0x77, 0xEE, 0x56, 0x17, 0x03, 0x03, 0x00, 0x5F,
    0xE4, 0x3B, 0xD8, 0xBF, 0xC0, 0x5A, 0x0A, 0xAF, 0xD0, 0xE9, 0xC9, 0x2B, 0xD8, 0xE9, 0xED, 0x57,
    0x10, 0xEA, 0x92, 0x16, 0x14, 0xDB, 0xC6, 0x01, 0xB3, 0x03, 0xB5, 0x7B, 0xCE, 0xB4, 0xCB, 0xF7,
    0x0B, 0xD3, 0xAB, 0x8F, 0x63, 0x7C, 0x93, 0xF5, 0x18, 0x0C, 0x2E, 0xB4, 0xCA, 0x3D, 0x3D, 0x45,
    0x4E, 0xBE, 0x40, 0xD5, 0xA6, 0xC9, 0xCB, 0x4D, 0xC7, 0x68, 0xEC, 0x21, 0xE2, 0xBD, 0xFF, 0x80,
    0x87, 0x39, 0x04, 0xD2, 0x04, 0x8A, 0x1E, 0x3B, 0xCB, 0x91, 0x08, 0x03, 0x43, 0x7A, 0xA8, 0x86,
    0xBD, 0xFA, 0x9E, 0xB4, 0x64, 0xF6, 0xAD, 0x78, 0x3D, 0x0B, 0x24, 0xA2, 0x76, 0x97, 0xBE, 0x17,
    0x03, 0x03, 0x00, 0x35, 0x4D, 0x54, 0x7E, 0x05, 0xF2, 0xBD, 0xD1, 0xE5, 0x12, 0xF3, 0x98, 0xF1,
    0xD1, 0xE8, 0x44, 0xC7, 0x95, 0x5C, 0x69, 0xF9, 0xE5, 0x5E, 0xD3, 0x11, 0xB8, 0xC2, 0x66, 0xD7,
    0x33, 0x3C, 0x4F, 0x35, 0x37, 0xFB, 0x4D, 0x51, 0x42, 0x81, 0x86, 0x9F, 0x8C, 0x35, 0xFC, 0xE5,
    0xA8, 0x7D, 0x6D, 0x8C, 0x72, 0xF4, 0x5A, 0x38, 0xCB,
];

fn main() {
    let record = OpaqueRecord {
        content_type: ContentType::Handshake,
        legacy_record_version: ProtocolVersion::Tls_1_3,
        length: U16(5),
        fragment: [0u8; 5].to_vec(),
    };
    println!("{record}");

    let (record, _) = OpaqueRecord::deserialize(&CLIENT_HELLO_BYTES).unwrap();
    println!("{record}");
    let (record, _) = OpaqueRecord::deserialize(&SERVER_HELLO_BYTES).unwrap();
    println!("{record}");
}