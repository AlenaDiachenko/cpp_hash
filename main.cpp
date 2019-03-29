#include <iostream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <cctype>
#include <fstream>

extern "C" {
    #include "hash/md6/md6.h"
    #include "hash/sha3/sha3.h"
    #include "hash/crc/crc32.h"
    #include "hash/blake/blake.h"
    #include "hash/murmur/murmurhash3_32.h"
}
#include "hash/cityHash/city.h"

#define MD6_LEN_BIT 512
#define SHA3_LEN_BIT 512
#define CRC_LEN_BIT 32
#define CITY_LEN_BIT 64
#define BLAKE_LEN_BIT 512
#define MURMUR_LEN_BIT 32

void printByteSequenceHex(std::vector<uint8_t>& sequence)
{
    std::cout << std::hex;
    for (uint8_t byte : sequence) {
        std::cout << static_cast<uint32_t>(byte) << " ";
    }
    std::cout << std::dec;
}

std::chrono::nanoseconds check_md6(std::vector<uint8_t >& data, std::vector<uint8_t >& hash){
    hash.clear();
    hash.resize(MD6_LEN_BIT / 8);
    auto start = std::chrono::high_resolution_clock::now();
    md6_hash(MD6_LEN_BIT, data.data(), data.size() * 8, hash.data());
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
}

std::chrono::nanoseconds check_sha3(std::vector<uint8_t >& data, std::vector<uint8_t >& hash){
    hash.clear();
    hash.resize(SHA3_LEN_BIT / 8);
    sha3_context c;
    auto start = std::chrono::high_resolution_clock::now();
    sha3_Init512(&c);
    sha3_Update(&c, reinterpret_cast<void*>(data.data()), data.size());
    const auto *hashPtr = reinterpret_cast<const uint8_t *>(sha3_Finalize(&c));
    auto end = std::chrono::high_resolution_clock::now();
    hash.assign(hashPtr, hashPtr + SHA3_LEN_BIT / 8);
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
}

std::chrono::nanoseconds check_crc(std::vector<uint8_t >& data, std::vector<uint8_t >& hash){
    hash.clear();
    hash.resize(CRC_LEN_BIT / 8);
    auto start = std::chrono::high_resolution_clock::now();
    uint32_t hashValue = crc32(0, reinterpret_cast<void*>(data.data()), data.size());
    auto end = std::chrono::high_resolution_clock::now();
    hash.assign(reinterpret_cast<uint8_t *>(&hashValue), reinterpret_cast<uint8_t *>(&hashValue) + CRC_LEN_BIT / 8);
    std::reverse(hash.begin(), hash.end());
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
}

std::chrono::nanoseconds check_city(std::vector<uint8_t >& data, std::vector<uint8_t >& hash){
    hash.clear();
    hash.resize(CITY_LEN_BIT / 8);
    auto start = std::chrono::high_resolution_clock::now();
    uint64_t hashValue = CityHash32(reinterpret_cast<const char*>(data.data()), data.size());
    auto end = std::chrono::high_resolution_clock::now();
    hash.assign(reinterpret_cast<uint8_t *>(&hashValue), reinterpret_cast<uint8_t *>(&hashValue) + CITY_LEN_BIT / 8);
    std::reverse(hash.begin(), hash.end());
    return std::chrono::duration_cast<std::chrono::nanoseconds >(end - start);
}

std::chrono::nanoseconds check_blake(std::vector<uint8_t >& data, std::vector<uint8_t >& hash){
    hash.clear();
    hash.resize(BLAKE_LEN_BIT / 8);
    auto start = std::chrono::high_resolution_clock::now();
    blake512_hash(hash.data(), data.data(), data.size());
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
}

std::chrono::nanoseconds check_murmur(std::vector<uint8_t >& data, std::vector<uint8_t >& hash){
    hash.clear();
    hash.resize(MURMUR_LEN_BIT / 8);
    auto start = std::chrono::high_resolution_clock::now();
    uint32_t hashValue = murmur3_32(reinterpret_cast<const char*>(data.data()), data.size(), 0);
    auto end = std::chrono::high_resolution_clock::now();
    hash.assign(reinterpret_cast<uint8_t *>(&hashValue), reinterpret_cast<uint8_t *>(&hashValue) + MURMUR_LEN_BIT / 8);
    std::reverse(hash.begin(), hash.end());
    return std::chrono::duration_cast<std::chrono::nanoseconds >(end - start);
}

int main() {
    std::string dataStr = "QWERQWERQWERQWERQWER";

    std::ifstream file("E:\\cpp_conf\\book.txt");
    std::string bigData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    std::cout << bigData.size() << std::endl;

    std::vector<uint8_t> data(dataStr.begin(), dataStr.end());
    std::vector<uint8_t> hashMD6;
    std::vector<uint8_t> hashSHA3;
    std::vector<uint8_t> hashCRC;
    std::vector<uint8_t> hashCITY;
    std::vector<uint8_t> hashBLAKE;
    std::vector<uint8_t> hashMURMUR;

    std::cout << std::endl << std::endl;

    auto timeMD6 = check_md6(data,hashMD6);
    auto timeSHA3 = check_sha3(data,hashSHA3);
    auto timeCRC = check_crc(data,hashCRC);
    auto timeCITY = check_city(data,hashCITY);
    auto timeBLAKE = check_blake(data,hashBLAKE);
    auto timeMURMUR = check_murmur(data,hashMURMUR);

    std::cout << "MD6: ";
    printByteSequenceHex(hashMD6);
    std::cout << std::endl;
    std::cout << "SHA3: ";
    printByteSequenceHex(hashSHA3);
    std::cout << std::endl;
    std::cout << "CRC: ";
    printByteSequenceHex(hashCRC);
    std::cout << std::endl;
    std::cout << "CITY: ";
    printByteSequenceHex(hashCITY);
    std::cout << std::endl;
    std::cout << "BLAKE: ";
    printByteSequenceHex(hashBLAKE);
    std::cout << std::endl;
    std::cout << "MURMUR: ";
    printByteSequenceHex(hashMURMUR);
    std::cout << std::endl;

    std::cout << "MD6 time = " << timeMD6.count() << " mks." << std::endl;
    std::cout << "SHA3 time = " << timeSHA3.count() << " mks." << std::endl;
    std::cout << "CRC time = " << timeCRC.count() << " mks." << std::endl;
    std::cout << "CITY time = " << timeCITY.count() << " mks." << std::endl;
    std::cout << "BLAKE time = " << timeBLAKE.count() << " mks." << std::endl;
    std::cout << "MURMUR time = " << timeMURMUR.count() << " mks." << std::endl;
    return 0;
}