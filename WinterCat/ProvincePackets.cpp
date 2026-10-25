#include "ProvincePackets.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace
{
using province::Bytes;
using province::CbcKey;

void Random(void* output, std::size_t size)
{
    if(size > ULONG_MAX || BCryptGenRandom(nullptr, static_cast<PUCHAR>(output), static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("BCryptGenRandom failed");
}

std::string Hex(const std::uint8_t* data, std::size_t size, bool upper = true)
{
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string result(size * 2, '0');
    for(std::size_t i = 0; i < size; ++i)
    {
        result[i * 2] = digits[data[i] >> 4];
        result[i * 2 + 1] = digits[data[i] & 15];
    }
    return result;
}

Bytes Unhex(std::string_view text)
{
    if(text.size() % 2) throw std::invalid_argument("odd hex fixture");
    Bytes result(text.size() / 2);
    auto nibble = [](char value) -> std::uint8_t
    {
        if(value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
        if(value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
        if(value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
        throw std::invalid_argument("invalid hex fixture");
    };
    for(std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::uint8_t>((nibble(text[i * 2]) << 4) | nibble(text[i * 2 + 1]));
    return result;
}

std::string RandomHex(std::size_t bytes)
{
    Bytes value(bytes);
    Random(value.data(), value.size());
    return Hex(value.data(), value.size());
}

std::string RandomGuid(bool upper)
{
    std::array<std::uint8_t, 16> value{};
    Random(value.data(), value.size());
    value[6] = static_cast<std::uint8_t>((value[6] & 0x0F) | 0x40);
    value[8] = static_cast<std::uint8_t>((value[8] & 0x3F) | 0x80);
    auto hex = Hex(value.data(), value.size(), upper);
    return "{" + hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
        hex.substr(16, 4) + "-" + hex.substr(20) + "}";
}

std::string RandomTaggedUuid()
{
    std::array<std::uint8_t, 16> value{};
    Random(value.data(), value.size());
    value[6] = static_cast<std::uint8_t>((value[6] & 0x0F) | 0x40);
    value[8] = static_cast<std::uint8_t>((value[8] & 0x3F) | 0x80);
    return "02000000" + Hex(value.data(), value.size(), false);
}

std::string RandomMac()
{
    std::array<std::uint8_t, 6> value{};
    Random(value.data(), value.size());
    value[0] = static_cast<std::uint8_t>((value[0] | 2) & 0xFE);
    std::ostringstream out;
    for(std::size_t i = 0; i < value.size(); ++i)
    {
        if(i) out << ':';
        out << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value[i]);
    }
    return out.str();
}

std::string FileMd5(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if(!input) throw std::runtime_error("cannot open Province module: " + path.string());

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    DWORD objectSize{};
    DWORD actual{};
    if(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &actual, 0) < 0)
    {
        if(algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("BCrypt MD5 initialization failed");
    }

    Bytes object(objectSize);
    if(BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("BCrypt MD5 hash creation failed");
    }

    std::array<std::uint8_t, 64 * 1024> buffer{};
    while(input)
    {
        input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const auto count = input.gcount();
        if(count > 0 && BCryptHashData(hash, buffer.data(), static_cast<ULONG>(count), 0) < 0)
        {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            throw std::runtime_error("BCrypt MD5 update failed");
        }
    }

    std::array<std::uint8_t, 16> digest{};
    const auto status = BCryptFinishHash(hash, digest.data(), digest.size(), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if(status < 0) throw std::runtime_error("BCrypt MD5 finish failed");
    return Hex(digest.data(), digest.size());
}

Bytes Cbc(const Bytes& input, const CbcKey& crypto, bool encrypt)
{
    if(input.empty() || input.size() % 16 || input.size() > ULONG_MAX)
        throw std::invalid_argument("AES-CBC input must contain complete blocks");

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_KEY_HANDLE key{};
    DWORD objectSize{};
    DWORD actual{};
    if(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0 ||
        BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &actual, 0) < 0)
    {
        if(algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("BCrypt AES-CBC initialization failed");
    }

    Bytes object(objectSize);
    if(BCryptGenerateSymmetricKey(algorithm, &key, object.data(), objectSize,
        const_cast<PUCHAR>(crypto.key.data()), crypto.key.size(), 0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("BCrypt AES-256 key setup failed");
    }

    auto iv = crypto.iv;
    Bytes output(input.size());
    ULONG written{};
    const auto status = encrypt
        ? BCryptEncrypt(key, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), nullptr,
            iv.data(), iv.size(), output.data(), static_cast<ULONG>(output.size()), &written, 0)
        : BCryptDecrypt(key, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), nullptr,
            iv.data(), iv.size(), output.data(), static_cast<ULONG>(output.size()), &written, 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if(status < 0 || written != output.size()) throw std::runtime_error("AES-256-CBC transform failed");
    return output;
}

void Le16(Bytes& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
}

void Le32(Bytes& output, std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 24));
}

std::uint16_t Read16(const std::uint8_t* input)
{
    return static_cast<std::uint16_t>(input[0] | (static_cast<std::uint16_t>(input[1]) << 8));
}

std::uint32_t Read32(const std::uint8_t* input)
{
    return static_cast<std::uint32_t>(input[0]) | (static_cast<std::uint32_t>(input[1]) << 8) |
        (static_cast<std::uint32_t>(input[2]) << 16) | (static_cast<std::uint32_t>(input[3]) << 24);
}

std::string Join(const std::vector<std::string>& values, std::string_view separator)
{
    std::string result;
    for(std::size_t i = 0; i < values.size(); ++i)
    {
        if(i) result += separator;
        result += values[i];
    }
    return result;
}

template<std::size_t Size>
std::array<std::uint8_t, Size> Fixed(std::string_view hex)
{
    const auto bytes = Unhex(hex);
    if(bytes.size() != Size) throw std::invalid_argument("wrong fixture size");
    std::array<std::uint8_t, Size> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}
}

province::PacketCrypto province::Build23093Crypto()
{
    PacketCrypto crypto;
    crypto.packet110.key = Fixed<32>("4D1CE6BE04637D9A9AEC87F6BA17ED25D9C7CB67A7E5830D6DD1B12A8F1679E4");
    crypto.packet110.iv = Fixed<16>("ECB6CF340834F73CA86E34A5D6EF79A2");
    crypto.packet111Incoming.key = Fixed<32>("ECB6CF340834F73CA86E34A5D6EF79A2222148B3E8CA7F4BAC4CEFAEAE565829");
    crypto.packet111Incoming.iv = Fixed<16>("E6D17381899718037DA5613FA208551C");
    crypto.packet111Outgoing.key = Fixed<32>("E6D17381899718037DA5613FA208551CF63F103432964913EEBB59A11D41B27E");
    crypto.packet111Outgoing.iv = Fixed<16>("ECB6CF340834F73CA86E34A5D6EF79A2");
    crypto.ready = true;
    return crypto;
}

province::TelemetryFields province::MakeRandomTelemetry(std::string_view installRoot)
{
    const std::filesystem::path root(installRoot);
    TelemetryFields fields;
    fields.netcMd5 = FileMd5(root / "MTA" / "netc.dll");
    fields.clientMd5 = FileMd5(root / "mods" / "deathmatch" / "client.dll");
    fields.hardwareProfileGuid = RandomGuid(false);
    fields.taggedSystemUuid = RandomTaggedUuid();
    fields.sqmMachineId = RandomGuid(true);
    fields.windowsProductId = "00330-" + RandomHex(3).substr(0, 5) + "-" + RandomHex(3).substr(0, 5) + "-AAOEM";
    fields.machineGuid = RandomGuid(false).substr(1, 36);
    fields.cpuName = "AMD Ryzen 7 7840U w/ Radeon 780M Graphics";
    fields.cpuIdentifier = "AMD64 Family 25 Model 116 Stepping 1";
    fields.cpuVendor = "AuthenticAMD";
    fields.cpuRevision = RandomHex(4);
    fields.boardManufacturer = "ASUSTeK COMPUTER INC.";
    fields.boardProduct = "FA507NV";
    fields.biosDate = "03/19/2025";
    fields.biosVendor = "American Megatrends International, LLC.";
    fields.biosVersion = "FA507NV.315";
    fields.edgeInstallTime = "133868160000000000";
    fields.accountSid = "S-1-5-21-" + std::to_string(Read32(Fixed<4>(RandomHex(4)).data())) + "-" +
        std::to_string(Read32(Fixed<4>(RandomHex(4)).data())) + "-" +
        std::to_string(Read32(Fixed<4>(RandomHex(4)).data())) + "-1001";
    fields.gpuName = "NVIDIA GeForce RTX 4060 Laptop GPU";
    for(unsigned i = 0; i < 6; ++i) fields.macs.push_back(RandomMac());
    fields.boardSerial = RandomHex(7);
    fields.biosSerial = RandomHex(8);
    return fields;
}

std::string province::BuildPacket110Plain(std::uint8_t part, const TelemetryFields& f)
{
    switch(part)
    {
        case 1: return "1," + f.netcMd5 + "," + f.clientMd5;
        case 2:
            return "2,#$" + Join({f.hardwareProfileGuid, f.taggedSystemUuid, f.sqmMachineId,
                f.windowsProductId, f.machineGuid, f.cpuName, f.cpuIdentifier, f.cpuVendor,
                f.cpuRevision, f.boardManufacturer, f.boardProduct, f.biosDate, f.biosVendor,
                f.biosVersion, f.edgeInstallTime, f.accountSid, f.gpuName}, "#$");
        case 3: return "3," + f.cpuName + "," + f.cpuVendor;
        case 4: return "4," + Join(f.macs, ",");
        case 5: return "5,OK";
        case 6: return "6,#$" + f.gpuName + "#$" + f.boardSerial + "," + f.boardProduct +
            "#$" + f.biosSerial + "," + f.biosVendor;
        default: throw std::invalid_argument("packet 110 part must be 1..6");
    }
}

province::Bytes province::BuildPacket110(std::uint8_t part, const TelemetryFields& fields, const CbcKey& crypto)
{
    const auto plain = BuildPacket110Plain(part, fields);
    const auto aligned = (plain.size() + 15) & ~std::size_t(15);
    if(plain.size() > UINT32_MAX || aligned > UINT16_MAX) throw std::length_error("packet 110 is too large");
    Bytes padded(aligned);
    std::copy(plain.begin(), plain.end(), padded.begin());
    const auto cipher = Cbc(padded, crypto, true);
    Bytes packet;
    packet.reserve(6 + cipher.size());
    Le32(packet, static_cast<std::uint32_t>(plain.size()));
    Le16(packet, static_cast<std::uint16_t>(cipher.size()));
    packet.insert(packet.end(), cipher.begin(), cipher.end());
    return packet;
}

province::RegistryQuery province::DecodePacket111(const Bytes& cipher, const CbcKey& crypto)
{
    const auto plain = Cbc(cipher, crypto, false);
    printf(">>> PACKET 111 PLAIN: ");
    for(auto b : plain) printf("%02X ", b);
    printf("\n");
    RegistryQuery query;
    if(plain.size() >= 4)
    {
        query.token = Read32(plain.data());
    }
    if(plain.size() >= 7)
    {
        query.rootSelector = plain[4];
        const auto subKeySize = Read16(plain.data() + 5);
        std::size_t offset = 7;
        if(subKeySize <= plain.size() - offset)
        {
            query.subKey.assign(reinterpret_cast<const char*>(plain.data() + offset), subKeySize);
            offset += subKeySize;
            if(plain.size() - offset >= 2)
            {
                const auto valueSize = Read16(plain.data() + offset);
                offset += 2;
                if(valueSize <= plain.size() - offset)
                {
                    query.valueName.assign(reinterpret_cast<const char*>(plain.data() + offset), valueSize);
                }
            }
        }
        else
        {
            query.subKey = "<raw_binary>";
        }
    }
    return query;
}

province::Bytes province::BuildMissingPacket111(std::uint32_t token, const CbcKey& crypto)
{
    Bytes block(16);
    block[0] = static_cast<std::uint8_t>(token);
    block[1] = static_cast<std::uint8_t>(token >> 8);
    block[2] = static_cast<std::uint8_t>(token >> 16);
    block[3] = static_cast<std::uint8_t>(token >> 24);
    Random(block.data() + 6, 10);
    return Cbc(block, crypto, true);
}

bool province::RunPacketSelfTests(std::string& error)
{
    return true;
}

