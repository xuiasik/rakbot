#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace province
{
using Bytes = std::vector<std::uint8_t>;
using Key = std::array<std::uint8_t, 32>;
using Iv = std::array<std::uint8_t, 16>;

struct CbcKey
{
    Key key{};
    Iv iv{};
};

struct PacketCrypto
{
    CbcKey packet110;
    CbcKey packet111Incoming;
    CbcKey packet111Outgoing;
    bool ready{};
};

struct TelemetryFields
{
    std::string netcMd5;
    std::string clientMd5;
    std::string hardwareProfileGuid;
    std::string taggedSystemUuid;
    std::string sqmMachineId;
    std::string windowsProductId;
    std::string machineGuid;
    std::string cpuName;
    std::string cpuIdentifier;
    std::string cpuVendor;
    std::string cpuRevision;
    std::string boardManufacturer;
    std::string boardProduct;
    std::string biosDate;
    std::string biosVendor;
    std::string biosVersion;
    std::string edgeInstallTime;
    std::string accountSid;
    std::string gpuName;
    std::vector<std::string> macs;
    std::string boardSerial;
    std::string biosSerial;
};

struct RegistryQuery
{
    std::uint32_t token{};
    std::uint8_t rootSelector{};
    std::string subKey;
    std::string valueName;
};

PacketCrypto Build23093Crypto();
TelemetryFields MakeRandomTelemetry(std::string_view installRoot);
std::string BuildPacket110Plain(std::uint8_t part, const TelemetryFields& fields);
Bytes BuildPacket110(std::uint8_t part, const TelemetryFields& fields, const CbcKey& crypto);
RegistryQuery DecodePacket111(const Bytes& cipher, const CbcKey& crypto);
Bytes BuildMissingPacket111(std::uint32_t token, const CbcKey& crypto);
bool RunPacketSelfTests(std::string& error);
}
