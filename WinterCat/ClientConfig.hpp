#pragma once

#include <cstdint>
#include <string>

struct ClientConfig
{
    std::string host{"185.71.66.81"};
    std::uint16_t port{22003};
    std::string nick{"WinterCat"};
    std::string serial;
    std::string privateSerial;
    std::string password;
    std::string loginUsername;
    std::string loginPassword;
    std::string provinceRoot{"C:\\Province Games"};
    std::string playerVersion{"1.6.0-5.23093.0"};
    std::uint16_t bitStreamVersion{140};
    std::uint8_t versionMajor{1};
    std::uint8_t versionMinor{6};
    std::uint8_t versionPatch{0};
    std::uint8_t releaseChannel{5};
    std::uint32_t build{23093};
    std::uint16_t revision{0};
    std::uint16_t netcodeVersion{0x41DA};
    std::uint16_t mtaVersion{0x0160};
    std::uint16_t gameplayBitStreamVersion{0x008C};
    std::uint8_t gameVersion{11};
    std::uint32_t connectTimeoutMs{15000};
    std::uint32_t holdSeconds{0};
    std::uint16_t instances{1};
    bool randomIdentities{false};
    bool randomNick{false};
    bool traceHex{false};
    bool transportOnly{false};
    bool noPureSync{false};
    bool latentTransfer{false};
    bool selfTest{false};
};

ClientConfig ParseCommandLine(int argc, char** argv);
void RandomizeClientInstance(ClientConfig& config);
void PrintUsage();
