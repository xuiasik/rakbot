#include "MtaJoinCodec.hpp"
#include "MtaProtocol.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace
{
constexpr std::string_view kIntegrityTailHex =
    "0299011024009be58efbfbb4bff691ef83838ab8c28c8f84e8edeea6afe681fa939ee0a8db986e6a666424009f958d8a"
    "89b5bc8097eff4818abec189fc81999c9fa3d9e483f8e39391a8a699606764636c006214111660131013111315646318"
    "621617606314156414191616121363626265176712676512136560651963671711671167641764646560671612161712"
    "14646214111660131013176511651812121960151260631163641562136260646717621560131516621260666c6a6c00"
    "621411166013101317141819141713186364621214176360161612136362626517671267651213656517636264156518"
    "116764176464656067161216171214646214111660131013131367171217671060151260631163641562136260646717"
    "62156013151662126062646a2000e0e3e0eef6c3d164e89999e5f5c8ac6d83f7f4f8e0d5b400fc8e8ef7eedecb7d0000"
    "24009be58efbfbb4bff691ef83838ab8c28c8f84e8edeea6afe681fa939ee0a8db986e6a66641300100f170f110c140f"
    "13121118120f110f1111110094000000000105010000000600000200e00011dd000417008014001e24382d2f5740bd3e"
    "3f28710f0a68b26d243c2c3b008104040000050000000100040000000001010000000100000000000100000000000000"
    "000000000101000000000000000000000900100010000e002f00822c006566646d063527e3c1bdd3abb4caa22ad3afc6"
    "cbdddec748c5cca5adb1c8a22af38ae6e687feee6c14121b14530083500013c0755a54ceea57b71bc29ce6316f9ea509"
    "d7fc8f250afcb36ab49ae3336f9e852cf7d1d50523d862b40a23b8011ca26f09e867a89b6c6d9ca1193754fbc2b47ba6"
    "133751fb98b576a6113752fbcdb4";

constexpr std::string_view kProtectedJoinBlobHex =
    "05479630eaf7737c236e8213f74fa517dd4c3314642db008ff715b044b99a80f6be12aa5ab7d7be23fe0e17d34f63799"
    "911690b0ee78e9ac2b6906b7afd191b5cf2deedcad46e46681be9581f1398dc99f5754431dcf8a6aa30e14ca1cef0e63"
    "7f7b11b00d8e1611741f5aca91979fc8ae210b1bf9107523890e99ba38cbc8a894d29d9eaf81687c712dea06f340616c"
    "66c64445a51f0374ced2c5eede887ed5bd512ae8e03cf3d87d9c34861a2c56051642232898f88e5ec001b2b8abd88081"
    "5a32a7a610b6b801d45f996f7003926a67ddf17b690ab00bf790be09e31d5d002d87845217094aa54861c8df51bee10d"
    "adad1e2588cb1e456ecfa9bfa944bed7";

constexpr std::uint32_t kProtectedJoinTag = 0xF084BFDDu;

std::uint8_t HexNibble(char value)
{
    if(value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
    if(value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
    if(value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
    throw std::runtime_error("invalid Province JOIN fixture hex");
}

std::vector<std::uint8_t> DecodeHex(std::string_view value)
{
    if(value.size() & 1) throw std::runtime_error("odd Province JOIN fixture hex length");
    std::vector<std::uint8_t> bytes(value.size() / 2);
    for(std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::uint8_t>((HexNibble(value[i * 2]) << 4) | HexNibble(value[i * 2 + 1]));
    return bytes;
}

std::array<std::uint8_t, 16> Md5(std::string_view input)
{
    std::array<std::uint8_t, 16> digest{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;
    if(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0) < 0)
        throw std::runtime_error("BCrypt MD5 initialization failed");

    std::vector<std::uint8_t> object(objectLength);
    if(BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0 ||
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0) < 0 ||
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    {
        if(hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("BCrypt MD5 calculation failed");
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return digest;
}

std::vector<std::uint8_t> BuildPrimary(const ClientConfig& config)
{
    auto integrity = DecodeHex(kIntegrityTailHex);
    std::vector<std::uint8_t> primary(config.privateSerial.begin(), config.privateSerial.end());
    primary.insert(primary.end(), integrity.begin(), integrity.end());
    if(primary.size() != 702) throw std::runtime_error("Province JOIN primary must contain 702 bytes");

    for(std::size_t i = 0; i < primary.size(); ++i)
        primary[i] ^= static_cast<std::uint8_t>(i) ^ 0xD4u ^ static_cast<std::uint8_t>(1u << (i & 7));
    return primary;
}

std::array<std::uint8_t, 61> MakeJoinWrapper()
{
    std::array<std::uint8_t, 61> wrapper{};
    if(BCryptGenRandom(nullptr, wrapper.data(), static_cast<ULONG>(wrapper.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("BCryptGenRandom failed for JOIN wrapper");
    return wrapper;
}

void WriteString16(RakNet::BitStream& stream, std::string_view value)
{
    stream.Write(static_cast<std::uint16_t>(value.size()));
    if(!value.empty())
        stream.WriteAlignedBytes(reinterpret_cast<const unsigned char*>(value.data()), static_cast<unsigned int>(value.size()));
}

void WriteBlob16(RakNet::BitStream& stream, const std::vector<std::uint8_t>& value)
{
    stream.Write(static_cast<std::uint16_t>(value.size()));
    if(!value.empty()) stream.WriteAlignedBytes(value.data(), static_cast<unsigned int>(value.size()));
}
}

void mta::BuildJoinData(const ClientConfig& config, RakNet::BitStream& stream)
{
    stream.Reset();
    stream.Write(config.bitStreamVersion);

    std::array<std::uint8_t, 32> fixed{};
    std::memcpy(fixed.data(), config.serial.data(), fixed.size());
    for(std::size_t i = 0; i < fixed.size(); ++i)
        fixed[i] ^= static_cast<std::uint8_t>(i) ^ 0xD1u ^ static_cast<std::uint8_t>(1u << (i & 7));
    stream.WriteAlignedBytes(fixed.data(), static_cast<unsigned int>(fixed.size()));

    WriteBlob16(stream, BuildPrimary(config));

    std::uint8_t version = config.versionMajor;
    stream.WriteBits(&version, 7, true);
    version = config.versionMinor;
    stream.WriteBits(&version, 7, true);
    version = config.versionPatch;
    stream.WriteBits(&version, 7, true);
    version = config.releaseChannel;
    stream.WriteBits(&version, 7, true);
    auto build = config.build;
    stream.WriteBits(reinterpret_cast<unsigned char*>(&build), 23, true);
    stream.WriteCompressed(config.revision);
    auto buildXor = config.build ^ 0x54ABCDu;
    stream.WriteBits(reinterpret_cast<unsigned char*>(&buildXor), 23, true);

    const auto wrapper = MakeJoinWrapper();
    stream.Write(static_cast<std::uint16_t>(wrapper.size()));
    stream.WriteBits(wrapper.data(), static_cast<unsigned int>(wrapper.size() * 8), false);
    stream.AlignWriteToByteBoundary();

    stream.Write(config.netcodeVersion);
    stream.Write(config.mtaVersion);
    stream.Write(config.gameplayBitStreamVersion);
    WriteString16(stream, config.playerVersion);
    stream.Write(true);
    stream.Write(config.gameVersion);

    std::array<char, mta::kNickLength> nick{};
    std::memcpy(nick.data(), config.nick.data(), config.nick.size());
    stream.Write(nick.data(), static_cast<unsigned int>(nick.size()));

    std::array<std::uint8_t, mta::kPasswordDigestLength> password{};
    if(!config.password.empty()) password = Md5(config.password);
    stream.Write(reinterpret_cast<const char*>(password.data()), static_cast<unsigned int>(password.size()));

    std::array<char, mta::kSerialUserLength> serialUser{};
    stream.Write(serialUser.data(), static_cast<unsigned int>(serialUser.size()));

    const auto protectedBlob = DecodeHex(kProtectedJoinBlobHex);
    stream.Write(kProtectedJoinTag);
    stream.WriteBits(protectedBlob.data(), static_cast<unsigned int>(protectedBlob.size() * 8), false);
    stream.AlignWriteToByteBoundary();
}

bool mta::RunJoinCodecSelfTest(std::string& error)
{
    try
    {
        ClientConfig config;
        config.serial.assign(32, 'A');
        config.privateSerial.assign(64, 'B');
        RakNet::BitStream stream;
        BuildJoinData(config, stream);
        if(stream.GetNumberOfBitsUsed() != 9328)
        {
            error = "Province JOIN body is not 9328 bits";
            return false;
        }
        return true;
    }
    catch(const std::exception& exception)
    {
        error = exception.what();
        return false;
    }
}

