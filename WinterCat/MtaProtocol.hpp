#pragma once

#include <cstddef>
#include <cstdint>

namespace mta
{
constexpr std::uint8_t kWireUserPacketBase = 99;
constexpr std::size_t kNickLength = 22;
constexpr std::size_t kPasswordDigestLength = 16;
constexpr std::size_t kSerialUserLength = 32;

enum class PacketId : std::uint8_t
{
    ServerJoin = 0,
    ServerJoinData = 1,
    ServerJoinComplete = 2,
    PlayerJoin = 3,
    PlayerJoinData = 4,
    PlayerQuit = 5,
    PlayerTimeout = 6,
    ModName = 7,
    ServerJoinedGame = 22,
    ServerDisconnected = 23,
    Rpc = 24,
    PlayerPureSync = 32,
    LuaEvent = 81,
    ResourceStart = 82,
    LatentTransfer = 96,
    PlayerNetworkStatus = 103,
    PlayerResourceStart = 108,
    ProvinceTelemetry = 110,
    ProvinceRegistry = 111
};

constexpr std::uint8_t ToWireId(std::uint8_t logicalId)
{
    return static_cast<std::uint8_t>(logicalId + 99);
}

constexpr std::uint8_t ToWireId(PacketId id)
{
    return ToWireId(static_cast<std::uint8_t>(id));
}
}
