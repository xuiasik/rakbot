#pragma once

#include "ClientConfig.hpp"
#include "MtaTransport.hpp"
#include "ProvincePackets.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

class MtaClient
{
public:
    explicit MtaClient(ClientConfig config, std::function<void()> latentHeaderSent = {});
    int Run();
    void RequestStop() { stopRequested_ = true; }

private:
    enum class State
    {
        Disconnected,
        Connecting,
        TransportConnected,
        PlayerJoinSent,
        ModNegotiated,
        JoinDataSent,
        JoinComplete,
        JoinedGame,
        Maintained,
        Failed
    };

    void HandlePacket(const std::vector<std::uint8_t>& packet);
    void HandleRakNetPacket(std::uint8_t id, const std::vector<std::uint8_t>& packet);
    void HandleMtaPacket(std::uint8_t logicalId, const std::vector<std::uint8_t>& packet);
    bool SendMtaPacket(std::uint8_t logicalId, RakNet::BitStream& payload, PacketPriority priority, PacketReliability reliability, std::uint8_t channel = 0);
    bool SendEmpty(std::uint8_t logicalId, PacketPriority priority, PacketReliability reliability, std::uint8_t channel = 0);
    bool SendPlayerJoin();
    bool SendJoinData();
    bool SendRpc(std::uint8_t rpcId);
    bool SendPlayerNetworkStatus();
    bool SendPlayerPureSync();
    bool SendLatentLuaEventReserveHeader(const std::string& eventName);
    bool TriggerServerEvent(const std::string& eventName, std::uint32_t elementId, const std::vector<std::string>& stringArgs);
    bool TriggerServerEventBool(const std::string& eventName, std::uint32_t elementId, bool boolArg);
    bool TriggerServerEventTable(const std::string& eventName, std::uint32_t elementId, const std::vector<std::pair<std::string, std::string>>& tableEntries);
    bool SendPlayerResourceStart(std::uint16_t resourceNetId, std::uint32_t startCounter);
    bool SendAcVerification();
    void HandleLuaEvent(RakNet::BitStream& payload);
    void HandleResourceStart(RakNet::BitStream& payload);
    void SendMaintenance();
    void Trace(const std::vector<std::uint8_t>& packet) const;
    void Fail(const std::string& reason);

    ClientConfig config_;
    std::function<void()> latentHeaderSent_;
    MtaTransport transport_;
    State state_{State::Disconnected};
    std::uint16_t serverBitStreamVersion_{0};
    std::uint8_t syncTimeContext_{1};
    std::chrono::steady_clock::time_point started_{};
    std::chrono::steady_clock::time_point joined_{};
    std::chrono::steady_clock::time_point lastStatus_{};
    std::chrono::steady_clock::time_point lastPureSync_{};
    std::chrono::steady_clock::time_point lastResourceStart_{};
    bool clientReadySent_{false};
    bool loginSent_{false};
    bool loggedIn_{false};
    std::chrono::steady_clock::time_point lastLoginAttempt_{};
    int loginAttemptCount_{0};
    std::uint32_t localElementId_{(1u << 17) - 1u};
    std::unordered_map<std::string, std::uint32_t> resourceRoots_;
    std::chrono::steady_clock::time_point provinceRpStarted_{};
    bool acVerified_{false};
    bool spawnSelected_{false};
    bool spawnPending_{false};
    std::chrono::steady_clock::time_point spawnPendingSince_{};
    std::atomic<bool> stopRequested_{};
    province::PacketCrypto crypto_{province::Build23093Crypto()};
};
