#include "MtaClient.hpp"
#include "MtaJoinCodec.hpp"
#include "MtaProtocol.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;

namespace
{
constexpr std::uint16_t kLatentTransferCategoryPacket = 1;
constexpr std::uint8_t kLatentTransferFlagHead = 0;
constexpr std::uint32_t kLatentTransferReceiverLimitBytes = 100u * 1024u * 1024u;
constexpr std::uint32_t kLatentTransferPreferredReserveBytes = 100u * 1024u * 1024u;
constexpr std::uint32_t kLatentTransferFallbackReserveBytes = 99u * 1024u * 1024u;
constexpr std::uint32_t kLatentTransferReserveBytes =
    kLatentTransferPreferredReserveBytes <= kLatentTransferReceiverLimitBytes ?
    kLatentTransferPreferredReserveBytes : kLatentTransferFallbackReserveBytes;
constexpr std::uint32_t kLatentTransferRateBytesPerSecond = 500;
constexpr std::uint32_t kInvalidElementId = (1u << 17) - 1u;
constexpr char kPostConnectLuaEventName[] = "b2T5DbG1LbQnRTZXRMYXVuY2h1ckRhAdGE";

const char* RakName(std::uint8_t id)
{
    switch (id)
    {
        case 14: return "CONNECTION_REQUEST_ACCEPTED";
        case 15: return "CONNECTION_ATTEMPT_FAILED";
        case 16: return "ALREADY_CONNECTED";
        case 18: return "NO_FREE_INCOMING_CONNECTIONS";
        case 19: return "DISCONNECTION_NOTIFICATION";
        case 20: return "CONNECTION_LOST";
        case 21: return "RSA_PUBLIC_KEY_MISMATCH";
        case 22: return "CONNECTION_BANNED";
        case 23: return "INVALID_PASSWORD";
        case 24: return "MODIFIED_PACKET";
        default: return "RAKNET_INTERNAL";
    }
}

void WriteFloatBits(RakNet::BitStream& stream, unsigned count, float minimum, float maximum, float value)
{
    const float clamped = std::clamp(value, minimum, maximum);
    const float alpha = (clamped - minimum) / (maximum - minimum);
    const auto packed = static_cast<std::uint32_t>(std::lround(alpha * static_cast<float>((1u << count) - 1u)));
    stream.WriteBits(reinterpret_cast<const unsigned char*>(&packed), count, true);
}

void WriteSignedFixed(RakNet::BitStream& stream, unsigned integerBits, unsigned fractionalBits, float value)
{
    const unsigned fullBits = integerBits + fractionalBits;
    const double minimum = -static_cast<double>(1u << (integerBits - 1));
    const double maximum = static_cast<double>((1u << (integerBits - 1)) - 1u);
    const double scale = static_cast<double>(1u << fractionalBits);
    const auto scaled = static_cast<std::int32_t>(std::lround(std::clamp(static_cast<double>(value), minimum, maximum) * scale));
    const auto packed = static_cast<std::uint32_t>(scaled) & ((1u << fullBits) - 1u);
    stream.WriteBits(reinterpret_cast<const unsigned char*>(&packed), fullBits, true);
}

void WriteKeys(RakNet::BitStream& stream)
{
    std::uint8_t flags = 0;
    stream.WriteBits(&flags, 8, true);
    stream.Write(false);
    stream.Write(false);
    stream.Write(static_cast<std::int8_t>(0));
    stream.Write(static_cast<std::int8_t>(0));
}

void WriteCamera(RakNet::BitStream& stream)
{
    constexpr float pi = 3.14159265f;
    WriteFloatBits(stream, 8, -pi, pi, 0.0f);
    WriteFloatBits(stream, 8, -pi, pi, 0.0f);
    stream.Write(false);
    std::uint8_t precision = 0;
    stream.WriteBits(&precision, 2, true);
    WriteFloatBits(stream, 3, -4.0f, 4.0f, 0.0f);
    WriteFloatBits(stream, 3, -4.0f, 4.0f, 0.0f);
    WriteFloatBits(stream, 3, -4.0f, 4.0f, 0.0f);
}
}

MtaClient::MtaClient(ClientConfig config, std::function<void()> latentHeaderSent)
    : config_(std::move(config)), latentHeaderSent_(std::move(latentHeaderSent))
{
}

int MtaClient::Run()
{
    std::cout << "WinterCat x86 / RakNet 3.25 reliability / MTA custom transport\n"
              << "target=" << config_.host << ':' << config_.port
              << " nick=" << config_.nick
              << " version=" << config_.playerVersion
              << " join-profile=province"
              << " join-bs=" << config_.bitStreamVersion
              << " build=" << config_.build << "\n";
    if(config_.latentTransfer)
        std::cout << "latent-transfer=on reserve-bytes=" << kLatentTransferReserveBytes
                  << " rate=" << kLatentTransferRateBytesPerSecond << '\n';

    started_ = std::chrono::steady_clock::now();
    state_ = State::Connecting;
    if (!transport_.Connect(config_.host, config_.port))
    {
        Fail(transport_.Error());
        return 2;
    }

    if (config_.instances <= 1)
        StartConsoleThread();

    while (state_ != State::Failed && !stopRequested_)
    {
        transport_.Poll();
        if (transport_.HasFailed())
        {
            Fail(transport_.Error());
            break;
        }

        std::vector<std::uint8_t> packet;
        while (transport_.Receive(packet))
        {
            Trace(packet);
            HandlePacket(packet);
        }

        ProcessConsoleCommands();

        const auto now = std::chrono::steady_clock::now();
        if (state_ == State::Connecting && now - started_ > std::chrono::milliseconds(config_.connectTimeoutMs))
            Fail("transport connect timeout");
        else if (state_ != State::Maintained && state_ != State::Connecting && now - started_ > 30s)
            Fail("MTA join timeout");

        if (state_ == State::Maintained && !config_.transportOnly)
            SendMaintenance();

        // Hold timer completely disabled - keep connection open indefinitely until user stops the client
        /* if (config_.holdSeconds && joined_ != std::chrono::steady_clock::time_point{} && now - joined_ >= std::chrono::seconds(config_.holdSeconds))
        {
            std::cout << "hold interval completed\n";
            transport_.Disconnect();
            return 0;
        } */
        std::this_thread::sleep_for(1ms);
    }
    if(stopRequested_)
    {
        std::cout << "client stop requested after bounded observation\n";
        transport_.Disconnect();
        return 0;
    }
    return 3;
}

void MtaClient::HandlePacket(const std::vector<std::uint8_t>& packet)
{
    if (packet.empty())
        return;
    const auto id = packet[0];
    if (id < mta::kWireUserPacketBase)
        HandleRakNetPacket(id, packet);
    else
        HandleMtaPacket(static_cast<std::uint8_t>(id - mta::kWireUserPacketBase), packet);
}

void MtaClient::HandleRakNetPacket(std::uint8_t id, const std::vector<std::uint8_t>& packet)
{
    std::cout << "RakNet IN id=" << static_cast<unsigned>(id) << ' ' << RakName(id) << " bytes=" << packet.size() << "\n";
    switch (id)
    {
        case 14:
            state_ = State::TransportConnected;
            if (config_.transportOnly)
            {
                std::cout << "transport-only success\n";
                joined_ = std::chrono::steady_clock::now();
                state_ = State::Maintained;
            }
            else if (!SendPlayerJoin())
                Fail("PLAYER_JOIN send failed");
            break;
        case 15:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 24:
            Fail(RakName(id));
            break;
        default:
            break;
    }
}

void MtaClient::HandleMtaPacket(std::uint8_t logicalId, const std::vector<std::uint8_t>& packet)
{
    const bool sessionPacket = logicalId == static_cast<std::uint8_t>(mta::PacketId::ModName) ||
        logicalId == static_cast<std::uint8_t>(mta::PacketId::ServerJoinComplete) ||
        logicalId == static_cast<std::uint8_t>(mta::PacketId::ServerJoinedGame) ||
        logicalId == static_cast<std::uint8_t>(mta::PacketId::ServerDisconnected) ||
        logicalId == static_cast<std::uint8_t>(mta::PacketId::ProvinceRegistry);
    if (sessionPacket || logicalId == static_cast<std::uint8_t>(mta::PacketId::LuaEvent) || config_.traceHex)
        std::cout << "MTA IN logical=" << static_cast<unsigned>(logicalId)
                  << " wire=" << static_cast<unsigned>(packet[0]) << " bytes=" << packet.size() << "\n";
    RakNet::BitStream payload(const_cast<unsigned char*>(packet.data() + 1), static_cast<unsigned int>(packet.size() - 1), false);

    if(logicalId == static_cast<std::uint8_t>(mta::PacketId::ProvinceRegistry))
    {
        std::cout << ">>> PROVINCE PACKET 111 (" << packet.size() << " bytes)\n";
        if(packet.size() > 1)
        {
            try
            {
                province::Bytes cipher(packet.begin() + 1, packet.end());
                printf(">>> INCOMING CIPHER: ");
                for(auto b : cipher) printf("%02X ", b);
                printf("\n");
                const auto query = province::DecodePacket111(cipher, crypto_.packet111Incoming);
                std::cout << ">>> PACKET 111 QUERY: token=0x" << std::hex << query.token << std::dec
                          << " root=" << static_cast<unsigned>(query.rootSelector)
                          << " subKey=\"" << query.subKey << "\" val=\"" << query.valueName << "\"\n";
                const auto reply = province::BuildMissingPacket111(query.token, crypto_.packet111Outgoing);
                RakNet::BitStream replyBs;
                replyBs.Write(reinterpret_cast<const char*>(reply.data()), static_cast<unsigned int>(reply.size()));
                SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::ProvinceRegistry), replyBs, HIGH_PRIORITY, RELIABLE_ORDERED, 1);
                std::cout << ">>> PACKET 111 REPLY SENT (16 bytes) for token=0x" << std::hex << query.token << std::dec << "\n";
            }
            catch(const std::exception& e)
            {
                std::cout << ">>> PACKET 111 DECODE ERROR: " << e.what() << "\n";
                std::uint32_t fallbackToken = 0;
                if(packet.size() >= 5)
                    memcpy(&fallbackToken, packet.data() + 1, 4);
                const auto reply = province::BuildMissingPacket111(fallbackToken, crypto_.packet111Outgoing);
                RakNet::BitStream replyBs;
                replyBs.Write(reinterpret_cast<const char*>(reply.data()), static_cast<unsigned int>(reply.size()));
                SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::ProvinceRegistry), replyBs, HIGH_PRIORITY, RELIABLE_ORDERED, 1);
                std::cout << ">>> PACKET 111 FALLBACK REPLY SENT (16 bytes) for token=0x" << std::hex << fallbackToken << std::dec << "\n";
            }
        }
    }
    else if (logicalId == static_cast<std::uint8_t>(mta::PacketId::ModName))
    {
        std::uint16_t length = 0;
        std::string mod;
        if (!payload.Read(serverBitStreamVersion_) || !payload.Read(length) || length > 128 ||
            payload.GetNumberOfUnreadBits() < static_cast<BitSize_t>(length) * 8u)
        {
            Fail("malformed MOD_NAME");
            return;
        }
        mod.resize(length);
        if (length && !payload.Read(mod.data(), length))
        {
            Fail("truncated MOD_NAME");
            return;
        }
        std::cout << "MOD_NAME bitstream=" << serverBitStreamVersion_ << " mod=" << mod << "\n";
        if (state_ != State::PlayerJoinSent)
            return;
        state_ = State::ModNegotiated;
        if (!SendJoinData()) Fail("PLAYER_JOINDATA send failed");
    }
    else if (logicalId == static_cast<std::uint8_t>(mta::PacketId::ServerJoinComplete))
    {
        state_ = State::JoinComplete;
        if (!SendRpc(0)) Fail("PLAYER_INGAME_NOTICE send failed");
    }
    else if (logicalId == static_cast<std::uint8_t>(mta::PacketId::ServerJoinedGame))
    {
        localElementId_ = 0;
        payload.ReadBits(reinterpret_cast<unsigned char*>(&localElementId_), 17, true);
        std::cout << "SERVER_JOINEDGAME localElement=" << localElementId_ << "\n";
        state_ = State::JoinedGame;
        joined_ = std::chrono::steady_clock::now();
        lastStatus_ = joined_ - 2s;
        lastPureSync_ = joined_ - 100ms;
        if (!SendRpc(1)) Fail("INITIAL_DATA_STREAM send failed");
        else
        {
            state_ = State::Maintained;
            std::cout << "MTA Session Established. Waiting for security checks / resources before login...\n";
            if(config_.latentTransfer && !SendLatentLuaEventReserveHeader(kPostConnectLuaEventName))
                std::cerr << "LATENT header send failed\n";
        }
    }
    else if (logicalId == static_cast<std::uint8_t>(mta::PacketId::LuaEvent))
    {
        HandleLuaEvent(payload);
    }
    else if (logicalId == static_cast<std::uint8_t>(mta::PacketId::ResourceStart))
    {
        HandleResourceStart(payload);
    }
    else if(logicalId == static_cast<std::uint8_t>(mta::PacketId::ServerDisconnected))
    {
        std::uint8_t type = 0;
        std::uint16_t length = 0;
        std::string reason;
        if(payload.ReadBits(&type, 5, true) && payload.GetNumberOfUnreadBits() >= 16 && payload.Read(length) &&
            length <= 1024 && payload.GetNumberOfUnreadBits() >= static_cast<BitSize_t>(length) * 8u)
        {
            reason.resize(length);
            if(length) payload.Read(reason.data(), length);
        }
        std::cout << "SERVER_DISCONNECTED type=" << static_cast<unsigned>(type)
                  << " reason=" << (reason.empty() ? "<none>" : reason) << "\n";
        Fail("server sent SERVER_DISCONNECTED");
    }
}

bool MtaClient::SendMtaPacket(std::uint8_t logicalId, RakNet::BitStream& payload, PacketPriority priority, PacketReliability reliability, std::uint8_t channel)
{
    RakNet::BitStream wire;
    const auto wireId = mta::ToWireId(logicalId);
    wire.Write(wireId);
    if (payload.GetNumberOfBitsUsed())
    {
        payload.ResetReadPointer();
        wire.Write(&payload, payload.GetNumberOfBitsUsed());
    }
    const bool sent = transport_.Send(wire, priority, reliability, channel);
    const bool maintenance = logicalId == static_cast<std::uint8_t>(mta::PacketId::PlayerPureSync) ||
        logicalId == static_cast<std::uint8_t>(mta::PacketId::PlayerNetworkStatus) ||
        logicalId == static_cast<std::uint8_t>(mta::PacketId::LatentTransfer);
    if (!maintenance || config_.traceHex)
        std::cout << "MTA OUT logical=" << static_cast<unsigned>(logicalId)
                  << " wire=" << static_cast<unsigned>(wireId)
                  << " bits=" << wire.GetNumberOfBitsUsed() << " sent=" << sent << "\n";
    return sent;
}

bool MtaClient::SendEmpty(std::uint8_t logicalId, PacketPriority priority, PacketReliability reliability, std::uint8_t channel)
{
    RakNet::BitStream empty;
    return SendMtaPacket(logicalId, empty, priority, reliability, channel);
}

bool MtaClient::SendPlayerJoin()
{
    const bool sent = SendEmpty(static_cast<std::uint8_t>(mta::PacketId::PlayerJoin), HIGH_PRIORITY, RELIABLE_ORDERED);
    if (sent) state_ = State::PlayerJoinSent;
    return sent;
}

bool MtaClient::SendJoinData()
{
    RakNet::BitStream join;
    mta::BuildJoinData(config_, join);
    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::PlayerJoinData), join, HIGH_PRIORITY, RELIABLE_ORDERED);
    if (sent) state_ = State::JoinDataSent;
    return sent;
}

bool MtaClient::SendRpc(std::uint8_t rpcId)
{
    RakNet::BitStream payload;
    payload.Write(rpcId);
    return SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::Rpc), payload, HIGH_PRIORITY, RELIABLE_ORDERED);
}

bool MtaClient::SendPlayerNetworkStatus()
{
    RakNet::BitStream payload;
    payload.Write(static_cast<std::uint8_t>(1));
    payload.Write(static_cast<std::uint32_t>(GetTickCount64()));
    return SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::PlayerNetworkStatus), payload, LOW_PRIORITY, UNRELIABLE_SEQUENCED);
}

bool MtaClient::SendPlayerPureSync()
{
    RakNet::BitStream payload;
    payload.Write(syncTimeContext_);
    WriteKeys(payload);
    std::uint16_t flags = 1u << 1;
    payload.WriteBits(reinterpret_cast<const unsigned char*>(&flags), 12, true);
    WriteSignedFixed(payload, 14, 10, 0.0f);
    WriteSignedFixed(payload, 14, 10, 0.0f);
    payload.Write(3.0f);
    constexpr float pi = 3.14159265f;
    WriteFloatBits(payload, 16, -pi, pi, 0.0f);
    WriteFloatBits(payload, 8, 0.0f, 255.0f, 100.0f);
    WriteFloatBits(payload, 8, 0.0f, 127.5f, 0.0f);
    WriteFloatBits(payload, 12, -pi, pi, 0.0f);
    WriteCamera(payload);
    payload.Write(false);
    return SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::PlayerPureSync), payload, MEDIUM_PRIORITY, UNRELIABLE_SEQUENCED);
}

bool MtaClient::SendLatentLuaEventReserveHeader(const std::string& eventName)
{
    if(eventName.empty() || localElementId_ == kInvalidElementId) return false;

    RakNet::BitStream event;
    event.WriteCompressed(static_cast<std::uint16_t>(eventName.size()));
    event.Write(eventName.c_str(), static_cast<unsigned int>(eventName.size()));
    event.WriteBits(reinterpret_cast<const unsigned char*>(&localElementId_), 17, true);
    event.WriteCompressed(static_cast<std::uint32_t>(1));
    const std::uint8_t luaNilType = 0;
    event.WriteBits(&luaNilType, 4, true);
    const auto eventBits = event.GetNumberOfBitsUsed();

    static std::atomic_uint nextTransferId{1};
    auto transferId = static_cast<std::uint16_t>(nextTransferId.fetch_add(1) & 0x7FFFu);
    if(!transferId) transferId = 1;

    RakNet::BitStream latent;
    latent.WriteBits(reinterpret_cast<const unsigned char*>(&transferId), 15, true);
    latent.Write(true);
    latent.Write(kLatentTransferFlagHead);
    latent.Write(kLatentTransferCategoryPacket);
    latent.Write(kLatentTransferReserveBytes);
    latent.Write(kLatentTransferRateBytesPerSecond);
    latent.Write(static_cast<std::uint16_t>(0xFFFF));
    latent.AlignWriteToByteBoundary();
    latent.Write(static_cast<std::uint16_t>(0));

    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LatentTransfer),
        latent, LOW_PRIORITY, RELIABLE_ORDERED, 2);
    std::cout << "LATENT header send=" << sent
              << " name=" << eventName
              << " source=" << localElementId_
              << " transfer=" << transferId
              << " reserveMB=" << kLatentTransferReserveBytes / (1024u * 1024u)
              << " eventBits=" << eventBits
              << " tail=0\n";
    if(sent && latentHeaderSent_)
    {
        auto callback = std::move(latentHeaderSent_);
        callback();
    }
    return sent;
}

bool MtaClient::TriggerServerEvent(const std::string& eventName, std::uint32_t elementId, const std::vector<std::string>& stringArgs)
{
    if(eventName.empty()) return false;

    RakNet::BitStream payload;
    // 1. Event name (compressed length + string bytes)
    const auto nameLen = static_cast<std::uint16_t>(eventName.size());
    payload.WriteCompressed(nameLen);
    payload.Write(eventName.data(), static_cast<unsigned int>(eventName.size()));

    // 2. Element ID (17 bits)
    payload.WriteBits(reinterpret_cast<const unsigned char*>(&elementId), 17, true);

    // 3. Argument count (compressed uint32)
    const auto argCount = static_cast<std::uint32_t>(stringArgs.size());
    payload.WriteCompressed(argCount);

    // 4. Arguments (each is LUA_TSTRING: 4-bit type 4 + compressed uint16 length + characters)
    constexpr std::uint8_t kLuaTypeString = 4;
    for(const auto& arg : stringArgs)
    {
        payload.WriteBits(&kLuaTypeString, 4, true);
        const auto strLen = static_cast<std::uint16_t>(arg.size());
        payload.WriteCompressed(strLen);
        if(strLen > 0)
            payload.Write(arg.data(), static_cast<unsigned int>(arg.size()));
    }

    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LuaEvent),
        payload, HIGH_PRIORITY, RELIABLE_ORDERED, 0);
    std::cout << "LUA_EVENT SENT: name=" << eventName << " element=" << elementId << " args=" << stringArgs.size() << " sent=" << sent << "\n";
    return sent;
}

bool MtaClient::TriggerServerEventBool(const std::string& eventName, std::uint32_t elementId, bool boolArg)
{
    if(eventName.empty()) return false;

    RakNet::BitStream payload;
    const auto nameLen = static_cast<std::uint16_t>(eventName.size());
    payload.WriteCompressed(nameLen);
    payload.Write(eventName.data(), static_cast<unsigned int>(eventName.size()));

    payload.WriteBits(reinterpret_cast<const unsigned char*>(&elementId), 17, true);

    const std::uint32_t argCount = 1;
    payload.WriteCompressed(argCount);

    constexpr std::uint8_t kLuaTypeBoolean = 1;
    payload.WriteBits(&kLuaTypeBoolean, 4, true);
    payload.Write(boolArg);

    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LuaEvent),
        payload, HIGH_PRIORITY, RELIABLE_ORDERED, 0);
    std::cout << "LUA_EVENT (bool) SENT: name=" << eventName << " element=" << elementId << " val=" << (boolArg ? "true" : "false") << " sent=" << sent << "\n";
    return sent;
}

bool MtaClient::TriggerServerEventTable(const std::string& eventName, std::uint32_t elementId, const std::vector<std::pair<std::string, std::string>>& tableEntries)
{
    if(eventName.empty()) return false;

    RakNet::BitStream payload;
    const auto nameLen = static_cast<std::uint16_t>(eventName.size());
    payload.WriteCompressed(nameLen);
    payload.Write(eventName.data(), static_cast<unsigned int>(eventName.size()));

    payload.WriteBits(reinterpret_cast<const unsigned char*>(&elementId), 17, true);

    const std::uint16_t argCount = 1;
    payload.WriteCompressed(argCount);

    constexpr std::uint8_t kLuaTypeTable = 5;
    payload.WriteBits(&kLuaTypeTable, 4, true);

    const auto itemCount = static_cast<std::uint32_t>(tableEntries.size() * 2);
    payload.WriteCompressed(itemCount);

    constexpr std::uint8_t kLuaTypeString = 4;
    for(const auto& [k, v] : tableEntries)
    {
        payload.WriteBits(&kLuaTypeString, 4, true);
        const auto kLen = static_cast<std::uint16_t>(k.size());
        payload.WriteCompressed(kLen);
        if(kLen > 0) payload.Write(k.data(), static_cast<unsigned int>(k.size()));

        payload.WriteBits(&kLuaTypeString, 4, true);
        const auto vLen = static_cast<std::uint16_t>(v.size());
        payload.WriteCompressed(vLen);
        if(vLen > 0) payload.Write(v.data(), static_cast<unsigned int>(v.size()));
    }

    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LuaEvent),
        payload, HIGH_PRIORITY, RELIABLE_ORDERED, 0);
    std::cout << "LUA_EVENT (table) SENT: name=" << eventName << " element=" << elementId << " pairs=" << tableEntries.size() << " sent=" << sent << "\n";
    return sent;
}

static void WriteLuaValue(RakNet::BitStream& bs, const LuaValue& val)
{
    switch (val.type)
    {
    case LuaValueType::Nil:
    {
        constexpr std::uint8_t kLuaTypeNil = 0;
        bs.WriteBits(&kLuaTypeNil, 4, true);
        break;
    }
    case LuaValueType::Boolean:
    {
        constexpr std::uint8_t kLuaTypeBoolean = 1;
        bs.WriteBits(&kLuaTypeBoolean, 4, true);
        bs.Write(val.boolVal);
        break;
    }
    case LuaValueType::Element:
    {
        constexpr std::uint8_t kLuaTypeElement = 2;
        bs.WriteBits(&kLuaTypeElement, 4, true);
        bs.WriteBits(reinterpret_cast<const unsigned char*>(&val.elementVal), 17, true);
        break;
    }
    case LuaValueType::NumberInt:
    {
        constexpr std::uint8_t kLuaTypeNumber = 3;
        bs.WriteBits(&kLuaTypeNumber, 4, true);
        const bool isFloat = false;
        bs.Write(isFloat);
        bs.WriteCompressed(val.intVal);
        break;
    }
    case LuaValueType::NumberFloat:
    {
        constexpr std::uint8_t kLuaTypeNumber = 3;
        bs.WriteBits(&kLuaTypeNumber, 4, true);
        const bool isFloat = true;
        bs.Write(isFloat);
        const bool isDouble = false;
        bs.Write(isDouble);
        const float f = static_cast<float>(val.floatVal);
        bs.Write(f);
        break;
    }
    case LuaValueType::String:
    {
        constexpr std::uint8_t kLuaTypeString = 4;
        bs.WriteBits(&kLuaTypeString, 4, true);
        const auto len = static_cast<std::uint16_t>(val.strVal.size());
        bs.WriteCompressed(len);
        if (len > 0)
            bs.Write(val.strVal.data(), static_cast<unsigned int>(val.strVal.size()));
        break;
    }
    case LuaValueType::Table:
    {
        constexpr std::uint8_t kLuaTypeTable = 5;
        bs.WriteBits(&kLuaTypeTable, 4, true);
        const auto itemCount = static_cast<std::uint32_t>(val.tablePairs.size() * 2);
        bs.WriteCompressed(itemCount);
        for (const auto& pair : val.tablePairs)
        {
            WriteLuaValue(bs, pair.first);
            WriteLuaValue(bs, pair.second);
        }
        break;
    }
    }
}

bool MtaClient::TriggerServerEventDynamic(const std::string& eventName, std::uint32_t elementId, const std::vector<LuaValue>& args)
{
    if (eventName.empty()) return false;

    RakNet::BitStream payload;
    const auto nameLen = static_cast<std::uint16_t>(eventName.size());
    payload.WriteCompressed(nameLen);
    payload.Write(eventName.data(), static_cast<unsigned int>(eventName.size()));

    payload.WriteBits(reinterpret_cast<const unsigned char*>(&elementId), 17, true);

    const auto argCount = static_cast<std::uint32_t>(args.size());
    payload.WriteCompressed(argCount);

    for (const auto& arg : args)
    {
        WriteLuaValue(payload, arg);
    }

    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LuaEvent),
        payload, HIGH_PRIORITY, RELIABLE_ORDERED, 0);

    std::cout << "[CONSOLE] >>> LUA_EVENT SENT: name=\"" << eventName << "\" element=" << elementId << " args=" << args.size() << " sent=" << (sent ? "OK" : "FAILED") << "\n";
    return sent;
}

namespace
{
std::string Trim(std::string s)
{
    if (s.size() >= 3 && static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB && static_cast<unsigned char>(s[2]) == 0xBF)
    {
        s = s.substr(3);
    }
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

std::string StripQuotes(std::string s)
{
    s = Trim(s);
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\'')))
        return s.substr(1, s.size() - 2);
    return s;
}

std::vector<std::string> SplitArgs(const std::string& str)
{
    std::vector<std::string> tokens;
    std::string current;
    int braceDepth = 0;
    bool inQuote = false;
    char quoteChar = 0;

    for (size_t i = 0; i < str.size(); ++i)
    {
        char c = str[i];

        if (!inQuote && c == '-' && i + 1 < str.size() && str[i + 1] == '-')
        {
            if (i + 3 < str.size() && str[i + 2] == '[' && str[i + 3] == '[')
            {
                size_t endComment = str.find("]]", i + 4);
                if (endComment != std::string::npos)
                {
                    i = endComment + 1;
                    continue;
                }
            }
            break;
        }

        if (inQuote)
        {
            current += c;
            if (c == '\\' && i + 1 < str.size())
            {
                current += str[++i];
            }
            else if (c == quoteChar)
            {
                inQuote = false;
            }
            continue;
        }

        if (c == '"' || c == '\'')
        {
            inQuote = true;
            quoteChar = c;
            current += c;
            continue;
        }

        if (c == '{')
        {
            braceDepth++;
            current += c;
            continue;
        }
        if (c == '}')
        {
            if (braceDepth > 0) braceDepth--;
            current += c;
            continue;
        }

        if (braceDepth == 0)
        {
            if (c == ',' || c == ' ' || c == '\t')
            {
                std::string trimmed = Trim(current);
                if (!trimmed.empty())
                {
                    tokens.push_back(trimmed);
                    current.clear();
                }
                continue;
            }
        }

        current += c;
    }

    std::string trimmed = Trim(current);
    if (!trimmed.empty())
        tokens.push_back(trimmed);

    return tokens;
}

size_t FindTopLevelEqual(const std::string& s)
{
    int braceDepth = 0;
    bool inQuote = false;
    char quoteChar = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        char c = s[i];
        if (inQuote)
        {
            if (c == '\\' && i + 1 < s.size()) i++;
            else if (c == quoteChar) inQuote = false;
            continue;
        }
        if (c == '"' || c == '\'') { inQuote = true; quoteChar = c; continue; }
        if (c == '{') { braceDepth++; continue; }
        if (c == '}') { if (braceDepth > 0) braceDepth--; continue; }
        if (braceDepth == 0 && c == '=')
            return i;
    }
    return std::string::npos;
}
}

std::uint32_t MtaClient::FindResourceRoot(const std::string& eventName)
{
    std::string prefix;
    size_t col = eventName.find(':');
    if (col != std::string::npos)
        prefix = eventName.substr(0, col);
    else
    {
        size_t under = eventName.find('_');
        if (under != std::string::npos)
            prefix = eventName.substr(0, under);
    }

    if (!prefix.empty())
    {
        auto it = resourceRoots_.find(prefix);
        if (it != resourceRoots_.end()) return it->second;

        std::string provPrefix = "province_" + prefix;
        it = resourceRoots_.find(provPrefix);
        if (it != resourceRoots_.end()) return it->second;

        for (const auto& [name, root] : resourceRoots_)
        {
            if (name.find(prefix) != std::string::npos)
                return root;
        }
    }

    auto itRp = resourceRoots_.find("Province_RP");
    if (itRp != resourceRoots_.end()) return itRp->second;

    if (!resourceRoots_.empty())
        return resourceRoots_.begin()->second;

    return 1;
}

std::uint32_t MtaClient::ResolveElement(const std::string& elemStr, const std::string& eventName)
{
    std::string s = Trim(elemStr);
    if (s.empty())
        return FindResourceRoot(eventName);

    if (s == "localPlayer" || s == "localplayer" || s == "me" || s == "player")
        return localElementId_;

    if (s == "resourceRoot" || s == "resRoot")
        return FindResourceRoot(eventName);

    if (s.starts_with("resourceRoot:"))
    {
        std::string resName = s.substr(13);
        auto it = resourceRoots_.find(resName);
        if (it != resourceRoots_.end()) return it->second;
        return FindResourceRoot(resName);
    }

    if (s == "root" || s == "rootElement")
        return 1;

    if (s.starts_with("0x") || s.starts_with("0X"))
    {
        try { return static_cast<std::uint32_t>(std::stoul(s, nullptr, 16)); } catch (...) {}
    }

    bool allDigits = true;
    for (char c : s) if (!std::isdigit(static_cast<unsigned char>(c))) { allDigits = false; break; }
    if (allDigits && !s.empty())
    {
        try { return static_cast<std::uint32_t>(std::stoul(s)); } catch (...) {}
    }

    auto it = resourceRoots_.find(s);
    if (it != resourceRoots_.end())
        return it->second;

    return FindResourceRoot(eventName);
}

LuaValue MtaClient::ParseLuaValue(const std::string& token, std::uint32_t defaultElem, std::uint32_t localElem)
{
    std::string s = Trim(token);
    LuaValue v;

    if (s.empty() || s == "nil" || s == "NIL")
    {
        v.type = LuaValueType::Nil;
        return v;
    }

    if (s == "true" || s == "TRUE")
    {
        v.type = LuaValueType::Boolean;
        v.boolVal = true;
        return v;
    }

    if (s == "false" || s == "FALSE")
    {
        v.type = LuaValueType::Boolean;
        v.boolVal = false;
        return v;
    }

    if (s == "localPlayer" || s == "me")
    {
        v.type = LuaValueType::Element;
        v.elementVal = localElem;
        return v;
    }

    if (s == "resourceRoot")
    {
        v.type = LuaValueType::Element;
        v.elementVal = defaultElem;
        return v;
    }

    if (s == "root")
    {
        v.type = LuaValueType::Element;
        v.elementVal = 1;
        return v;
    }

    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\'')))
    {
        v.type = LuaValueType::String;
        v.strVal = StripQuotes(s);
        return v;
    }

    if (s.size() >= 2 && s.front() == '{' && s.back() == '}')
    {
        v.type = LuaValueType::Table;
        std::string inner = s.substr(1, s.size() - 2);
        auto items = SplitArgs(inner);
        int autoIndex = 1;
        for (const auto& item : items)
        {
            size_t eqPos = FindTopLevelEqual(item);
            if (eqPos != std::string::npos)
            {
                std::string kStr = Trim(item.substr(0, eqPos));
                std::string vStr = Trim(item.substr(eqPos + 1));
                if (kStr.size() >= 2 && kStr.front() == '[' && kStr.back() == ']')
                    kStr = Trim(kStr.substr(1, kStr.size() - 2));

                LuaValue key = ParseLuaValue(kStr, defaultElem, localElem);
                LuaValue val = ParseLuaValue(vStr, defaultElem, localElem);
                v.tablePairs.emplace_back(key, val);
            }
            else
            {
                LuaValue key;
                key.type = LuaValueType::NumberInt;
                key.intVal = autoIndex++;
                LuaValue val = ParseLuaValue(item, defaultElem, localElem);
                v.tablePairs.emplace_back(key, val);
            }
        }
        return v;
    }

    if (s.starts_with("0x") || s.starts_with("0X"))
    {
        try
        {
            v.type = LuaValueType::NumberInt;
            v.intVal = static_cast<int>(std::stol(s, nullptr, 16));
            return v;
        }
        catch (...) {}
    }

    bool isInt = true;
    bool isFloat = false;
    size_t start = (s.front() == '-' || s.front() == '+') ? 1 : 0;
    if (start < s.size())
    {
        for (size_t i = start; i < s.size(); ++i)
        {
            char c = s[i];
            if (c == '.' && !isFloat)
            {
                isFloat = true;
                isInt = false;
            }
            else if (!std::isdigit(static_cast<unsigned char>(c)))
            {
                isInt = false;
                isFloat = false;
                break;
            }
        }

        if (isInt)
        {
            try
            {
                v.type = LuaValueType::NumberInt;
                v.intVal = std::stoi(s);
                return v;
            }
            catch (...) {}
        }
        else if (isFloat)
        {
            try
            {
                v.type = LuaValueType::NumberFloat;
                v.floatVal = std::stod(s);
                return v;
            }
            catch (...) {}
        }
    }

    v.type = LuaValueType::String;
    v.strVal = s;
    return v;
}

void MtaClient::StartConsoleThread()
{
    if (consoleStarted_)
        return;
    consoleStarted_ = true;

    std::cout << "\n=======================================================\n";
    std::cout << ">>> INTERACTIVE CONSOLE READY!\n";
    std::cout << ">>> Type trigger commands (e.g. triggerServerEvent(\"...\") or 'help')\n";
    std::cout << "=======================================================\n\n";

    consoleThread_ = std::thread([this]()
    {
        std::string line;
        while (!stopRequested_)
        {
            if (!std::getline(std::cin, line))
                break;

            std::string trimmed = Trim(line);
            if (trimmed.empty())
                continue;

            {
                std::lock_guard<std::mutex> lock(consoleMutex_);
                consoleQueue_.push(trimmed);
            }
        }
    });
    consoleThread_.detach();
}

void MtaClient::ProcessConsoleCommands()
{
    std::string cmd;
    while (true)
    {
        {
            std::lock_guard<std::mutex> lock(consoleMutex_);
            if (consoleQueue_.empty())
                break;
            cmd = std::move(consoleQueue_.front());
            consoleQueue_.pop();
        }
        ExecuteConsoleCommand(cmd);
    }
}

void MtaClient::ExecuteConsoleCommand(const std::string& rawCmd)
{
    std::string cmd = Trim(rawCmd);
    if (cmd.empty())
        return;

    if (cmd == "exit" || cmd == "quit")
    {
        std::cout << "[CONSOLE] Disconnecting and exiting...\n";
        stopRequested_ = true;
        return;
    }

    if (cmd == "help" || cmd == "?")
    {
        std::cout << "\n==================================================================\n";
        std::cout << "           WINTERCAT INTERACTIVE LUA CONSOLE                      \n";
        std::cout << "==================================================================\n";
        std::cout << " 1. Direct Lua call (paste from logger or scripts):\n";
        std::cout << "    triggerServerEvent(\"eventName\", [element], [arg1], [arg2]...)\n";
        std::cout << "    Examples:\n";
        std::cout << "      triggerServerEvent(\"radio:xnykuxcazgmqruzg\")\n";
        std::cout << "      triggerServerEvent(\"boneAttach_requestAttachmentData\", resourceRoot)\n";
        std::cout << "      triggerServerEvent(\"afktimer:toggleAFK\", resourceRoot, false)\n";
        std::cout << "      triggerServerEvent(\"onRequestLogin\", localPlayer, \"user\", \"pass\")\n";
        std::cout << "      triggerServerEvent(\"onNotifyTargetEnabled\", resourceRoot, true, {[1] = \"Categories\"})\n\n";
        std::cout << " 2. Short CLI syntax:\n";
        std::cout << "    trigger <eventName> [element] [args...]\n";
        std::cout << "    Examples:\n";
        std::cout << "      trigger donate:requestBonus\n";
        std::cout << "      trigger afktimer:toggleAFK resourceRoot false\n";
        std::cout << "      trigger aPermissions localPlayer\n\n";
        std::cout << " 3. Utility commands:\n";
        std::cout << "    roots / res         - Show all loaded resources & root element IDs\n";
        std::cout << "    player / me         - Show local player element ID\n";
        std::cout << "    ac                  - Re-send AC verification table\n";
        std::cout << "    login <user> <pass> - Trigger login request\n";
        std::cout << "    exit / quit         - Disconnect and exit\n";
        std::cout << "==================================================================\n\n";
        return;
    }

    if (cmd == "roots" || cmd == "res" || cmd == "resources")
    {
        std::cout << "\n=======================================================\n";
        std::cout << "[CONSOLE] Loaded Resource Roots (" << resourceRoots_.size() << " total):\n";
        std::cout << "  - localPlayer: netID " << localElementId_ << " (0x" << std::hex << localElementId_ << std::dec << ")\n";
        for (const auto& [name, rootId] : resourceRoots_)
        {
            std::cout << "  - " << name << ": netID " << rootId << " (0x" << std::hex << rootId << std::dec << ")\n";
        }
        std::cout << "=======================================================\n\n";
        return;
    }

    if (cmd == "player" || cmd == "local" || cmd == "me")
    {
        std::cout << "[CONSOLE] localPlayer netID = " << localElementId_ << " (0x" << std::hex << localElementId_ << std::dec << ")\n";
        return;
    }

    if (cmd == "ac")
    {
        std::cout << "[CONSOLE] Resending AC verification...\n";
        acVerified_ = false;
        SendAcVerification();
        return;
    }

    if (cmd.starts_with("login "))
    {
        auto tokens = SplitArgs(cmd.substr(6));
        if (tokens.size() >= 2)
        {
            std::string user = StripQuotes(tokens[0]);
            std::string pass = StripQuotes(tokens[1]);
            std::cout << "[CONSOLE] Sending onRequestLogin with user=" << user << "...\n";
            TriggerServerEvent("onRequestLogin", localElementId_, {user, pass});
        }
        else
        {
            std::cout << "[CONSOLE] Usage: login <username> <password>\n";
        }
        return;
    }

    if (cmd.starts_with("code ") || cmd.starts_with("sec ") || cmd.starts_with("2fa "))
    {
        std::string code = StripQuotes(Trim(cmd.substr(cmd.find(' ') + 1)));
        std::cout << "[CONSOLE] >>> Sending login:checkSecCode and login:check2FA with code=" << code << "...\n";
        TriggerServerEvent("login:checkSecCode", localElementId_, {code});
        TriggerServerEvent("login:check2FA", localElementId_, {code});
        return;
    }

    // Direct 6-digit code support (e.g. user just pastes "843917")
    if (cmd.size() == 6 && std::all_of(cmd.begin(), cmd.end(), ::isdigit))
    {
        std::cout << "[CONSOLE] >>> Sending 6-digit email confirmation code: " << cmd << "...\n";
        TriggerServerEvent("login:checkSecCode", localElementId_, {cmd});
        TriggerServerEvent("login:check2FA", localElementId_, {cmd});
        return;
    }

    if (cmd.starts_with("spawn ") || cmd == "spawn")
    {
        std::string pt = "lastpoint";
        if (cmd.starts_with("spawn "))
            pt = StripQuotes(Trim(cmd.substr(6)));
        std::cout << "[CONSOLE] >>> Manually sending auth:onPlayerSelectSpawnPoint with point=" << pt << " on localElement=" << localElementId_ << "...\n";
        TriggerServerEvent("auth:onPlayerSelectSpawnPoint", localElementId_, {pt});
        return;
    }

    bool isLuaFunc = false;
    std::string work = cmd;
    if (work.starts_with("triggerServerEvent") || work.starts_with("TriggerServerEvent"))
    {
        isLuaFunc = true;
        size_t op = work.find('(');
        size_t cl = work.rfind(')');
        if (op != std::string::npos && cl != std::string::npos && cl > op)
            work = work.substr(op + 1, cl - op - 1);
    }
    else if (work.starts_with("trigger ") || work.starts_with("send "))
    {
        work = work.substr(work.find(' ') + 1);
    }

    auto tokens = SplitArgs(work);
    if (tokens.empty())
        return;

    std::string eventName = StripQuotes(tokens[0]);
    std::uint32_t elementId = 0;
    std::vector<LuaValue> args;

    if (isLuaFunc)
    {
        if (tokens.size() >= 2)
        {
            elementId = ResolveElement(tokens[1], eventName);
            for (size_t i = 2; i < tokens.size(); ++i)
                args.push_back(ParseLuaValue(tokens[i], elementId, localElementId_));
        }
        else
        {
            elementId = ResolveElement("", eventName);
        }
    }
    else
    {
        if (tokens.size() >= 2)
        {
            const std::string& t1 = tokens[1];
            if (t1 == "localPlayer" || t1 == "me" || t1 == "player" ||
                t1 == "resourceRoot" || t1 == "root" ||
                t1.starts_with("resourceRoot:") ||
                t1.starts_with("0x") ||
                resourceRoots_.find(t1) != resourceRoots_.end())
            {
                elementId = ResolveElement(t1, eventName);
                for (size_t i = 2; i < tokens.size(); ++i)
                    args.push_back(ParseLuaValue(tokens[i], elementId, localElementId_));
            }
            else
            {
                elementId = ResolveElement("", eventName);
                for (size_t i = 1; i < tokens.size(); ++i)
                    args.push_back(ParseLuaValue(tokens[i], elementId, localElementId_));
            }
        }
        else
        {
            elementId = ResolveElement("", eventName);
        }
    }

    if (eventName == "radio:xnykuxcazgmqruzg" && args.empty())
    {
        std::cout << "[CONSOLE] Triggering official AC verification table for radio:xnykuxcazgmqruzg...\n";
        acVerified_ = false;
        SendAcVerification();
        return;
    }

    std::cout << "[CONSOLE] >>> Sending triggerServerEvent(\"" << eventName << "\", element=" << elementId << ", args=" << args.size() << ")...\n";
    TriggerServerEventDynamic(eventName, elementId, args);
}

bool MtaClient::SendAcVerification()
{
    if (acVerified_)
        return true;
    acVerified_ = true;

    std::uint32_t acRoot = 1;
    auto it = resourceRoots_.find("province_ac");
    if(it != resourceRoots_.end() && it->second != 0)
        acRoot = it->second;

    RakNet::BitStream payload;
    const std::string eventName = "radio:xnykuxcazgmqruzg";
    const auto nameLen = static_cast<std::uint16_t>(eventName.size());
    payload.WriteCompressed(nameLen);
    payload.Write(eventName.data(), static_cast<unsigned int>(eventName.size()));

    payload.WriteBits(reinterpret_cast<const unsigned char*>(&acRoot), 17, true);

    const std::uint16_t argCount = 1;
    payload.WriteCompressed(argCount);

    constexpr std::uint8_t kLuaTypeBoolean = 1;
    constexpr std::uint8_t kLuaTypeNumber = 3;
    constexpr std::uint8_t kLuaTypeString = 4;
    constexpr std::uint8_t kLuaTypeTable = 5;

    auto writeNumber = [&](int val) {
        payload.WriteBits(&kLuaTypeNumber, 4, true);
        const bool isFloat = false;
        payload.Write(isFloat);
        payload.WriteCompressed(val);
    };

    auto writeString = [&](const std::string& str) {
        payload.WriteBits(&kLuaTypeString, 4, true);
        const auto len = static_cast<std::uint16_t>(str.size());
        payload.WriteCompressed(len);
        if(len > 0) payload.Write(str.data(), static_cast<unsigned int>(str.size()));
    };

    auto writeBool = [&](bool b) {
        payload.WriteBits(&kLuaTypeBoolean, 4, true);
        payload.Write(b);
    };

    // Table with 9 key-value pairs (18 items total):
    // [1] = hash of client.dll ("4D54F73E8D8F360F6FC2CEB9D4BB13A0")
    // [2] = mtime of client.dll (1792178937)
    // [3] = hash of netc.dll ("F84B670D281D1E2FAB59F44091B4DC11")
    // [4] = mtime of netc.dll (1781684864)
    // [5] = "none"
    // [6] = "none"
    // [7] = "none"
    // [8] = sub-table { [1]=true, [2]=true, [3]=true }
    // [9] = true
    payload.WriteBits(&kLuaTypeTable, 4, true);
    const std::uint32_t mainItemCount = 12;
    payload.WriteCompressed(mainItemCount);

    writeNumber(1); writeString("26699A041A9A82B0D5227653C4888FDE");
    writeNumber(2); writeNumber(1792685782);
    writeNumber(3); writeString("F84B670D281D1E2FAB59F44091B4DC11");
    writeNumber(4); writeNumber(1781684864);
    // none
    // none
    // none

    writeNumber(8);
    payload.WriteBits(&kLuaTypeTable, 4, true);
    const std::uint32_t subItemCount = 6;
    payload.WriteCompressed(subItemCount);
    writeNumber(1); writeBool(false);
    writeNumber(2); writeBool(false);
    writeNumber(3); writeBool(false);

    writeNumber(9);
    writeBool(true);

    const bool sent = SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LuaEvent),
        payload, HIGH_PRIORITY, RELIABLE_ORDERED, 0);
    std::cout << "\n>>> AC VERIFICATION SENT: 'radio:xnykuxcazgmqruzg' on element=" << acRoot << " (sent=" << sent << ")\n\n";
    return sent;
}

void MtaClient::HandleLuaEvent(RakNet::BitStream& payload)
{
    std::uint16_t nameLen = 0;
    if(!payload.ReadCompressed(nameLen) || nameLen > 512 || payload.GetNumberOfUnreadBits() < 17)
    {
        std::cout << "LUA_EVENT RECV: malformed event header\n";
        return;
    }

    std::string eventName(nameLen, '\0');
    if(nameLen > 0 && !payload.Read(eventName.data(), nameLen))
    {
        std::cout << "LUA_EVENT RECV: truncated event name\n";
        return;
    }

    std::uint32_t elementId = 0;
    payload.ReadBits(reinterpret_cast<unsigned char*>(&elementId), 17, true);
    if(elementId == 0x1FFFF) elementId = 0xFFFFFFFF;

    std::uint32_t argCount = 0;
    payload.ReadCompressed(argCount);

    std::function<std::string()> readArg = [&]() -> std::string {
        if(payload.GetNumberOfUnreadBits() < 4) return "<eof>";
        std::uint8_t luaType = 0;
        payload.ReadBits(&luaType, 4, true);
        if(luaType == 0) // NIL
        {
            return "nil";
        }
        else if(luaType == 1) // BOOLEAN
        {
            bool bVal = false;
            payload.Read(bVal);
            return bVal ? "true" : "false";
        }
        else if(luaType == 3) // NUMBER
        {
            bool isFloat = false;
            if(payload.Read(isFloat))
            {
                if(isFloat)
                {
                    bool isDouble = false;
                    if(payload.Read(isDouble))
                    {
                        if(isDouble) { double d = 0; payload.Read(d); return std::to_string(d); }
                        else { float f = 0; payload.Read(f); return std::to_string(f); }
                    }
                }
                else
                {
                    int iVal = 0;
                    if(payload.ReadCompressed(iVal))
                        return std::to_string(iVal);
                }
            }
            return "<num_err>";
        }
        else if(luaType == 4) // STRING_SHORT
        {
            std::uint16_t strLen = 0;
            if(payload.ReadCompressed(strLen))
            {
                if(strLen > 4096 || payload.GetNumberOfUnreadBits() < static_cast<BitSize_t>(strLen) * 8u)
                    return "<str_err>";
                std::string str(strLen, '\0');
                if(strLen == 0 || payload.Read(str.data(), strLen))
                    return "\"" + str + "\"";
            }
            return "<str_err>";
        }
        else if(luaType == 10) // STRING_LONG
        {
            std::uint32_t strLen = 0;
            if(payload.ReadCompressed(strLen))
            {
                if(strLen > 65536 || payload.GetNumberOfUnreadBits() < static_cast<BitSize_t>(strLen) * 8u)
                    return "<long_str_err>";
                payload.AlignReadToByteBoundary();
                std::string str(strLen, '\0');
                if(strLen == 0 || payload.Read(str.data(), strLen))
                    return "\"" + str + "\"";
            }
            return "<long_str_err>";
        }
        else if(luaType == 5) // TABLE
        {
            std::uint32_t count = 0;
            if(payload.ReadCompressed(count))
            {
                if(count > 1000) count = 1000;
                std::string res = "{";
                for(std::uint32_t i = 0; i < count; ++i)
                {
                    if(payload.GetNumberOfUnreadBits() < 4) { res += "..."; break; }
                    if(i > 0) res += (i % 2 == 1 ? "=" : ", ");
                    res += readArg();
                }
                res += "}";
                return res;
            }
            return "<tbl_err>";
        }
        else if(luaType == 9) // TABLE_REF
        {
            std::uint32_t refId = 0;
            payload.ReadCompressed(refId);
            return "<ref:" + std::to_string(refId) + ">";
        }
        else if(luaType == 2 || luaType == 7) // ELEMENT (LIGHTUSERDATA or USERDATA)
        {
            std::uint32_t eId = 0;
            payload.ReadBits(reinterpret_cast<unsigned char*>(&eId), 17, true);
            if(eId == 0x1FFFF) eId = 0xFFFFFFFF;
            return "<elem:" + std::to_string(eId) + ">";
        }
        if(luaType > 10)
            return "<invalid_type:" + std::to_string(static_cast<unsigned>(luaType)) + ">";
        return "<type_" + std::to_string(static_cast<unsigned>(luaType)) + ">";
    };

    std::vector<std::string> parsedStrings;
    if(argCount > 256) argCount = 256;
    for(std::uint32_t i = 0; i < argCount; ++i)
    {
        if(payload.GetNumberOfUnreadBits() < 4) break;
        parsedStrings.push_back(readArg());
    }

    std::cout << ">>> LUA_EVENT RECV: name=\"" << eventName << "\" element=" << elementId << " args=[";
    for(size_t i = 0; i < parsedStrings.size(); ++i)
    {
        if(i > 0) std::cout << ", ";
        std::cout << parsedStrings[i];
    }
    std::cout << "]\n";

    if (eventName == "main:sendServerTime")
    {
        std::cout << "\n=======================================================\n";
        std::cout << ">>> === [OK] OTVET OT SERVERA POLUCHEN: main:sendServerTime! ===\n";
        std::cout << "=======================================================\n\n";
    }

    if (eventName == "login:sendError" || eventName == "login:clientError" || eventName == "login:errorCode")
    {
        std::cout << "\n=======================================================\n";
        std::cout << ">>> === [SERVER AUTH RESPONSE: ERROR / ACCOUNT STATUS] ===\n";
        std::cout << ">>> Event: " << eventName << "\n";
        for (const auto& arg : parsedStrings)
            std::cout << ">>> Message: " << arg << "\n";
        std::cout << "=======================================================\n\n";
    }
    else if (eventName == "login:clientAccountFound")
    {
        std::cout << "\n=======================================================\n";
        std::cout << ">>> === [SERVER AUTH RESPONSE: ACCOUNT FOUND! (login:clientAccountFound)] ===\n";
        std::cout << "=======================================================\n\n";
    }
    else if (eventName == "login:regAccFound")
    {
        std::cout << "\n=======================================================\n";
        std::cout << ">>> === [SERVER AUTH RESPONSE: REG ACCOUNT EXISTS! (login:regAccFound)] ===\n";
        std::cout << "=======================================================\n\n";
    }
    else if (eventName == "login:2FA" || eventName == "login:secureCode")
    {
        std::cout << "\n=======================================================\n";
        std::cout << ">>> === [SERVER AUTH: 2FA / EMAIL CODE REQUIRED! (" << eventName << ")] ===\n";
        std::cout << ">>> Type: code <123456> or just enter the 6 digits directly in console!\n";
        std::cout << "=======================================================\n\n";
    }

    if (eventName == "onLogin" || eventName == "LOGIN:showSuccess")
    {
        loggedIn_ = true;
        if (elementId != 0 && elementId != 0xFFFFFFFF && elementId != 1)
        {
            std::cout << ">>> Updating localPlayer elementId from " << localElementId_ << " to " << elementId << "\n";
            localElementId_ = elementId;
        }

        std::cout << "\n========================================\n";
        std::cout << ">>> SUCCESSFUL LOGIN! (" << eventName << " received on element=" << elementId << ")\n";
        std::cout << "========================================\n\n";

        // Required on onLogin by province_documents:
        std::cout << ">>> Triggering documents:updatePlayerPermission on localElement=" << localElementId_ << "...\n";
        TriggerServerEvent("documents:updatePlayerPermission", localElementId_, {});

        // Required by Province_RP login_c.luac proto 0.30: triggerServerEvent("auth:accountCheck", resourceRoot)
        auto itRp = resourceRoots_.find("Province_RP");
        const std::uint32_t rpRoot = (itRp != resourceRoots_.end()) ? itRp->second : 0;
        if (rpRoot != 0)
        {
            std::cout << ">>> Triggering auth:accountCheck on Province_RP root=" << rpRoot << "...\n";
            TriggerServerEvent("auth:accountCheck", rpRoot, {});
        }

        auto itShop = resourceRoots_.find("province_carshop");
        if (itShop != resourceRoots_.end() && itShop->second != 0)
        {
            TriggerServerEvent("carshop:requestCarPlateSlots", itShop->second, {});
        }
    }
    else if (eventName == "province_camhunt:onClientRespawned" || eventName == "helper:showStartGUI")
    {
        // Player respawned or GUI shown
    }
    else if (eventName == "ac:yoclmn")
    {
        std::uint32_t acRoot = 1;
        auto it = resourceRoots_.find("province_ac");
        if(it != resourceRoots_.end() && it->second != 0)
            acRoot = it->second;

        // ac-c.lua line 357: triggerServerEvent("ac:yoclmn", resourceRoot, getPlayerSerial(), true)
        RakNet::BitStream resp;
        const std::string rName = "ac:yoclmn";
        const auto nLen = static_cast<std::uint16_t>(rName.size());
        resp.WriteCompressed(nLen);
        resp.Write(rName.data(), static_cast<unsigned int>(rName.size()));
        resp.WriteBits(reinterpret_cast<const unsigned char*>(&acRoot), 17, true);
        const std::uint32_t aCount = 2;
        resp.WriteCompressed(aCount);

        constexpr std::uint8_t kLuaTypeString = 4;
        resp.WriteBits(&kLuaTypeString, 4, true);
        const auto sLen = static_cast<std::uint16_t>(config_.serial.size());
        resp.WriteCompressed(sLen);
        resp.Write(config_.serial.data(), static_cast<unsigned int>(config_.serial.size()));

        constexpr std::uint8_t kLuaTypeBoolean = 1;
        resp.WriteBits(&kLuaTypeBoolean, 4, true);
        resp.Write(true);

        SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::LuaEvent), resp, HIGH_PRIORITY, RELIABLE_ORDERED, 0);
        std::cout << "\n>>> RESPONDED TO ac:yoclmn with serial and true!\n\n";
    }
    else if (eventName == "login:clientAccountFound")
    {
        std::cout << "\n>>> ACCOUNT FOUND ON SERVER (login:clientAccountFound)\n\n";
    }
    else if (eventName == "onClientLoginPanel")
    {
        std::string panelSheet = parsedStrings.empty() ? "" : parsedStrings[0];
        std::cout << ">>> onClientLoginPanel received: sheet=" << panelSheet << "\n";
    }
    else if (eventName == "login:sendError" || eventName == "login:clientError" || eventName == "LOGIN:showError" || eventName == "login:errorCode")
    {
        std::cout << "\n=======================================================\n";
        std::cout << ">>> [SERVER LOGIN ERROR RESPONSE]: (" << eventName << ") ";
        for (const auto& a : parsedStrings) std::cout << a << " ";
        std::cout << "\n=======================================================\n\n";
    }
    else if (eventName == "login:regAccFound" || eventName == "login:successfulCode")
    {
        std::cout << "\n>>> REGISTRATION CODE ACCEPTED! (" << eventName << ")\n\n";
    }
    else if (eventName == "login:2FA" || eventName == "LOGIN:onTwoFaResponse")
    {
        std::cout << "\n>>> LOGIN 2FA REQUIRED!\n\n";
    }
    else if (eventName == "auth:onClientOpenSpawpointSelector")
    {
        if (elementId != 0 && elementId != 0xFFFFFFFF && elementId != 1)
        {
            std::cout << ">>> Updating localPlayer elementId from " << localElementId_ << " to " << elementId << "\n";
            localElementId_ = elementId;
        }

        std::cout << "\n=======================================================\n";
        std::cout << ">>> SPAWN POINT SELECTOR OPENED (" << parsedStrings.size() << " args) on element=" << elementId << "\n";
        std::cout << ">>> AUTO-SPAWN IS DISABLED! Holding connection.\n";
        std::cout << ">>> To spawn manually later, type: spawn lastpoint (or spawn railway)\n";
        std::cout << "=======================================================\n\n";
    }
}

bool MtaClient::SendPlayerResourceStart(std::uint16_t resourceNetId, std::uint32_t startCounter)
{
    RakNet::BitStream payload;
    payload.Write(resourceNetId);
    payload.Write(startCounter);
    return SendMtaPacket(static_cast<std::uint8_t>(mta::PacketId::PlayerResourceStart), payload, HIGH_PRIORITY, RELIABLE_ORDERED, 0);
}

void MtaClient::HandleResourceStart(RakNet::BitStream& payload)
{
    std::uint8_t nameLen = 0;
    if(!payload.Read(nameLen) || payload.GetNumberOfUnreadBits() < (static_cast<BitSize_t>(nameLen) * 8u + 48u))
        return;

    std::string resName(nameLen, '\0');
    if(nameLen > 0) payload.Read(resName.data(), nameLen);

    std::uint32_t startCounter = 0;
    payload.Read(startCounter);

    std::uint16_t resourceNetId = 0;
    payload.Read(resourceNetId);

    std::uint32_t resourceRootId = 0;
    if(payload.GetNumberOfUnreadBits() >= 17)
        payload.ReadBits(reinterpret_cast<unsigned char*>(&resourceRootId), 17, true);

    std::uint32_t dynamicRootId = 0;
    if(payload.GetNumberOfUnreadBits() >= 17)
        payload.ReadBits(reinterpret_cast<unsigned char*>(&dynamicRootId), 17, true);

    if(!resName.empty() && resourceRootId != 0)
        resourceRoots_[resName] = resourceRootId;

    std::cout << "RESOURCE_START: name=\"" << resName << "\" netId=" << resourceNetId
              << " counter=" << startCounter << " resRoot=" << resourceRootId << " dynRoot=" << dynamicRootId << "\n";
    lastResourceStart_ = std::chrono::steady_clock::now();

    // Acknowledge resource start to server so the server marks this client as ready
    SendPlayerResourceStart(resourceNetId, startCounter);

    if (resName == "province_ac")
    {
        std::cout << ">>> province_ac resource started, sending AC verification immediately...\n";
        SendAcVerification();
        std::cout << "\n==================================================================\n";
        std::cout << ">>> AC VERIFICATION SENT! INTERACTIVE CONSOLE READY\n";
        std::cout << ">>> Only 'radio:xnykuxcazgmqruzg' was sent automatically.\n";
        std::cout << ">>> All other triggers are awaiting manual input in console!\n";
        std::cout << "==================================================================\n\n";
    }
    /* // Optional gameplay resource triggers (disabled so you can trigger them manually via console):
    else if (resName == "bone_attach" && resourceRootId != 0)
    {
        TriggerServerEvent("boneAttach_requestAttachmentData", resourceRootId, {});
    }
    else if (resName == "scoreboard")
    {
        TriggerServerEvent("onClientDXScoreboardResourceStart", 1, {});
        TriggerServerEvent("requestServerInfo", 1, {});
    }
    else if (resName == "province_lifts" && resourceRootId != 0)
    {
        TriggerServerEvent("lift:elevatorInit", resourceRootId, {});
    }
    else if (resName == "province_cs" && resourceRootId != 0)
    {
        TriggerServerEvent("province_cs:onRequestUpdateData", resourceRootId, {});
        TriggerServerEvent("province_cs:onRequestUpdateShopCS", resourceRootId, {});
    }
    else if (resName == "province_afktimer" && resourceRootId != 0)
    {
        TriggerServerEventBool("afktimer:toggleAFK", resourceRootId, false);
    }
    else if (resName == "province_carshop" && resourceRootId != 0)
    {
        TriggerServerEvent("onOpenGui", resourceRootId, {});
        TriggerServerEvent("carshop:requestCarPlateSlots", resourceRootId, {});
    }
    else if (resName == "admin" && localElementId_ != ((1u << 17) - 1u))
    {
        TriggerServerEvent("aPermissions", localElementId_, {});
    }
    else if (resName == "demprovince" && resourceRootId != 0)
    {
        TriggerServerEvent("requestLODsClient", resourceRootId, {});
    }
    else if (resName == "province_realdriveby" && localElementId_ != ((1u << 17) - 1u))
    {
        TriggerServerEvent("driveby_clientScriptLoaded", localElementId_, {});
    }
    else if (resName == "province_bank" && resourceRootId != 0)
    {
        TriggerServerEvent("bank:reqestAccountInfo", resourceRootId, {});
    }
    else if (resName == "province_donate" && resourceRootId != 0)
    {
        TriggerServerEvent("donate:requestBonus", resourceRootId, {});
    }
    else if (resName == "province_garage" && resourceRootId != 0)
    {
        TriggerServerEvent("garage:initOnStart", resourceRootId, {});
    }
    else if (resName == "Province_RP" && resourceRootId != 0)
    {
        TriggerServerEvent("houses:request_getOwnedHouses", resourceRootId, {});
    }
    */
    if (resName == "province_auth" || resName == "Province_RP")
    {
        provinceRpStarted_ = std::chrono::steady_clock::now();
        std::cout << "\n=======================================================\n";
        std::cout << ">>> " << resName << " resource started (root=" << resourceRootId << ")\n";
        std::cout << "=======================================================\n\n";
    }
}

void MtaClient::SendMaintenance()
{
    const auto now = std::chrono::steady_clock::now();
    if (now - lastStatus_ >= 2s)
    {
        lastStatus_ = now;
        SendPlayerNetworkStatus();
    }
    if (!config_.noPureSync && loggedIn_ && spawnSelected_ && now - lastPureSync_ >= 100ms)
    {
        lastPureSync_ = now;
        SendPlayerPureSync();
    }
}

void MtaClient::Trace(const std::vector<std::uint8_t>& packet) const
{
    if (!config_.traceHex)
        return;
    std::ostringstream out;
    out << "RX HEX";
    for (const auto byte : packet)
        out << ' ' << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    std::cout << out.str() << '\n';
}

void MtaClient::Fail(const std::string& reason)
{
    std::cerr << "FAILED: " << reason << '\n';
    state_ = State::Failed;
}
