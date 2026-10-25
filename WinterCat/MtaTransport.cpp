#include "MtaTransport.hpp"

#include <ws2tcpip.h>

#include <GetTime.h>
#include <RakMemoryOverride.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;

namespace
{
constexpr std::array<std::uint8_t, 16> kOfflineMagic{
    0x00, 0xFF, 0x00, 0xFF, 0xFE, 0xFE, 0xFE, 0xFE,
    0xFD, 0xFD, 0xFD, 0xFD, 0x78, 0x56, 0x34, 0x17
};
constexpr int kMtu = 1188;
constexpr unsigned kOpenRequestCount = 120;

std::uint64_t ClockMicroseconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

void AppendU32(std::vector<std::uint8_t>& packet, std::uint32_t value)
{
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
    packet.insert(packet.end(), bytes, bytes + 4);
}

void GenerateLocalToken(std::array<std::uint8_t, 16>& token)
{
    std::array<std::uint32_t, 4> words{};
    words[0] = static_cast<std::uint32_t>(ClockMicroseconds());
    for(std::size_t word = 1; word < words.size(); ++word)
    {
        Sleep(1);
        Sleep(0);
        words[word] = static_cast<std::uint32_t>(ClockMicroseconds());
        for(unsigned shift = 0; shift < 28; shift += 4)
        {
            const auto before = ClockMicroseconds();
            Sleep(1);
            Sleep(0);
            const auto delta = static_cast<std::uint32_t>(ClockMicroseconds() - before);
            words[word] ^= static_cast<std::uint32_t>(delta << 28) >> shift;
        }
    }
    std::memcpy(token.data(), words.data(), token.size());
}
}

MtaTransport::MtaTransport()
{
    if (WSAStartup(MAKEWORD(2, 2), &wsa_) != 0)
        throw std::runtime_error("WSAStartup failed");
    reliability_.SetTimeoutTime(35000);
    reliability_.SetDatagramTransform(&MtaCipher::Transform, &cipher_);
    localAddresses_.fill(SystemAddress{0xFFFFFFFFu, 0});
    serverAddresses_.fill(UNASSIGNED_SYSTEM_ADDRESS);
}

MtaTransport::~MtaTransport()
{
    if (socket_ != INVALID_SOCKET)
        closesocket(socket_);
    WSACleanup();
}

bool MtaTransport::Connect(const std::string& host, std::uint16_t port)
{
    if (state_ != State::Idle)
        return false;
    GenerateLocalToken(localToken_);
    if(!OpenSocket(host, port)) return false;
    openRequestsSent_ = 0;
    lastControlPingUs_ = 0;
    lastOpenRequest_ = std::chrono::steady_clock::now() - 500ms;
    state_ = State::AwaitOpenReply;
    return true;
}

void MtaTransport::Disconnect()
{
    if (state_ == State::Connected)
    {
        RakNet::BitStream stream;
        stream.Write(static_cast<std::uint8_t>(19));
        Send(stream, SYSTEM_PRIORITY, RELIABLE_ORDERED);
        const auto deadline = std::chrono::steady_clock::now() + 150ms;
        while (state_ == State::Connected && std::chrono::steady_clock::now() < deadline)
        {
            Poll();
            std::this_thread::sleep_for(1ms);
        }
    }
    state_ = State::Idle;
}

void MtaTransport::Poll()
{
    if (state_ == State::Failed || state_ == State::Idle)
        return;

    std::array<std::uint8_t, 8192> buffer{};
    for (;;)
    {
        sockaddr_in from{};
        int fromLength = sizeof(from);
        const int length = recvfrom(socket_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
            reinterpret_cast<sockaddr*>(&from), &fromLength);
        if (length == SOCKET_ERROR)
        {
            const int code = WSAGetLastError();
            if (code != WSAEWOULDBLOCK && code != WSAEMSGSIZE)
                Fail("recvfrom failed: " + std::to_string(code));
            break;
        }
        if (length == 0)
            break;

        if (from.sin_addr.s_addr != remote_.binaryAddress || ntohs(from.sin_port) != remote_.port)
            continue;

        if (state_ == State::AwaitOpenReply)
            std::cout << "RakNet OFFLINE IN id=" << static_cast<unsigned>(buffer[0]) << " bytes=" << length << "\n";

        if (state_ == State::AwaitOpenReply)
        {
            if (length > 512)
                continue;
            if (length == 34 && buffer[0] == 95 &&
                std::equal(kOfflineMagic.begin(), kOfflineMagic.end(), buffer.begin() + 2))
            {
                Fail("RakNet protocol mismatch; server requires " + std::to_string(buffer[1]));
                break;
            }
            if (buffer[0] == 10 && !HandleOpenReply(buffer.data(), static_cast<std::size_t>(length)))
                break;
        }
        else
            HandleConnectedDatagram(buffer.data(), static_cast<std::size_t>(length));
    }

    if (state_ == State::AwaitOpenReply && std::chrono::steady_clock::now() - lastOpenRequest_ > 500ms)
    {
        if(openRequestsSent_ < kOpenRequestCount)
            SendOpenRequest();
        else
        {
            incoming_.push_back({15});
            state_ = State::Idle;
        }
    }

    if (state_ == State::AwaitConnectionAccepted || state_ == State::Connected)
    {
        reliability_.Update(socket_, remote_, kMtu, RakNet::GetTimeNS(), 0, plugins_);
        DrainReliability();
        PollRawControls();
        if (reliability_.IsDeadConnection())
            Fail("RakNet reliability timeout");
    }

    if (state_ == State::Connected && std::chrono::steady_clock::now() - lastPing_ >= 1000ms)
        SendConnectedPing();
}

bool MtaTransport::Receive(std::vector<std::uint8_t>& packet)
{
    if (incoming_.empty())
        return false;
    packet = std::move(incoming_.front());
    incoming_.pop_front();
    return true;
}

bool MtaTransport::Send(RakNet::BitStream& stream, PacketPriority priority, PacketReliability reliability, std::uint8_t channel)
{
    return Send(stream.GetData(), stream.GetNumberOfBitsUsed(), priority, reliability, channel);
}

bool MtaTransport::Send(const std::uint8_t* data, BitSize_t bits, PacketPriority priority, PacketReliability reliability, std::uint8_t channel)
{
    if ((state_ != State::AwaitConnectionAccepted && state_ != State::Connected) || !data || !bits)
        return false;
    return reliability_.Send(reinterpret_cast<char*>(const_cast<std::uint8_t*>(data)), bits, priority, reliability,
        channel, true, kMtu, RakNet::GetTimeNS());
}

bool MtaTransport::OpenSocket(const std::string& host, std::uint16_t port)
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result)
    {
        Fail("cannot resolve IPv4 host " + host);
        return false;
    }
    const sockaddr_in* selected = nullptr;
    for(auto* entry = result; entry; entry = entry->ai_next)
    {
        if(entry->ai_family != AF_INET || entry->ai_addrlen < sizeof(sockaddr_in)) continue;
        const auto* address = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
        selected = address;
        break;
    }
    if(!selected)
    {
        freeaddrinfo(result);
        Fail("DNS host has no IPv4 address: " + host);
        return false;
    }
    remote_.binaryAddress = selected->sin_addr.s_addr;
    remote_.port = port;
    std::array<char, INET_ADDRSTRLEN> resolved{};
    inet_ntop(AF_INET, &selected->sin_addr, resolved.data(), static_cast<socklen_t>(resolved.size()));
    freeaddrinfo(result);
    std::cout << "Resolved target: " << host << " -> " << resolved.data() << ':' << port << "\n";

    auto createSocket = [this]()
    {
        socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if(socket_ == INVALID_SOCKET) return false;
        const int receiveBuffer = 0x40000;
        const int sendBuffer = 0x4000;
        const BOOL broadcast = TRUE;
        const linger disabledLinger{};
        u_long nonBlocking = 1;
        setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&receiveBuffer), sizeof(receiveBuffer));
        setsockopt(socket_, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&disabledLinger), sizeof(disabledLinger));
        setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&sendBuffer), sizeof(sendBuffer));
        ioctlsocket(socket_, FIONBIO, &nonBlocking);
        setsockopt(socket_, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));
        return true;
    };
    if(!createSocket())
    {
        Fail("socket creation failed");
        return false;
    }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if(bind(socket_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR)
    {
        int code = WSAGetLastError();
        if(code == WSAEADDRINUSE)
        {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
            Sleep(100);
            if(createSocket() && bind(socket_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != SOCKET_ERROR)
                code = 0;
            else
                code = WSAGetLastError();
        }
        if(code)
        {
            Fail("UDP bind failed: " + std::to_string(code));
            return false;
        }
    }
    int localLength = sizeof(local);
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&local), &localLength) == 0)
        localPort_ = ntohs(local.sin_port);
    DiscoverLocalAddresses();
    return true;
}

bool MtaTransport::SendOpenRequest()
{
    if (openRequestsSent_ == 0)
    {
        sockaddr_in aseTarget{};
        aseTarget.sin_family = AF_INET;
        aseTarget.sin_port = htons(remote_.port + 123);
        aseTarget.sin_addr.s_addr = remote_.binaryAddress;
        const char aseQuery = 's';
        sendto(socket_, &aseQuery, 1, 0, reinterpret_cast<const sockaddr*>(&aseTarget), sizeof(aseTarget));
        std::cout << "MTA ASE port knock sent to port " << (remote_.port + 123) << "\n";
    }

    std::vector<std::uint8_t> request;
    request.reserve(64);
    request.push_back(9);
    request.push_back(4);
    request.insert(request.end(), localToken_.begin(), localToken_.end());
    request.insert(request.end(), kOfflineMagic.begin(), kOfflineMagic.end());
    const std::uint8_t clientHello[] = {
        0xED, 0xCA, 0x01, 0x01,
        0xA8, 0x04, 0xE8, 0x03, 0x00, 0x00,
        0xC8, 0x04, 0xE8, 0x03, 0x00, 0x00, 0xDE
    };
    request.insert(request.end(), std::begin(clientHello), std::end(clientHello));
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(remote_.port);
    target.sin_addr.s_addr = remote_.binaryAddress;
    int sent = 0;
    while(sent == 0)
        sent = sendto(socket_, reinterpret_cast<const char*>(request.data()), static_cast<int>(request.size()), 0,
            reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    ++openRequestsSent_;
    lastOpenRequest_ = std::chrono::steady_clock::now();
    std::cout << "RakNet OFFLINE OUT id=9 bytes=" << request.size() << " sent=" << sent << "\n";
    if(sent == SOCKET_ERROR)
        std::cout << "RakNet ID9 send error=" << WSAGetLastError() << " (netc continues retries)\n";
    return true;
}

bool MtaTransport::HandleOpenReply(const std::uint8_t* data, std::size_t size)
{
    std::string cipherError;
    if (!cipher_.InitializeFromOpenReply(data, size, cipherError))
    {
        Fail(std::move(cipherError));
        return false;
    }
    reliability_.SetDatagramTransformOverhead(cipher_.Mode() == 1 ? 3u : 0u);
    state_ = State::AwaitConnectionAccepted;
    return SendConnectedRequest();
}

bool MtaTransport::SendConnectedRequest()
{
    RakNet::BitStream stream;
    stream.Write(static_cast<std::uint8_t>(4));
    stream.WriteAlignedBytes(kOfflineMagic.data(), static_cast<unsigned int>(kOfflineMagic.size()));
    stream.WriteAlignedBytes(localToken_.data(), static_cast<unsigned int>(localToken_.size()));
    return Send(stream, SYSTEM_PRIORITY, RELIABLE);
}

bool MtaTransport::SendNewIncomingConnection()
{
    RakNet::BitStream stream;
    stream.Write(static_cast<std::uint8_t>(17));
    WriteAddress(stream, remote_.binaryAddress, remote_.port);
    for(const auto& address : localAddresses_)
        WriteAddress(stream, address.binaryAddress, address.port);
    return Send(stream, SYSTEM_PRIORITY, RELIABLE_ORDERED);
}

bool MtaTransport::ParseConnectionAccepted(const std::vector<std::uint8_t>& packet)
{
    if(packet.size() < 69) return false;
    RakNet::BitStream stream(const_cast<unsigned char*>(packet.data()), static_cast<unsigned int>(packet.size()), false);
    stream.IgnoreBits(8);
    auto readAddress = [&stream](SystemAddress& address)
    {
        std::uint32_t hidden{};
        std::uint16_t networkPort{};
        if(!stream.ReadBits(reinterpret_cast<unsigned char*>(&hidden), 32, true) ||
            !stream.ReadBits(reinterpret_cast<unsigned char*>(&networkPort), 16, true))
            return false;
        address.binaryAddress = ~hidden;
        address.port = ntohs(networkPort);
        return true;
    };
    if(!readAddress(externalAddress_) || !stream.Read(systemIndex_)) return false;
    for(auto& address : serverAddresses_)
    {
        if(!readAddress(address)) return false;
    }
    return true;
}

void MtaTransport::DiscoverLocalAddresses()
{
    localAddresses_.fill(SystemAddress{0xFFFFFFFFu, 0});
    std::array<char, 80> name{};
    if(gethostname(name.data(), static_cast<int>(name.size())) == SOCKET_ERROR) return;
    const auto* host = gethostbyname(name.data());
    if(!host || host->h_addrtype != AF_INET || host->h_length != sizeof(std::uint32_t)) return;
    for(std::size_t i = 0; i < localAddresses_.size() && host->h_addr_list[i]; ++i)
    {
        std::memcpy(&localAddresses_[i].binaryAddress, host->h_addr_list[i], sizeof(std::uint32_t));
        localAddresses_[i].port = localPort_;
    }
}

bool MtaTransport::SendConnectedPing()
{
    RakNet::BitStream stream;
    stream.Write(static_cast<std::uint8_t>(0));
    stream.Write(static_cast<std::uint64_t>(GetTickCount64()));
    lastPing_ = std::chrono::steady_clock::now();
    return Send(stream, SYSTEM_PRIORITY, UNRELIABLE);
}

bool MtaTransport::SendRawControl(const std::uint8_t* data, std::size_t size)
{
    if (!data || !size || (state_ != State::AwaitConnectionAccepted && state_ != State::Connected))
        return false;
    std::array<std::uint8_t, 2048> encoded{};
    const auto encodedSize = cipher_.Encode(data, size, encoded.data(), encoded.size());
    if (encodedSize <= 0)
        return false;
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(remote_.port);
    target.sin_addr.s_addr = remote_.binaryAddress;
    return sendto(socket_, reinterpret_cast<const char*>(encoded.data()), encodedSize, 0,
        reinterpret_cast<const sockaddr*>(&target), sizeof(target)) == encodedSize;
}

bool MtaTransport::HandleRawControl(const std::vector<std::uint8_t>& packet)
{
    if (packet.size() < 18 || packet[0] != 38 || !std::equal(kOfflineMagic.begin(), kOfflineMagic.end(), packet.begin() + 1))
        return false;
    const auto type = packet[17];
    if (type == 0)
        return true;
    if (type == 1)
    {
        if (packet.size() < 22)
            return true;
        std::uint32_t echoedTick{};
        std::memcpy(&echoedTick, packet.data() + 18, 4);
        std::vector<std::uint8_t> reply;
        reply.reserve(26);
        reply.push_back(38);
        reply.insert(reply.end(), kOfflineMagic.begin(), kOfflineMagic.end());
        reply.push_back(2);
        AppendU32(reply, echoedTick);
        AppendU32(reply, static_cast<std::uint32_t>(GetTickCount64()));
        SendRawControl(reply.data(), reply.size());
        return true;
    }
    if (type == 2)
        return true;
    return true;
}

void MtaTransport::PollRawControls()
{
    const auto nowUs = ClockMicroseconds();
    const auto pingInterval = cipher_.PingIntervalUs();
    if (pingInterval && nowUs - lastControlPingUs_ >= pingInterval)
    {
        lastControlPingUs_ = nowUs;
        std::vector<std::uint8_t> packet;
        packet.reserve(22);
        packet.push_back(38);
        packet.insert(packet.end(), kOfflineMagic.begin(), kOfflineMagic.end());
        packet.push_back(1);
        AppendU32(packet, static_cast<std::uint32_t>(GetTickCount64()));
        SendRawControl(packet.data(), packet.size());
    }

    const auto idleInterval = cipher_.IdleIntervalUs();
    const auto lastEncryptedSend = cipher_.LastEncryptedSendUs();
    if (idleInterval && lastEncryptedSend && nowUs - lastEncryptedSend >= idleInterval)
    {
        std::array<std::uint8_t, 18> packet{};
        packet[0] = 38;
        std::copy(kOfflineMagic.begin(), kOfflineMagic.end(), packet.begin() + 1);
        SendRawControl(packet.data(), packet.size());
    }
}

void MtaTransport::HandleConnectedDatagram(const std::uint8_t* data, std::size_t size)
{
    std::vector<std::uint8_t> plain;
    std::string cipherError;
    if (!cipher_.Decode(data, size, plain, cipherError))
    {
        std::cout << "RakNet dropped connected datagram: " << cipherError << "\n";
        return;
    }
    if (!plain.empty() && plain[0] == 38)
    {
        HandleRawControl(plain);
        return;
    }
    constexpr std::array<std::uint8_t, 11> specialIds{1, 2, 4, 9, 10, 13, 15, 16, 18, 22, 95};
    if (plain.size() >= 17 && std::find(specialIds.begin(), specialIds.end(), plain[0]) != specialIds.end() &&
        std::equal(kOfflineMagic.begin(), kOfflineMagic.end(), plain.begin() + 1))
    {
        incoming_.push_back(std::move(plain));
        return;
    }
    if (!reliability_.HandleSocketReceiveFromConnectedPlayer(reinterpret_cast<const char*>(plain.data()),
        static_cast<unsigned int>(plain.size()), remote_, plugins_, kMtu))
    {
        incoming_.push_back(std::vector<std::uint8_t>{24});
        return;
    }
    DrainReliability();
}

void MtaTransport::DrainReliability()
{
    for (;;)
    {
        unsigned char* data = nullptr;
        const auto bits = reliability_.Receive(&data);
        if (!bits || !data)
            break;
        const auto bytes = static_cast<std::size_t>((bits + 7) / 8);
        std::vector<std::uint8_t> packet(data, data + bytes);
        RakNet::RakMemoryOverride::RakFree(data);
        HandlePayload(std::move(packet));
    }
}

void MtaTransport::HandlePayload(std::vector<std::uint8_t> packet)
{
    if (packet.empty())
        return;
    if (packet[0] == 14 && state_ == State::AwaitConnectionAccepted)
    {
        if(!ParseConnectionAccepted(packet))
        {
            Fail("malformed Province ID_CONNECTION_REQUEST_ACCEPTED");
            return;
        }
        state_ = State::Connected;
        if (!SendNewIncomingConnection())
        {
            Fail("failed to send ID_NEW_INCOMING_CONNECTION");
            return;
        }
        if (!SendConnectedPing())
        {
            Fail("failed to send immediate ID_CONNECTED_PING");
            return;
        }
        incoming_.push_back(std::move(packet));
        return;
    }
    if (packet[0] == 0 && packet.size() == 9)
    {
        RakNet::BitStream pong;
        pong.Write(static_cast<std::uint8_t>(3));
        pong.WriteAlignedBytes(packet.data() + 1, 8);
        pong.Write(static_cast<std::uint64_t>(GetTickCount64()));
        Send(pong, SYSTEM_PRIORITY, UNRELIABLE);
        return;
    }
    if (packet[0] == 3)
        return;
    incoming_.push_back(std::move(packet));
}

void MtaTransport::Fail(std::string reason)
{
    if (state_ != State::Failed)
        error_ = std::move(reason);
    state_ = State::Failed;
}

void MtaTransport::WriteAddress(RakNet::BitStream& stream, std::uint32_t addressNetworkOrder, std::uint16_t portHostOrder)
{
    const auto hiddenAddress = ~addressNetworkOrder;
    const auto networkPort = htons(portHostOrder);
    stream.WriteBits(reinterpret_cast<const unsigned char*>(&hiddenAddress), 32, true);
    stream.WriteBits(reinterpret_cast<const unsigned char*>(&networkPort), 16, true);
}
