#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

class MtaCipher
{
public:
    bool InitializeFromOpenReply(const std::uint8_t* data, std::size_t size, std::string& error);
    bool Decode(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& plain, std::string& error) const;
    int Encode(const std::uint8_t* data, std::size_t size, std::uint8_t* output, std::size_t capacity);
    bool IsReady() const { return ready_; }
    std::uint8_t Mode() const { return mode_; }
    std::uint32_t IdleIntervalUs() const { return idleIntervalUs_; }
    std::uint32_t PingIntervalUs() const { return pingIntervalUs_; }
    std::uint64_t LastEncryptedSendUs() const { return lastEncryptedSendUs_.load(); }
    const std::vector<std::uint8_t>& ServerToken() const { return serverToken_; }
    static bool RunSelfTests(std::string& error);

    static int Transform(void* context, const unsigned char* input, unsigned int inputLength,
        unsigned char* output, unsigned int outputCapacity);

private:
    static std::uint16_t Crc16(const std::uint8_t* data, std::size_t size);
    void Crypt(const std::uint8_t* input, std::size_t size, std::uint8_t seed, std::uint8_t* output) const;

    std::array<std::uint8_t, 256> sbox_{};
    std::vector<std::uint8_t> tag_;
    std::vector<std::uint8_t> serverToken_;
    std::uint32_t lcg_{1};
    std::atomic<std::uint64_t> lastEncryptedSendUs_{0};
    std::mutex encodeMutex_;
    std::uint32_t idleIntervalUs_{0};
    std::uint32_t pingIntervalUs_{0};
    std::uint8_t mode_{0};
    bool ready_{false};
};
