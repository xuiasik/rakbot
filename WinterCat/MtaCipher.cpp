#include "MtaCipher.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace
{
constexpr std::array<std::uint8_t, 16> kOfflineMagic{
    0x00, 0xFF, 0x00, 0xFF, 0xFE, 0xFE, 0xFE, 0xFE,
    0xFD, 0xFD, 0xFD, 0xFD, 0x78, 0x56, 0x34, 0x17
};
}

bool MtaCipher::InitializeFromOpenReply(const std::uint8_t* data, std::size_t size, std::string& error)
{
    ready_ = false;
    if (!data || size < 33 || data[0] != 10)
    {
        error = "malformed ID_OPEN_CONNECTION_REPLY";
        return false;
    }
    if (!std::equal(kOfflineMagic.begin(), kOfflineMagic.end(), data + 1))
    {
        error = "ID_OPEN_CONNECTION_REPLY has wrong offline magic";
        return false;
    }

    serverToken_.assign(data + 17, data + 33);
    std::vector<std::uint8_t> key;
    tag_.clear();
    mode_ = 0;
    idleIntervalUs_ = 0;
    pingIntervalUs_ = 0;
    lastEncryptedSendUs_ = 0;
    std::size_t offset = 33;
    if (offset < size && data[offset] == 0xED)
    {
        ++offset;
        bool terminated = false;
        while (offset < size)
        {
            const auto type = data[offset++];
            if (type == 0xDE)
            {
                terminated = true;
                break;
            }
            if (offset >= size)
            {
                error = "truncated ServerHello TLV";
                return false;
            }
            const auto length = data[offset++];
            if (offset + length > size)
            {
                error = "ServerHello TLV exceeds datagram";
                return false;
            }
            if (type == 0x80 && length)
                mode_ = data[offset];
            else if (type == 0x6E)
                key.assign(data + offset, data + offset + length);
            else if (type == 0x1A)
                tag_.assign(data + offset, data + offset + length);
            else if (type == 0xA8 && length == 4)
                std::memcpy(&idleIntervalUs_, data + offset, 4);
            else if (type == 0xC8 && length == 4)
                std::memcpy(&pingIntervalUs_, data + offset, 4);
            offset += length;
        }
        if (!terminated)
        {
            error = "unterminated ServerHello";
            return false;
        }
    }

    for (std::size_t i = 0; i < sbox_.size(); ++i)
        sbox_[i] = static_cast<std::uint8_t>(i);

    if (!key.empty())
    {
        std::uint8_t j = 0;
        for (std::size_t i = 0; i < sbox_.size(); ++i)
        {
            j = static_cast<std::uint8_t>(j + sbox_[i] + key[i % key.size()]);
            std::swap(sbox_[i], sbox_[j]);
        }

        std::uint8_t i = 0;
        j = 0;
        for (unsigned drop = 0; drop < 1000; ++drop)
        {
            j = static_cast<std::uint8_t>(j + sbox_[i]);
            std::swap(sbox_[i], sbox_[j]);
            ++i;
        }
    }

    ready_ = true;
    return true;
}

bool MtaCipher::Decode(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& plain, std::string& error) const
{
    if (!ready_ || !data || !size)
    {
        error = "empty connected datagram";
        return false;
    }
    if (mode_ != 1)
    {
        plain.assign(data, data + size);
        return true;
    }

    if (tag_.size() > 5)
    {
        error = "connected datagram tag is longer than five bytes";
        return false;
    }

    const std::size_t header = tag_.size() + 3;
    if (size <= header || !std::equal(tag_.begin(), tag_.end(), data))
    {
        error = "invalid encrypted datagram header/tag";
        return false;
    }

    const auto storedCrc = static_cast<std::uint16_t>(data[tag_.size()] | (data[tag_.size() + 1] << 8));
    const auto seed = data[tag_.size() + 2];
    const auto* cipher = data + header;
    const auto cipherSize = size - header;
    if (Crc16(cipher, cipherSize) != storedCrc)
    {
        error = "encrypted datagram CRC16 mismatch";
        return false;
    }

    plain.resize(cipherSize);
    Crypt(cipher, cipherSize, seed, plain.data());
    return true;
}

int MtaCipher::Encode(const std::uint8_t* data, std::size_t size, std::uint8_t* output, std::size_t capacity)
{
    std::lock_guard lock(encodeMutex_);
    if (!ready_ || !data || !output)
        return 0;
    if (mode_ != 1)
    {
        if (size > capacity)
            return 0;
        std::memcpy(output, data, size);
        return static_cast<int>(size);
    }

    const auto tagSize = tag_.size() <= 5 ? tag_.size() : 0;
    const std::size_t total = tagSize + 3 + size;
    if (total > capacity)
        return 0;

    std::copy_n(tag_.begin(), tagSize, output);
    lcg_ = 214013u * lcg_ + 2531011u;
    const auto seed = static_cast<std::uint8_t>(lcg_ >> 16);
    auto* cipher = output + tagSize + 3;
    Crypt(data, size, seed, cipher);
    const auto crc = Crc16(cipher, size);
    output[tagSize] = static_cast<std::uint8_t>(crc);
    output[tagSize + 1] = static_cast<std::uint8_t>(crc >> 8);
    output[tagSize + 2] = seed;
    lastEncryptedSendUs_ = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    return static_cast<int>(total);
}

bool MtaCipher::RunSelfTests(std::string& error)
{
    std::array<std::uint8_t, 33> plainReply{};
    plainReply[0] = 10;
    std::copy(kOfflineMagic.begin(), kOfflineMagic.end(), plainReply.begin() + 1);
    MtaCipher plainCipher;
    if (!plainCipher.InitializeFromOpenReply(plainReply.data(), plainReply.size(), error) || plainCipher.Mode() != 0)
        return false;
    const std::array<std::uint8_t, 4> sample{0x26, 1, 2, 3};
    std::array<std::uint8_t, 64> encoded{};
    const auto plainSize = plainCipher.Encode(sample.data(), sample.size(), encoded.data(), encoded.size());
    std::vector<std::uint8_t> decoded;
    if (plainSize != static_cast<int>(sample.size()) || !std::equal(sample.begin(), sample.end(), encoded.begin()) ||
        !plainCipher.Decode(encoded.data(), plainSize, decoded, error) || !std::equal(sample.begin(), sample.end(), decoded.begin()))
    {
        error = "mode-0 transport round trip failed";
        return false;
    }

    std::vector<std::uint8_t> reply(33);
    reply[0] = 10;
    std::copy(kOfflineMagic.begin(), kOfflineMagic.end(), reply.begin() + 1);
    const std::uint8_t hello[]{
        0xED, 0x80, 1, 1, 0x6E, 3, 1, 2, 3, 0x1A, 2, 0xAA, 0xBB,
        0xA8, 4, 0x40, 0x0D, 0x03, 0, 0xC8, 4, 0x80, 0x84, 0x1E, 0,
        0x42, 2, 0xCA, 0xFE, 0xDE
    };
    reply.insert(reply.end(), std::begin(hello), std::end(hello));
    MtaCipher encryptedCipher;
    if (!encryptedCipher.InitializeFromOpenReply(reply.data(), reply.size(), error) || encryptedCipher.Mode() != 1 ||
        encryptedCipher.IdleIntervalUs() != 200000 || encryptedCipher.PingIntervalUs() != 2000000)
    {
        error = "mode-1 ServerHello parse failed";
        return false;
    }
    const auto encryptedSize = encryptedCipher.Encode(sample.data(), sample.size(), encoded.data(), encoded.size());
    constexpr std::array<std::uint8_t, 9> expected{0xAA, 0xBB, 0xBD, 0x5C, 0x29, 0x08, 0xFF, 0xFE, 0xB8};
    if (encryptedSize != static_cast<int>(expected.size()) || !std::equal(expected.begin(), expected.end(), encoded.begin()) ||
        !encryptedCipher.Decode(encoded.data(), encryptedSize, decoded, error) || decoded.size() != sample.size() ||
        !std::equal(sample.begin(), sample.end(), decoded.begin()))
    {
        error = "mode-1 transport round trip failed";
        return false;
    }
    return true;
}

int MtaCipher::Transform(void* context, const unsigned char* input, unsigned int inputLength,
    unsigned char* output, unsigned int outputCapacity)
{
    return context ? static_cast<MtaCipher*>(context)->Encode(input, inputLength, output, outputCapacity) : 0;
}

std::uint16_t MtaCipher::Crc16(const std::uint8_t* data, std::size_t size)
{
    std::uint16_t crc = 0;
    for (std::size_t i = 0; i < size; ++i)
    {
        crc ^= static_cast<std::uint16_t>(data[i]) << 8;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = static_cast<std::uint16_t>((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0));
    }
    return crc;
}

void MtaCipher::Crypt(const std::uint8_t* input, std::size_t size, std::uint8_t seed, std::uint8_t* output) const
{
    for (std::size_t index = 0; index < size; ++index)
    {
        const auto a = sbox_[static_cast<std::uint8_t>(index)];
        seed = static_cast<std::uint8_t>(seed + a);
        output[index] = static_cast<std::uint8_t>(input[index] ^ sbox_[static_cast<std::uint8_t>(a + sbox_[seed])]);
    }
}
