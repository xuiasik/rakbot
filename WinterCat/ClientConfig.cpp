#include "ClientConfig.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <unordered_set>

namespace
{
template<class T>
T ParseUnsigned(std::string_view text, std::string_view name)
{
    unsigned long value = 0;
    const int base = text.starts_with("0x") || text.starts_with("0X") ? 16 : 10;
    if (base == 16)
        text.remove_prefix(2);
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value > static_cast<unsigned long>(std::numeric_limits<T>::max()))
        throw std::runtime_error("invalid value for " + std::string(name));
    return static_cast<T>(value);
}

std::string_view RequireValue(int& index, int argc, char** argv)
{
    if (++index >= argc)
        throw std::runtime_error("missing value for " + std::string(argv[index - 1]));
    return argv[index];
}

bool IsUpperHex(std::string_view value, std::size_t length)
{
    return value.size() == length && std::all_of(value.begin(), value.end(), [](unsigned char c)
    {
        return std::isdigit(c) != 0 || c >= 'A' && c <= 'F';
    });
}

template<std::size_t Size>
std::string RandomUpperHex()
{
    std::array<std::uint8_t, Size> bytes{};
    if(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("BCryptGenRandom failed for random identities");

    constexpr char digits[] = "0123456789ABCDEF";
    std::string value(bytes.size() * 2, '0');
    for(std::size_t i = 0; i < bytes.size(); ++i)
    {
        value[i * 2] = digits[bytes[i] >> 4];
        value[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    return value;
}

std::size_t RandomIndex(std::size_t count)
{
    std::uint32_t value = 0;
    if(BCryptGenRandom(nullptr, reinterpret_cast<unsigned char*>(&value), sizeof(value),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("BCryptGenRandom failed for random nickname");
    return value % count;
}

std::string RandomHumanNickname()
{
    static constexpr std::string_view firstNames[] =
    {
        "Alex", "Andrey", "Anton", "Artem", "Bogdan", "Daniil", "Denis", "Dmitry",
        "Egor", "Gleb", "Ilya", "Ivan", "Kirill", "Maksim", "Mark", "Matvey",
        "Mikhail", "Nikita", "Oleg", "Pavel", "Roman", "Sergey", "Timur", "Vadim",
        "Viktor", "Vlad", "Yaroslav", "Alina", "Anna", "Daria", "Diana", "Elena",
        "Eva", "Irina", "Karina", "Katya", "Lera", "Maria", "Nika", "Sofia"
    };
    static constexpr std::string_view lastNames[] =
    {
        "Bondar", "Boyko", "Dovhan", "Fedorenko", "Gonchar", "Havrylenko", "Klymenko", "Koval",
        "Kravchenko", "Kuzmenko", "Lysenko", "Marchenko", "Melnik", "Moroz", "Novak", "Oliynyk",
        "Pavlenko", "Petrenko", "Polishchuk", "Romanenko", "Rudenko", "Savchenko", "Shevchuk", "Sydorenko",
        "Tkachenko", "Vasylenko", "Volkov", "Zaychenko", "Bilenko", "Chernenko", "Dubov", "Karpov",
        "Kozak", "Levchenko", "Mazur", "Orlov", "Panchenko", "Sokolov", "Tarasenko", "Yurchenko"
    };
    static std::mutex nickMutex;
    static std::unordered_set<std::string> issuedNicks;

    constexpr auto firstCount = sizeof(firstNames) / sizeof(firstNames[0]);
    constexpr auto lastCount = sizeof(lastNames) / sizeof(lastNames[0]);
    for(unsigned attempt = 0; attempt < 128; ++attempt)
    {
        std::string nick = std::string(firstNames[RandomIndex(firstCount)]) + '_' +
            std::string(lastNames[RandomIndex(lastCount)]);
        std::lock_guard lock(nickMutex);
        if(issuedNicks.insert(nick).second) return nick;
    }
    return "Player_" + RandomUpperHex<4>();
}

}

ClientConfig ParseCommandLine(int argc, char** argv)
{
    ClientConfig config;
    for (int i = 1; i < argc; ++i)
    {
        const std::string_view option = argv[i];
        if (option == "--host") config.host = RequireValue(i, argc, argv);
        else if (option == "--port") config.port = ParseUnsigned<std::uint16_t>(RequireValue(i, argc, argv), option);
        else if (option == "--nick") config.nick = RequireValue(i, argc, argv);
        else if (option == "--serial") config.serial = RequireValue(i, argc, argv);
        else if (option == "--private-serial") config.privateSerial = RequireValue(i, argc, argv);
        else if (option == "--random-identities") config.randomIdentities = true;
        else if (option == "--random-nick") config.randomNick = true;
        else if (option == "--password") {
            const auto val = RequireValue(i, argc, argv);
            config.password = val;
            config.loginPassword = val;
        }
        else if (option == "--pass" || option == "--auth-pass" || option == "--account-password") {
            config.loginPassword = RequireValue(i, argc, argv);
        }
        else if (option == "--connect-timeout") config.connectTimeoutMs = ParseUnsigned<std::uint32_t>(RequireValue(i, argc, argv), option);
        else if (option == "--hold") config.holdSeconds = ParseUnsigned<std::uint32_t>(RequireValue(i, argc, argv), option);
        else if (option == "--instances") config.instances = ParseUnsigned<std::uint16_t>(RequireValue(i, argc, argv), option);
        else if (option == "--trace-hex") config.traceHex = true;
        else if (option == "--transport-only") config.transportOnly = true;
        else if (option == "--no-puresync") config.noPureSync = true;
        else if (option == "--login" || option == "--account-login") config.loginUsername = RequireValue(i, argc, argv);
        else if (option == "--latent-transfer" || option == "--latent-packet" || option == "--latent-lua-event")
            config.latentTransfer = true;
        else if (option == "--self-test") config.selfTest = true;
        else if (option == "--help" || option == "-h") { PrintUsage(); std::exit(0); }
        else throw std::runtime_error("unknown option: " + std::string(option));
    }

    if(!config.randomNick && (config.nick.size() < 1 || config.nick.size() > 22))
        throw std::runtime_error("nickname must contain 1..22 bytes");
    if(!config.selfTest && !config.randomIdentities)
    {
        if(!IsUpperHex(config.serial, 32))
            throw std::runtime_error("--serial must contain exactly 32 uppercase hexadecimal characters");
        if(config.privateSerial.empty())
            config.privateSerial = RandomUpperHex<32>();
        else if(!IsUpperHex(config.privateSerial, 64))
            throw std::runtime_error("--private-serial must contain exactly 64 uppercase hexadecimal characters");
    }
    if(config.instances < 1 || config.instances > 800)
        throw std::runtime_error("--instances must be in range 1..800");
    if (config.host.empty())
        throw std::runtime_error("host cannot be empty");
    return config;
}

void RandomizeClientInstance(ClientConfig& config)
{
    if(config.randomIdentities)
    {
        config.serial = RandomUpperHex<16>();
        config.privateSerial = RandomUpperHex<32>();
    }
    if(config.randomNick)
        config.nick = RandomHumanNickname();
}

void PrintUsage()
{
    std::cout
        << "WinterCat --host 185.71.66.81 --port 22003 (--random-identities | --serial TEXT --private-serial TEXT) [options]\n"
        << "  --host HOST             IPv4 literal or DNS hostname\n"
        << "  --password TEXT          MTA server password (MD5 is sent)\n"
        << "  --serial TEXT            required 32-char Province serial\n"
        << "  --private-serial TEXT    required 64-char Province private serial\n"
        << "  --random-identities      generate fresh CSPRNG public/private serials\n"
        << "  --random-nick            generate a fresh CSPRNG-backed nickname\n"
        << "  --instances COUNT        run 1..32 independent clients concurrently\n"
        << "  --connect-timeout MS     default: 15000\n"
        << "  --hold SECONDS           0 keeps the session until Ctrl-C\n"
        << "  --transport-only         stop after RakNet transport connect\n"
        << "  --no-puresync            keep status heartbeat but skip 10 Hz puresync\n"
        << "  --latent-transfer        send the latent Lua-event reserve header after join\n"
        << "  --self-test              run transport and packet-codec golden tests\n"
        << "  --trace-hex              dump received packets\n";
}
