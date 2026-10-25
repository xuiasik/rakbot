#include "ClientConfig.hpp"
#include "MtaJoinCodec.hpp"
#include "MtaClient.hpp"
#include "MtaCipher.hpp"
#include "ProvincePackets.hpp"

#include <windows.h>

#include <chrono>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>
#include <utility>

namespace
{
struct InstanceLaunchSignal
{
    std::promise<bool> promise;
    std::atomic<bool> completed{};

    void Complete(bool headerSent)
    {
        if(!completed.exchange(true)) promise.set_value(headerSent);
    }
};

struct InstanceProgress
{
    explicit InstanceProgress(std::uint16_t totalInstances) : total(totalInstances)
    {
        UpdateTitle(0);
    }

    void LatentHeaderSent()
    {
        UpdateTitle(sent.fetch_add(1) + 1);
    }

    void UpdateTitle(std::uint16_t count) const
    {
        wchar_t title[128]{};
        swprintf_s(title, L"WinterCat - Connected: %hu/%hu", count, total);
        SetConsoleTitleW(title);
    }

    const std::uint16_t total;
    std::atomic<std::uint16_t> sent{};
};

int RunInstance(ClientConfig config, std::uint16_t instanceNumber,
    const std::shared_ptr<InstanceLaunchSignal>& signal = {},
    const std::shared_ptr<InstanceProgress>& progress = {})
{
    try
    {
        RandomizeClientInstance(config);
        constexpr auto retryDelay = std::chrono::seconds(10);
        for(unsigned attempt = 1;; ++attempt)
        {
            bool headerSent = false;
            if(attempt > 1)
                std::cout << "instance " << instanceNumber << " reconnect attempt " << attempt << " starting\n";

            try
            {
                auto attemptConfig = config;
                MtaClient client(std::move(attemptConfig), [&headerSent, signal, progress]
                {
                    headerSent = true;
                    if(progress) progress->LatentHeaderSent();
                    if(signal) signal->Complete(true);
                });
                const int result = client.Run();
                if(!config.latentTransfer || headerSent) return result;

                std::cerr << "instance " << instanceNumber
                          << " failed before LATENT header on attempt " << attempt
                          << " (exit=" << result << "); reconnecting in 10 seconds\n";
            }
            catch(const std::exception& error)
            {
                if(!config.latentTransfer || headerSent) throw;
                std::cerr << "instance " << instanceNumber
                          << " entry attempt " << attempt << " threw: " << error.what()
                          << "; reconnecting in 10 seconds\n";
            }
            std::this_thread::sleep_for(retryDelay);
        }
    }
    catch(...)
    {
        if(signal) signal->Complete(false);
        throw;
    }
}
}

int main(int argc, char** argv)
{
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);
    try
    {
        auto config = ParseCommandLine(argc, argv);
        if(config.selfTest)
        {
            std::string error;
            if(!province::RunPacketSelfTests(error))
                throw std::runtime_error("packet self-test failed: " + error);
            if(!mta::RunJoinCodecSelfTest(error))
                throw std::runtime_error("JOIN-codec self-test failed: " + error);
            if(!MtaCipher::RunSelfTests(error))
                throw std::runtime_error("transport-cipher self-test failed: " + error);
            std::cout << "transport cipher and packet codec self-tests passed\n";
            return 0;
        }
        const auto progress = config.latentTransfer ? std::make_shared<InstanceProgress>(config.instances) : nullptr;
        if(config.instances == 1)
            return RunInstance(std::move(config), 1, {}, progress);

        const auto count = config.instances;
        std::cout << "launching " << count << " independent client instances\n";
        std::vector<std::future<int>> clients;
        clients.reserve(count);
        for(std::uint16_t index = 0; index < count; ++index)
        {
            auto instance = config;
            instance.instances = 1;
            auto signal = config.latentTransfer ? std::make_shared<InstanceLaunchSignal>() : nullptr;
            auto ready = signal ? signal->promise.get_future() : std::future<bool>{};
            const auto instanceNumber = static_cast<std::uint16_t>(index + 1);
            clients.emplace_back(std::async(std::launch::async, [instance = std::move(instance), instanceNumber, signal, progress]() mutable
            {
                return RunInstance(std::move(instance), instanceNumber, signal, progress);
            }));

            if(signal && index + 1 < count)
            {
                std::cout << "instance " << (index + 1) << '/' << count
                          << " launched; waiting for LATENT header before next connect\n";
                if(!ready.get())
                {
                    std::cerr << "instance " << (index + 1)
                              << " exited before sending LATENT header; remaining instances will not start\n";
                    break;
                }
                std::cout << "instance " << (index + 1)
                          << " sent LATENT header; opening next launch gate\n";
            }
        }

        unsigned failures = 0;
        for(std::size_t index = 0; index < clients.size(); ++index)
        {
            const int result = clients[index].get();
            std::cout << "instance " << (index + 1) << '/' << count << " exit=" << result << "\n";
            failures += result != 0;
        }
        const auto skipped = count - clients.size();
        std::cout << "instance summary: passed=" << (clients.size() - failures)
                  << " failed=" << failures << " not-launched=" << skipped << "\n";
        return failures || skipped ? 3 : 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "error: " << error.what() << "\n\n";
        PrintUsage();
        return 1;
    }
}
