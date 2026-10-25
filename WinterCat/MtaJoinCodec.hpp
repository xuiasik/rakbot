#pragma once

#include "ClientConfig.hpp"

#include <BitStream.h>

#include <string>

namespace mta
{
void BuildJoinData(const ClientConfig& config, RakNet::BitStream& stream);
bool RunJoinCodecSelfTest(std::string& error);
}
