class RakPeer;

// ReliabilityLayer is driven synchronously by WinterCat; SocketLayer's RakPeer receive callback is never used.
void ProcessNetworkPacket(const unsigned int, const unsigned short, const char*, const int, RakPeer*, unsigned)
{
}
