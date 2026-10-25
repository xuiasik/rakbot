# RakNet legacy source provenance

The files in `Source/` are RakNet 3.25, vendored from the DarkflameServer repository:

- Repository: https://github.com/DarkflameUniverse/DarkflameServer
- Commit: `8f2004c9a33e16979eda52a5347867249c0ead0a`
- Original path: `thirdparty/raknet/Source`
- Version marker: `thirdparty/raknet/version.txt` (`RakNet 3.25`)

RakNet source headers offer GPL version 2 or, at the user's option, any later version. WinterCat uses that option.

WinterCat carries three deliberate wire-compatibility changes relative to that source snapshot:

1. `RakNetDefines.h` enables `__GET_TIME_64BIT`, matching the exact ProjectEagle `net.dll` ABI.
2. `ReliabilityLayer.h/.cpp` add an outgoing datagram-transform callback.
3. The callback wraps fully formed RakNet datagrams in the independently implemented MTA cipher/CRC envelope before UDP send.

The `RakNetLegacy.vcxproj` builds only the source subset required by this client. No prebuilt RakNet binary is used.
