# WinterCat

Win32/x86 RakNet client for the MTA Province.
It implements the custom MTA transport, RakNet 3.25 reliability, Province JOIN,
and idle session maintenance. Packet 110/111 codecs are retained for offline
analysis, but the live client deliberately neither sends 110 nor answers 111.

## Province profile

- Outer library version: `1.6.0-5.23093.0`
- Upper client version: `1.6.0-5.00000.0`
- Network bitstream: `140`
- Version tuple: `1.6.0-5`
- Build/revision: `23093 / 0`
- Netcode/MTA/gameplay bitstream: `0x41DA / 0x0160 / 0x008C`
- Active Province ReliabilityLayer MTU: `1188`
- RakNet raw mapping: `wireId = logicalId + 99`

The values above were recovered from the currently opened Province `netc.dll`
and `client.dll` IDBs. 

## Packets 110 and 111

The recovered six-part packet-110 codec uses priority/reliability/channel
`0/3/0`. Module MD5 values come from the installed Province files under
`C:\Province Games`; machine-profile fields use a coherent random fixture.

Incoming packet 111 is decrypted and restricted to
`HKCU\Software\2RAMB0T` values `Remnant`, `MapRegion`, and `MapSize`.
The offline packet-111 codec can produce the captured missing-value form, but
the current live path only logs and ignores packet 111.

The app-level AES parameters are the values captured by runtime hooks from the
target Province build. They are separate from the outer ServerHello transport
cipher and must be revalidated when either target DLL changes.

## Build and test

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' .\WinterCat.sln /m /p:Configuration=Release /p:Platform=Win32
.\bin\Release\WinterCat.exe --self-test
```

The self-test checks the connected transport's mode-zero/mode-one parsing,
first LCG seed, CRC and cipher round trip, plus captured packet-111 vectors,
packet-110 envelopes, AES round trips and installed Province module hashes.

## Run

Edit and start `bin\Release\run-connect.bat`. By default `RANDOM_IDENTITIES=1`
generates fresh CSPRNG uppercase-hex public32/private64 identities inside the
process, so neither value is read from the registry or exposed on the command
line. Set the switch to `0` to use the fixed BAT values instead.

`--hold 0` keeps the client running until it is stopped. `--trace-hex`
enables packet dumps, and `--transport-only` stops before the MTA JOIN.
`--instances N --random-nick` runs up to 32 independent clients concurrently;
the supplied BAT currently launches five random-identity/random-nick clients
for a 60-second hold.

Live 2026-08-15 tests reached ID10, ID14, sent the 9336-bit Province JOIN and
received `SERVER_JOINEDGAME`. Two additional runs used independent random
public32/private64 pairs; both joined and held the session for five seconds.
Logical packets 110 and 111 remained disabled throughout all acceptance tests.
A five-instance follow-up also completed a full 60-second hold for every client
(`passed=5 failed=0`). The server sent logical 111 requests during that minute;
WinterCat ignored them and sent no replies without losing any connection.

## License

GPL-2.0-or-later. See `LICENSE` and `third_party/raknet-legacy/ORIGIN.md`.
