# Neware BTS Client 8.0 <-> BTS Server (TCP 8001) protocol

Status: **everything in this file is Inferred (static)**. It comes from reading the ILSpy output
under `vendor/decompiled/` (BTS Client 8.0.1.492, `Network.dll`/`NetworkBase.dll`/`Proto.dll`).
Nothing has been captured on the wire yet. Paths below are relative to `vendor/decompiled/`.
"Client.cs" means `Network/Network/Client.cs`.

Integers are **little-endian** unless stated otherwise (`BitConverter` on x86, `Packet.EncodeValue`
with the default `bBigEnd=false`, `NetworkBase/Network/Packet.cs:185-289`).

---

## 0. Which protocol generation an 8.0 client uses

| Generation | Class | Port | Used for |
|---|---|---|---|
| **BTSCS ("CS", 4S/7.x/8.x)** | `Network.Client : OnLineEx : OnLine` | **8001** (`Network/Network/OnLine.cs:28`) | Every non-BTS9 server node. `MainFrame.cs:14801-14814`: `if (!nodeEx.Is9s) { new Client(nodeEx.SvrIP, this) }` |
| BTS9 | `Network.Client9 : OnLine9` | 8002 (`Network/Network/OnLine9.cs:15`) | Only BTS9 nodes (`MainFrame.cs:14815-14826`). Not relevant here. |
| **BTSPLUS** (protobuf in the CS frame) | `BTSPLUS.PacketPlus` / `PacketPlusResp` | same socket, 8001 | A sub-protocol carried in the same frame (cmd 0xFE/0xFF/0x7F + cmdEx 0x02xx/0x82xx). The 8.0 client uses it with an 8.0 server for heartbeat, device list, select-device and device info, and for **all** channel control on DevType 27 (BTS85). |
| Legacy-proto (`PacketProto`) | `BTSCS.PacketProto` / `PacketProtoResp` | same socket | Protobuf payloads with a u32 length prefix, used for BTS82/83/84 start, jump83, RT82/83 and some others. |

So a Python client for 8.0 must use **one TCP connection to 8001** and speak three payload styles
in the same framing: fixed C structs (BTSCS), protobuf with a length prefix (`PacketProto`), and
BTSPLUS (header + protobuf, which can be split into chunks). Which style a command uses depends on
the server version and the device type (`DevType`, see section 4).

Client constants: `new Client(ip, this)` uses the default `ver = ClientVersion.client801 = 513 (0x0201)`
(`Client.cs:7681`, `Common/common/Version.cs:14`). Server version enum: `Server800=0x0800, Server801=0x0801,
Server802=0x0802` (`Version.cs:35-37`). Feature gates (`Client.cs:387-409, 536-570, 1006-1027`) compare
the build date inside `SvrVerStr`, the text in parentheses, e.g. `"...(2025.01.02)"`. For BtsServer 8.0.1.437,
whose README's newest entry is 2025.01.02, these gates should be **on**:
`Allow256Zwj` (>= 2020-10-07) selects SelectDevPlus, `AllowPlusHeartBeat` (>= 2019-09-06) selects the Plus heartbeat,
and `AllowUndefinedDev` (>= 2020-09-16, `OnLineEx.cs:795-832`) selects GetDevListPlus.
*Inferred. Confirm with a capture of the 0x0081 server-version packet.*

---

## 1. Packet framing

### 1.1 Common header (both directions)

| Offset | Size | Field | Notes / source |
|---|---|---|---|
| 0 | 8 | start flag `FF FF FF FF FF FF FF FF` | `Packet.cs:23`, `PacketDefine.cs:7-9` |
| 8 | 1 | `devID` (low byte of DevID) | `PacketSend.cs:10`. In BTSPLUS packets this is `DevID & 0xFF` (`BTSPLUS/PacketPlus.cs:77-88`) |
| 9 | 1 | `unitID` | `PacketSend.cs:11`. In BTSPLUS this is `DevID >> 8`, so DevID becomes a u16 (`PacketPlus.cs:81-86`) |
| 10 | 2 | `msgLen` u16 LE = **total frame length including start flag and trailer** | `Packet.cs:477-486` (written at [10..11]), `PacketDefine.cs:23` `LOC_CMD_LEN=10` |
| 12 | 1 | `cmd` | `PacketDefine.cs:25` `LOC_CMD=12` |
| … | … | type-specific header continues (1.2) | |
| len-2 | 1 | checksum | `Packet.cs:110-116` |
| len-1 | 1 | end flag `0x5A` | `Packet.cs:41`, `PacketDefine.cs:11` |

**Checksum:** an 8-bit sum (mod 256) of the bytes at indices `8 .. len-3`, that is, every byte after
the start flag and before the checksum byte. This includes the length field, which is filled in
first (`EncodeTail`: `SetPacketSize(count+2)`, then `CaculateSum(data, count)`; `Packet.cs:110-116, 488-496`).
The receiver tolerates a mismatch if the byte at `MsgLen-2` matches a recomputed sum (`Packet.cs:120-136`).

**Receive validation / resync** (`Packet.CheckPacket`, `Packet.cs:548-579`; `OnLineEx.OnReceive`, `Network/Network/OnLineEx.cs:850-1000`):
- need >= 15 bytes; bytes 0-7 must be `FF`; the len at [10] is read as **signed** i16; len >= 15; byte[len-1] == 0x5A.
- On garbage, the receiver drops one byte at a time until it sees 8×`FF` again. Frames with len >= 4096 are treated as invalid
  (`OnLineEx.cs:919-931`). The client's receive buffer is 4096 bytes (`OnLine.cs:19`). **Keep every frame below 4096 bytes.**
  BTSPLUS splits payloads larger than 3996 bytes into chunks (1.5).

### 1.2 Header variants (selected by `cmd` byte at [12])

`OnLineEx.OnReceive` dispatch (`OnLineEx.cs:879-909`):
- `cmd == 0xFE or 0xFF` → `cmdEx = u16 @ [14]` (`Packet.GetCmdExFromData`, `Packet.cs:507-514`). This is the **response layout**.
- `cmd == 0x7F` → `cmdEx = u16 @ [13]` (`Packet.GetCmdPlusExFromData`, `Packet.cs:516-523`). This is the **command layout**.
- anything else → plain `cmd` (only `0x80` = login response is handled, `Client.cs:7998-8017`).

| Layout | Bytes 12.. | Header length | Classes |
|---|---|---|---|
| A. plain cmd (C→S) | `[12] cmd` | 13 (`LEN_CMD_HEAD`) | `PacketSend` (`PacketSend.cs:7-14`), e.g. `PacketConnect` cmd 0x00 |
| B. plain resp (S→C) | `[12] cmd, [13] result` | 14 (`LEN_RESP_HEAD`) | `PacketResp` (`PacketResp.cs:21-29`), e.g. `PacketConnectResp` cmd 0x80 |
| C. **ext cmd (C→S)** | `[12] 0xFE, [13..14] cmdEx u16` | 15 (`LEN_CMD_EX_HEAD`) | `PacketSendEx` (`PacketSendEx.cs:23-30`) |
| D. **ext resp (S→C)** | `[12] 0xFE (or 0xFF), [13] result u8, [14..15] cmdEx u16` | 16 (`LEN_RESP_EX_HEAD`) | `PacketRespEx` (`PacketRespEx.cs:23-30`) |
| E. server-originated cmd (S→C) | `[12] 0x7F, [13..14] cmdEx u16` then layout C body | 15 | Decoded with `PacketPlus` (cmd layout), e.g. Plus RT 0x0202 (`Client.cs:14678-14687`) |

`result`: 0 = OK, 250 (0xFA) = failed/default, 255 = "see ResultEx" (Plus) (`PacketDefine.cs:35-39`, `PacketPlusResp.cs:110-133`).

Note that a client sends ext commands with `cmd=0xFE` and cmdEx at **[13]**, while the server's replies
carry cmdEx at **[14]** after the result byte. Server pushes that use the *command* layout (Plus RT)
must therefore use `cmd=0x7F`, otherwise the client could not find the cmdEx. That is an inference from the
dispatcher. **Open question P1.**

Response cmdEx convention: **resp = req | 0x8000** (e.g. Stop 0x000A → 0x800A, Plus GetDevInfo 0x0201 → 0x8201;
`BTSCS/PacketCS.cs:7-457`). Server pushes reuse codes from either range (0x0081, 0x009B, 0x0202, 0x80BE, 0x80D4…).

### 1.3 BTSCS fixed-struct body (most legacy commands)
After a layout C/D header, the body usually begins with `devType u8`, followed by command fields.
Example: `PacketStop` = `devType u8, channelMask u64` (`BTSCS/PacketStop.cs`, Encode). The device ID and unit ID
travel in header bytes 8 and 9 (`Packet.DevID` setter truncates to byte, `Packet.cs:43-53`).

### 1.4 Legacy protobuf body (`PacketProto` / `PacketProtoResp`)
`hdr(C or D) | protoLen u32 LE | protobuf bytes | cksum | 5A` (`BTSCS/PacketProto.cs:33-45`, `PacketProtoResp.cs:49-62`).
The header bytes devID, unitID and result are copied from the proto's own `DevType/DevID/UnitID/Result` fields.
There is **no** devType byte after the header. These messages are proto2 `BTSCS` package (`required` fields).

### 1.5 BTSPLUS body
Request (layout C or E), `BTSPLUS/PacketPlus.cs:120-141`:
```
[0..14]  hdr: FF×8, devID_lo, devID_hi, len u16, 0xFE (0x7F when server->client), cmdEx u16
[15]     devType u8
[16]     subFlag u8   (1 = data/more chunks follow, 2 = end/last)   PacketPlus.cs:13-17, default 2
[17..18] subIndex u16 (0-based chunk index)
[19..]   protobuf bytes (chunk)
[len-2]  cksum, [len-1] 0x5A
```
Response (layout D), `BTSPLUS/PacketPlusResp.cs:157-201`:
```
[0..15]  hdr: FF×8, devID_lo, devID_hi, len, 0xFE/0xFF, result u8, cmdEx u16
[16..19] resultEx u32  (meaningful when result==0xFF)
[20]     devType u8
[21]     subFlag u8, [22..23] subIndex u16
[24..]   protobuf bytes (chunk)
```
Chunking: if `SerializedSize > 3996`, the serialized message is cut into 3996-byte slices. Every slice has
`subFlag=1`, except the last which has `subFlag=2`, and `subIndex = 0,1,2…` (`Client.cs:14036-14078` `SendPlusCmd`).
The receiver concatenates slices per `"{devType}-{devID}-{cmdEx}"` and resets on `subIndex==0` (`Client.cs:14015-14034` `OnSubResp`).
A single unchunked message is sent as `subFlag=2, subIndex=0`.

**Protobuf flavour:** Google.ProtocolBuffers 2.x C# port. Even for `syntax="proto3"` files, the generated code
tracks `hasX`, so explicitly set scalar fields are serialized **even when 0**
(`Proto/BTSPLUS/TPacketClientHeart.cs:242-250`). Python's proto3 runtime skips zero scalars. The server is C++
and may not care, but match the original encoding to be safe (P6).

**Schema source:** each generated C# file embeds its `FileDescriptorProto` as base64 (`FileDescriptor.InternalBuildGeneratedFileFrom(...)`).
I extracted all 131 descriptors to `.proto` text with a small script (see Appendix). Field lists below come from that extraction.

### 1.6 Worked examples (computed by hand from the code above; not captured)

**Login** (`PacketConnect`, cmd 0x00, `clientType=3`, `version=0x0201`; `NetworkBase/Network/PacketConnect.cs:35-46`, `Client.cs:6962-6970`):
```
FF FF FF FF FF FF FF FF | 00 | 00 | 12 00 | 00 | 03 | 01 02 | 18 | 5A
 start                   dev  unit len=18  cmd  ctype ver=513  sum  end
sum = 0x00+0x00+0x12+0x00+0x00+0x03+0x01+0x02 = 0x18
```
Expected reply: `PacketConnectResp` = layout B, cmd 0x80, result, no body. That is 16 bytes: `FF×8 dd uu 10 00 80 rr ss 5A`
(`PacketConnectResp.cs`, `PacketRespEmpty.cs`).

**Plus heartbeat**, first call (`cmdEx 0x0211`, `TPacketClientHeart{Counter=0}` → proto bytes `08 00`; `Client.cs:15942-15949`):
```
FF×8 | 00 00 | 17 00 | FE | 11 02 | 00 | 02 | 00 00 | 08 00 | 32 | 5A      (len 23)
sum = 17+FE+11+02+00+02+00+00+08+00 = 0x132 -> 0x32
```

**Legacy stop** (illustration only; **do not send on the live rig**). BTS80 devType 22, dev 1, unit 1, channel 1 → mask `1<<(1-1)`:
```
FF×8 | 01 | 01 | 1A 00 | FE | 0A 00 | 16 | 01 00 00 00 00 00 00 00 | 3B | 5A
```

---

## 2. Connection / handshake sequence (8.0 server, as the GUI does it)

1. **TCP connect** to `ip:8001` (`OnLine.cs:226-268`). On success `OnConnectSuccess → SendLogin()` (`Client.cs:7958-7963`).
2. **C→S Login** `cmd 0x00 {clientType u8 = 3 (BGS_CLIENT), version u16 = 0x0201}` (`Client.cs:6962-6970`).
   The login is queued under key (BTS, dev 0). If no reply arrives within **2 s** it is resent once, and after that the client disconnects (`CmdLogin.cs:17-24`, `Client.cs:7820-7826`).
3. **S→C Login resp** `cmd 0x80` (plain layout B) → client marks the server online (`Client.cs:6972-6994`).
4. **S→C Server version push** `cmdEx 0x0081` (layout D, `BTSCS/PacketGetSvrVer.cs`), **unsolicited**. The client never sends a version request: `CMD_GET_SVR_VERSION=129` exists only as a constant (`PacketCS.cs:183`).
   Body (`PacketGetSvrVer.cs:148-174`): `version u16` (e.g. 0x0801), `svrVer char[30]` (e.g. `"8.0.1.437(2025.01.02)"`, format inferred),
   then, if the frame is long enough: `dbUserName[20]`, `dbPwd[100]`, each byte de-obfuscated with `b[i] -= i`;
   then `svrGuid[32]`, `baseboardSN[100]`, `sysVer[100]`, `computerName[256]`.
   The client rejects servers older than `Server760` (`Client.cs:7027-7048`).
5. Client sets `_isLogined = true`, sends a heartbeat after 1 s, and then:
   - if `AllowUndefinedDev`: **GetDevListPlus** `cmdEx 0x021B` `TPacketGetDeviceList{ClientVersion=string}` (`Client.cs:7062-7069`).
   - else: legacy `GetDevList612` `cmdEx 0x005E` body `devType u8`, sent once per devType 22, 23, 24, 27 (`Client.cs:7042-7046, 7112-7117`).
6. **S→C device list** `0x821B TRespGetDeviceList{repeated TDevParam{DevType,DevID,OnLineStatus,Version}, AbnDevs}` (`Client.cs:7071-7110`)
   or legacy `0x805E` (`PacketGetDevList612Resp`: `devType u8, count u8, {devID u8, version u16, status u8, polarity u8,
   cellHeight u8, stepTime u32, remainTime u32, isMap u8, reserve u32}×n`).
7. For each device, `UpdateDevice()` runs (`Client.cs:7144-7230`) and for **online** devices calls `SelectDev`:
   - `Allow256Zwj` → **SelectDevPlus** `cmdEx 0x021F TPacketSelectDev{SelectStatus}` (SelectStatus left unset) (`Client.cs:8445-8457, 16661-16669`).
     The resp is 0x821F.
   - else `PacketSelectDevID` `cmdEx 0x0004 {devType u8, deviceID u8}`, resp 0x8004.
   **Selecting a device is the subscription.** No RT-request command exists in the client. RT data then arrives unsolicited (section 4).
8. Channel topology per device (`Client.cs:7199-7224`):
   - **DevType 27 (BTS85, Plus)** or **>= 25 (BTS83/84)** → **Plus GetDeviceInfo** `cmdEx 0x0201 TPacketGetDeviceInfo{}` with devType/devID in the Plus header (`Client.cs:14096-14103`).
     Resp `0x8201 TRespGetDeviceInfo` (may be chunked) holds `DevInfo` (85) or `DevInfo83` (83/84), which contain `ChlMap{UnitID,ChlID,AuxID,RealChlID,ChlType}`, XWJ info, parallel and temp maps (`Client.cs:14105-14160, 1048-1080`).
   - **DevType 22-24 (BTS80/81/82)** → `GetChlMap612` `cmdEx 0x0062 {devType}` → `0x8062`: `devType u8, count u16, {subDevID(unit) u8, mainChlMap(chl) u8, auxChlMap u8, realChlID u8, chlType u8}×n`. Entries with `auxChlMap==0` are main channels (`Client.cs:7267-7340`).
     The client also sends GetSubDevList 0x0002, GetTempMap 0x00DA, GetIP 0x0053, ZwjSnEx 0x00C2 and GetDevInfo 0x00E1 (proto). These are not needed for a minimal client.
   - The client also asks for virtual/"comb" devices with `0x0067` (`Client.cs:7567-7573`). Optional.
9. **Keep-alive:** every ~10 s (`OnLine.cs:192-199`: every `10000/1000` loops of the 1 s thread) the client sends a heartbeat.
   For an 8.0 server this is the **Plus heartbeat** `0x0211 TPacketClientHeart{Counter++}` → `0x8211 TRespClientHeart{Counter, DiskStatus, MemoryStatus, MysqlStatus, ThreadStatus, DbRoot…}`
   (`Client.cs:8389-8400, 15942-15949`). Legacy heartbeat: `0x0012 {devType u8}` → `0x8012`.
   No server-side idle timeout is visible from the client side (P4).
10. **S→C device status pushes:** legacy `0x800C` (`PacketUpdateDevStatusResp`: `devType u8, version u16, status u8, polarity u8, cellHeight u8, stepTime u32, remainTime u32`; `Client.cs:7050-7060`),
    Plus `0x821D TRespUpdateDevStatus{Status}` (`Client.cs:16619`). In both, `status==1` means online. The client then re-runs `UpdateDevice` and the select.

Command pacing: the client keeps **one outstanding queued command per device** (`SaveCmd`/`SendNextCmd`, `Client.cs:7713-7786`).
Queued commands time out after 10 s and are resent once (`CmdToSvr.cs:116-132`, `Client.cs:7788-7950`). Fire-and-forget commands
(Stop, Plus Stop/Jump/Clear/Resume, SelectDev, heartbeat) are sent directly with `SendCmd`.

---

## 3. Command table

Dir: C→S = client to server, S→C = server push. "L" = layout from section 1.2. Codes are hex (decimal in the source).

### 3.1 Session / discovery

| Name | Req code | Resp code | Payload (req → resp) | Source |
|---|---|---|---|---|
| Login | cmd 0x00 (L-A) | cmd 0x80 (L-B) | `clientType u8=3, version u16=0x0201` → (empty) | `PacketConnect.cs:40-46`; `Client.cs:6962, 6972` |
| Server version | — | 0x0081 push (L-D) | see §2 step 4 | `PacketGetSvrVer.cs`; `Client.cs:6996-7048, 8046` |
| Heartbeat (legacy) | 0x0012 | 0x8012 | `devType u8` → `devType u8` | `BTSCS/PacketHeartBeat.cs`, `PacketSendClientEmpty.cs`; `Client.cs:8389-8406` |
| Heartbeat (Plus) | 0x0211 | 0x8211 | `TPacketClientHeart{1:Counter u32}` → `TRespClientHeart{1:Counter,2:DiskStatus,3:MemoryStatus,4:MysqlStatus,5:ThreadStatus,6:DbRoot str,…,12:NoDfDevs,13:NoDfChls,…}` | `Client.cs:15942-15960`; `Proto/BTSPLUS/HeartClient.cs` |
| GetDevList (Plus) | 0x021B | 0x821B | `TPacketGetDeviceList{1:ClientVersion string}` → `TRespGetDeviceList{1:repeated TDevParam{1:DevType,2:DevID,3:OnLineStatus,4:Version}, 2:repeated TAbnormalDevStatus}` | `Client.cs:7062-7110, 13959` |
| GetDevList (legacy) | 0x005E | 0x805E | `devType u8` → see §2 step 6 | `PacketGetDevList612*.cs`; `Client.cs:7112-7142, 8031` |
| SelectDev (Plus) | 0x021F | 0x821F | `TPacketSelectDev{1:SelectStatus u32}` (left unset) → `TRespSelectDev{}` | `Client.cs:16661-16680, 13971` |
| SelectDev (legacy) | 0x0004 | 0x8004 | `devType u8, deviceID u8` → same | `BTSCS/PacketSelectDevID.cs`; `Client.cs:8445-8470` |
| GetDeviceInfo (Plus; BTS83/84/85) | 0x0201 | 0x8201 (chunked) | `TPacketGetDeviceInfo{}` → `TRespGetDeviceInfo{1:DevInfo DeviceInfo, 2:bytes IP, 3:int32 Version, 4:string Remark, 5:DevInfo83 DeviceInfo83, 6:repeated LockedChl}` | `Client.cs:14096-14160, 13878` |
| GetChlMap (BTS80-82) | 0x0062 | 0x8062 | `devType u8` → map list (§2 step 8) | `PacketGetMap612*.cs`; `Client.cs:7267-7340, 8034` |
| Dev status push | — | 0x800C / 0x821D | §2 step 10 | `Client.cs:8028, 13965` |

### 3.2 Realtime data (all S→C, unsolicited after SelectDev) — see §4

| Name | Code | Device types | Payload | Source |
|---|---|---|---|---|
| RtData80 | 0x80BE (L-D) | BTS80/81 (22/23) | struct, §4.2 | `BTSCS/PacketRtData80.cs`; `Client.cs:8085, 17448-17524` |
| RtData82/83 | 0x80D4 (L-D, PacketProtoResp) | BTS82/83/84 (24-26) | `ProtocSendRTData82Resp{1:DevType,2:DevID,3:UnitID,4:Result,5:RTCount,6:repeated RTData82,7:repeated RTData83}` | `Client.cs:8088, 17526-17700` |
| Plus RT | 0x0202 (**L-E, cmd 0x7F**, PacketPlus) | BTS85 (27) | `TPacketRtData{1:repeated TProtoOneRt RtData, 2:WholeMachineRt, 3:ZwjSysInfo}` | `Client.cs:13881, 14678-14830` |
| Older RT | 0x806E/0x80A1/0x8083/0x80A2/0x80A5 | <= BTS79 | legacy | `Client.cs:8076-8084` |

### 3.3 Channel control

The channel selector differs by style:
- **legacy:** header `devID/unitID` + body `devType u8, mask u64`, where bit `(ChlID-1)` is set (ChlID is 1-based, up to 64 per unit; `Client.cs:12162-12179`).
- **Plus:** Plus header devType/devID(u16), and the proto contains `repeated uint32 ChNo` (1-based ChlID).

The client chooses Plus when `DevType.IsPlus(devType)`, i.e. `devType==27` (`Common/common/DevType.cs:384-400`).

| Action | Legacy (devType <= 26) | Resp | Plus (devType 27) | Resp | Source |
|---|---|---|---|---|---|
| **Stop** (running → "stop"; see note) | 0x000A `devType u8, mask u64` (direct send, not queued) | 0x800A same | 0x0208 `TPacketStop{1:repeated ChNo}` | 0x8208 `TRespStop{}` | `PacketStop.cs`; `Client.cs:8663-8687, 15235-15283` |
| Stop whole device | 0x000A, `unitID=253` (refuse paused ch.) or `0`, `mask=0` | 0x800A | Plus Stop with all stoppable ChNo | | `Client.cs:8689-8732` |
| **Continue / resume** | 0x000D `devType u8, mask u64` (queued) | 0x800D | 0x0209 `TPacketResume{1:bytes Guid, 2:uint32 type (TResumType, 0=normal), 3:repeated ChNo}` | 0x8209 `TRespResume{Guid,type}` | `PacketContinue.cs`; `Client.cs:8750-8806, 15285-15310` |
| **Jump / goto step** | BTS80-82: 0x0070 `devType u8, mask u64, stepID u16` (queued). BTS83/84: 0x00EC PacketProto `ProtocJump83{1:DevType,2:DevID,3:UnitID,4:int64 Channel(mask),5:StepID}` | 0x8070 / 0x80EC `ProtocJump83Resp{…,4:Result,5:Channel}` | 0x020A `TPacketJump{1:repeated StepNo, 2:repeated ChNo}` | 0x820A `TRespJump{}` | `PacketJump.cs`; `Client.cs:8808-8873, 15444-15475` |
| **Clear flag / reset status** ("清除标记") | 0x0097 `devType u8, mask u64` (queued) | 0x8097 | 0x020B `TPacketClear{1:repeated ChNo}` | 0x820B `TRespClear{}` | `PacketResetChlStatus.cs`; `Client.cs:8917-8955, 15492-15512` |
| Reserve (scheduled) pause | 0x00D2 PacketProto `ProtocReserveStop82` | 0x80D2 | 0x0214 `TPacketReserveSet` | 0x8214 | `Client.cs:10510-10570, 16195` |
| Channel ctrl (generic) | 0x00DC `ProtocSendChlCtrl{DevType,DevID,UnitID,ChlID,CtrlType}` | 0x80DC | — | | `Client.cs:8901-8915` (CtrlType values unknown, P7) |
| Modify step in run | 0x00B7 / 0x00ED (83) | 0x80B7 / 0x80ED | 0x020F | 0x820F | `Client.cs:9057…, 13917` |

**Pause vs stop semantics:** the 8.0 GUI has no separate "pause" command for 4S/8.x devices. "Stop" (停止)
moves a running channel into `WorkType.stop` (2), and "Continue" resumes it (`WorkType.AllowContinue`: stop/protect/pause/
ReservePause/beep, `Common/common/WorkType.cs:228-235`). A test is finally ended by Clear-flag (ResetChlStatus) or by starting
a new test. `WorkType.pause` (4) comes from step type PAUSE or a reserve pause. `AllowStop` also covers pause/ReservePause when
devType >= BTS82 and the `AllowStopWhenPause` setting is on (`WorkType.cs:183-208`). GUI callers: `BTSLib/BTS/ChlViewRightMenu.cs:7217` (Stop),
`7645` (StopAll), `7851/7944` (Continue), `8022/8058` (Jump), `9491` (ClearFlag).

### 3.4 Start test (with step file)

Entry point `Client.SendStartStep` (`Client.cs:17890-17988`) dispatches on devType: BTS80 → `CmdStart80`, BTS81 → `CmdStart81`,
BTS82 → `CmdStart82`, BTS83/84 → `CmdStart83`, BTS85 → `CmdStart85` (`Client.cs:18285, 18385, 1380, 14849`). Each start is a
**multi-packet transaction**: a queued state machine that sends one sub-command, waits for its response, then sends the next.
All sub-commands carry the same random 16-byte transaction `Guid`.

**BTS85 / Plus** (`NetworkBase/Network/CmdStart85.cs`; progress enum at `:15-25`; sub-command build at `:303-316`):

| # | Stage | cmdEx → resp | Proto | Notes |
|---|---|---|---|---|
| 1 | ChlInfo | 0x0203 → 0x8203 | `TPacketStartInfo{1:Guid, 2:repeated TStartChlStep{1:StepGuid, 2:repeated TStartChl{1:ChNo, 2:bytes Barcode(UTF-8)}, 3:IsExist}}` | `Client.cs:14873-14893`; the resp's `IsExist!=0` → step already on the device (`Client.cs:14918-14925`) |
| 2 | RemarkInfo | 0x0207 → 0x8207 | `TPacketRemarkInfo{Guid, Remark, Sn, TestSn, StepName, TestName, Creator, BatteryMass(F), ChlInfo[]…}` | `CmdStart85.cs:622-680` |
| 3 | DBC (optional) | 0x0226 → 0x8226 | `TPacketSetStepDBC` | only if the step file has CAN/485/SMBus data |
| 4 | **Step** | 0x0204 → 0x8204 | `TPacketStepData{1:Guid, 2:repeated TStepInfo, 4:StepGuid, 5:StartStepID, 6:GlobalRecord, 7:GlobalProtect, 8:RateMode, 9:MultCap, 10:NominalCap, 11:GlobalParam}`. Each step is built by `NetworkBase/Proto/ProtoStep.Encode(StepItem, StandardCap)` (`ProtoStep.cs:16`) | chunked by SendPlusCmd/SetSubCmd |
| 5 | SimFile (optional) | 0x020E → 0x820E | `TPacketPutFile` | only for simulation steps |
| 6 | GlobalPrt | 0x0224 → 0x8224 | `TPacketGlobalPrt` (fire temp, fixture volt limits…) | `CmdStart85.cs:765-846` |
| 7 | Start | 0x0205 → 0x8205 | `TPacketStart{1:Guid, 2:TestId}` → `TRespStart{1:Guid, 2:TestId}` | the client stores `TestId` (`Client.cs:15015-15032`) |
| 8 | StartConfirm | 0x0206 → 0x8206 | `TPacketStartConfirm{1:Guid, 2:TestId}` | `CmdStart85.cs:849-860` |

**BTS82/83/84** (`CmdStart82.cs`, `CmdStart83.cs`; the stage list is in `CmdStart76.cs:14-34`: Map, Barcode, Remark, Aux, DBC, Smbus,
Step, StepGlobal, GuidFile, SimFile, Paral, TempBoxMap, WaterMap, PressureMap, TempModeMap, HeightGuageMap, GlobalPrt, Start, Confirm;
many stages are skipped when empty):
- **Step:** 0x00D1 PacketProto `ProtocSetStep82{1:DevType,2:DevID,3:UnitID,4:repeated StartChlInfo{UnitID,ChlID},5:StepCount,6:StepFileLen,7:PackIndex(1-based),8:EndFlag(2=last),9:bytes StepBuf,10:bytes Guid}` → 0x80D1.
  `StepBuf` holds the **binary step encoding** from `Common/common/Step.cs:877-952` (`EncodeBts80`). Per step: `len u16, stepNo u16, stepID (u8, or i16 for >=BTS83), stepType u8, u32[] params, bytes cond, u32 1`.
  The per-step body comes from `StepItem.Encode` (or `EncodeF` for >=BTS83). Steps are packed into chunks of <=1000 bytes, or <=3500 for devType >= 25 (`CmdStart82.cs:20-110`).
- StepGlobal 0x00F0 `ProtocSetStepGlobal`. GlobalPrt 0x00D7 `ProtocSetGrobalProtect82`.
- **Start:** BTS83/84 → 0x00EB `ProtocStart83{1:DevType,2:DevID,3:UnitID,4:repeated UnitChlInfo{UnitID,ChlID},5:Guid,6:StepID(start step),7:double BatteryMass,8:Creator,9:Sn,10:Remark,11:TestSn}` → 0x80EB `ProtocStart83Resp{…,5:repeated UnitChlStartInfo,6:Guid}` (`CmdStart83.cs:35-78`).
  BTS80-82 → 0x00BD `PacketSendStart80` struct → 0x80BD (`CmdStart80.cs:540`).
- **Confirm:** 0x00E3 `ProtocStartConfirm{DevType,DevID,UnitID,4:repeated ConfirmTest{UnitID,ChlID,TestID},5:Guid}` → 0x80E3 (`CmdStart83.cs:80-98`).

**Step file → model:** the GUI loads the `.xml` step file (format: `vendor/config/DefaultStep.xml`, `<root><config type="Step File" version="18" … Guid=…><Head_Info>…<Step_Info Num=N><StepK Step_ID Step_Type>…`)
with `Common/common/XmlStep.cs` into `Common.Step`. It then encodes that model with `ProtoStep.Encode` (Plus) or `Step.EncodeBts80` (legacy).
**The XML file is never sent as-is.** A Python client has to port one of these encoders (P8).

---

## 4. Realtime data and channel identity

### 4.1 Identity
- **devType** u8: 22=BTS80, 23=BTS81, 24=BTS82, 25=BTS83, 26=BTS84, **27=BTS85 (the only "Plus" type)** (`Common/common/DevType.cs:7-43, 384-400`).
- **devID**: u8 in legacy frames (header byte 8). In Plus frames it is a u16 split over header bytes 8 and 9.
- **unitID** (the "sub-device", 中位机): header byte 9 in legacy frames. Plus treats unit as 0 (`PacketPlus.cs:103-112`) and channels are numbered device-wide.
- **chlID**: 1-based. Legacy masks use bit `chlID-1` within a unit. Plus uses `ChNo` lists.
- **dev_uid** = `devType*10000 + devID` (`Common/.../ValueValidate.cs:504-507`); unit/chl key = `unitID*100000 + chlID` (`:529-532`).
- A GUI channel is the tuple `(SvrIP, devType, devID, unitID, chlID)`, built from GetChlMap / DevInfo (§2 step 8). In map responses, entries with `auxChlMap/AuxID != 0` are auxiliary (temperature/voltage) channels attached to a main channel.

### 4.2 Push mechanism
RT frames arrive **unsolicited** after SelectDev. The client never polls (no sender of the RT cmd codes exists in `Client.cs`).
Each frame covers one device (and one unit for legacy) and lists records for several channels.

**RtData80 (0x80BE)** body after the 16-byte resp header (`BTSCS/PacketRtData80.cs:420-434`): `devType u8, dataPoint u32, count u8`, then `count ×` this record (`:344-370`):
```
dataFlag u8, chlID u8, auxChlID u8 (0 = main channel), cycle u32, stepID u16, stepType u8, workType u32,
testTime u64, volt i32, curr i32, ir u16, temp i16, ccap u64, dcap u64, ceng u64, deng u64,
currStepRange i32, prtCode u32, testID u32, totalTime u64, seqID u32, dfCurrSeqID u32     (= 92 bytes)
```
**RTData82** (proto2, fields 1-25) has the same fields as integers. **RTData83** (field 7 of the RT82 resp, used by BTS83/84) has float Volt/Curr/CurStepRange,
double CCap/DCCap/CEng/DCEng, plus 26:TotalCap, 27:TotalEng, 28:CapRetentionRate. The client handles both lists (`Client.cs:17546-17700`).

**Plus RT (0x0202)** `TProtoOneRt{1:MainRt, 2:repeated AuxRt{1:TDataType DataType, 2:AuxChNo, 3:TypeID, 4:float Value, 5:AuxConnect}, 3:DbcRt, 4:SmbusRt, 5:uint32 ChNo, 6:UpCastRt}`.
`TProtoMainRt`: `2:CycleNo, 3:repeated StepNo (first = step, rest = sub-steps), 4:TStepType StepType, 5:TChStatus ChStatus, 6:u64 StepRunTime, 7:float Voltage (V), 8:float Current (A),
9:double ChgCap (Ah), 10:DchgCap, 11:ChgEnergy (Wh), 12:DchgEEnergy, 13:float CurRange, 14:LogInfo (protection code), 15:u64 TotolRunTime, 16:TestID, 17-22 reserve-pause info,
23:repeated float LogValue, 24:ChConnect, 25:ForbidResume, 26:IsCali, 27:TotalCap, 28:TotalEng, 29:CapRetentionRate` (`Client.cs:14701-14760`).
Units are inferred from `SystemUnit.ToBaseValue(x, Unit.UnitIndex.V/A/Ah/Wh)`.

**Units:** the client converts Plus floats to "base" integers with `Unit.GetScale` (`Common/common/Unit.cs:629-700`):
V×10000 (base 0.1 mV), A×1000 (base mA), Ah×3,600,000 (base mAs), ms for time. It assigns legacy RtData80/82 ints **directly**
to the same Channel fields, so legacy raw units are probably **volt 0.1 mV, curr mA(?), cap mAs, energy mWs(?), time ms**. Not verified (P5).

**Status enums:**
- Legacy `workType` → `WorkType.ToType()`. GUI enum `WorkType.type`: 0 finish, 1 running, 2 stop, 3 protect, 4 pause, 5 offline, … 17 ReservePause, 18 FinshProtect (`WorkType.cs:7-35`).
- Plus `TChStatus`: 0 Idle, 1 Testing, 2 Stop, 3 Pause, 4 Protected, 5 ReadyRun, 6 Light, 7 PauseReserve, mapped via `WorkType.ToPlusType` (`Client.cs:17774`).
- `TStepType`: 1 CCC, 2 CCD, 3 CVC, 4 REST, 5 CYCLE, 6 END, 7 CCCVC, 8 CPD, 9 CPC, 10 CRD, 13 PAUSE, 16 PULSE, 17 Sim, 19 CVD, 20 CCCVD, 21 Ctrl, 22 OCV, …

---

## 5. Minimal Python client plan (read-only first)

1. Connect to `127.0.0.1:8001`. Send the Login frame (§1.6). Read and frame-parse in a loop (8×FF sync, len@10, 0x5A trailer).
2. Expect `cmd 0x80`, then `0xFE … cmdEx 0x0081`. Parse the version and the date string.
3. Send GetDevListPlus 0x021B (or legacy 0x005E for each devType if the date gate is off). For each online device, send SelectDevPlus 0x021F, then GetDeviceInfo 0x0201 (83/84/85) or GetChlMap 0x0062 (80-82).
4. Send a heartbeat every 10 s (Plus 0x0211 with an increasing Counter).
5. Decode 0x80BE / 0x80D4 / 0x0202 pushes into per-channel state. Log any unknown cmdEx with a hex dump.
6. Control (later, on a spare channel only): Stop/Continue/Jump/Clear as in §3.3. Start needs a step encoder port (§3.4).

**Safety note:** the client does not check permissions locally for these packets. The server may enforce them
(`GetPopedom` 0x0074/0x8074 exists, P3). A wrong mask or ChNo will act on **live channels**. Build and verify against captures first.

---

## 6. Open questions / uncertainties (all Inferred)

- **P1** Server-originated *command-layout* packets (Plus RT 0x0202, 0x0221 XWJ-update progress, 0x0228 PLC status) must use `cmd=0x7F`, as derived from the dispatcher. Do Plus *responses* use `0xFE` or `0xFF` in byte 12? The client accepts both (`OnLineEx.cs:884-886`). `PacketDefine.cs:45-47` (`CMD_PLUS_EX=0x7F`, `RESP_PLUS_EX=0xFF`) suggests 0xFF for Plus responses. Does the server accept 0x7F from clients? Not needed: the client always sends 0xFE.
- **P2** Exact `svrVer` string format and the `version` u16 value for 8.0.1.437. The feature gates depend on the date in parentheses. If the date does not parse, every gate is off and the client falls back to the legacy GetDevList/SelectDev/heartbeat.
- **P3** Is any user login or password required beyond `PacketConnect`? None is visible in `Client` (`_isUserLogin` is used only in debug mode, `Client.cs:7685-7693`). User permissions look GUI-side (popedom). Confirm on a capture.
- **P4** Server idle timeout / heartbeat requirement. The client sends a heartbeat every 10 s.
- **P5** Legacy RT units (curr mA vs 0.1 mA, energy) and the `dataFlag` meanings (115/117 = DBC/virtual aux, `Client.cs:17590`). The meaning of `dataPoint`.
- **P6** Whether the C++ server tolerates proto3-style omission of zero fields. Safest is to emit explicitly set zeros like the C# client.
- **P7** `ProtocSendChlCtrl.CtrlType` values. The reserve-pause details (`ReservePause.Action`).
- **P8** Step encoders (`ProtoStep.Encode`, `StepItem.Encode/EncodeF`) are large and not documented here. Also unknown: whether the server can start from a step GUID it already holds (`IsExist` in TRespStartInfo suggests the device caches steps by GUID, but the client still sends the step data).
- **P9** Which devTypes are actually attached to this server. The answer decides between the legacy/struct, legacy-proto (82-84) and Plus (85) paths. Read it from the first device-list response.
- **P10** Exact meaning of `Stop` with `unitID=253` (whole-device stop that excludes paused channels?) (`Client.cs:8713-8720`).

---

## Appendix: proto extraction

`FileDescriptorProto` blobs are embedded in `Proto/**/*.cs` (base64 strings passed to `FileDescriptor.InternalBuildGeneratedFileFrom`).
A dependency-free script (`python -I dump_protos.py <Proto dir> <out dir>`) decodes all 131 of them into `.proto` text
(packages `BTSPLUS`, `BTSCS`, `MISC`, root). It was run from the session scratchpad. Copy it to `tools/` if the generated `.proto`
files are wanted for `protoc --python_out`. Key files: `BTSPLUS/RtData.proto`, `GetDevList.proto`, `GetDevInfo.proto`, `DevInfo.proto`,
`DevInfo83.proto`, `Stop.proto`, `Resume.proto`, `Jump.proto`, `Clear.proto`, `StartInfo.proto`, `StepInfo.proto`, `Start.proto`,
`StartConfirm.proto`, `HeartClient.proto`, `SelectDev.proto`, `BTSCS/ProtocSendRTData82.proto`, `ProtocSetStep82.proto`,
`ProtocStart83.proto`, `ProtocStartConfirm.proto`, `ProtocJump83.proto`.

Plus cmdEx list (client-side names; resp = |0x8000): 0x0201 GetDevInfo, 0x0202 RT (push), 0x0203 StartInfo, 0x0204 Step, 0x0205 Start,
0x0206 StartConfirm, 0x0207 StartRemark, 0x0208 Stop, 0x0209 Resume, 0x020A Jump, 0x020B Clear, 0x020C VersionInfo, 0x020D SetMap,
0x020E PutFile, 0x020F ResetStep, 0x0210 Move, 0x0211 Heartbeat, 0x0212 Tftp, 0x0213 Parallel, 0x0214/0x0215 Reserve set/get,
0x0216 SetDevID, 0x0217 Restart, 0x0218 Lighten, 0x0219 HisContinue, 0x021A Thermostat, 0x021B GetDevList, 0x021C AbnormalDevStatus,
0x021D UpdateDevStatus, 0x021E DeleteOfflineDev, 0x021F SelectDev, 0x0221 XwjUpdateProgress (push), 0x0222 VoiceWarm, 0x0223 Rtc,
0x0224 GlobalPrt, 0x0225 SetDbc, 0x0226 SetStepDbc, 0x0227 PlcCtrl, 0x0228 PlcStatus (push), 0x0229 PlcResult, 0x022A AdapterConfig,
0x022B BmsSearch, 0x022C ChlLock, 0x022D ChlLockReq, 0x022E ResetBarcode (`Client.cs:13874-14010` and the `PacketPlus(` constructors).
The server PDB confirms matching names `PLUS_CS_CMD_*` / `PLUS_CS_RESP_*` (`vendor/server/BtsServer.pdb`, strings only).
