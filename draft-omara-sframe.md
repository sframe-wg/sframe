---
title: Secure Frame (SFrame)
abbrev: SFrame
docname: draft-omara-sframe-00
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: E. Omara
    name: Emad Omara
    organization: Google
    email: emadomara@google.com
 -
    ins: J. Uberti
    name: Justin Uberti
    organization: Google
    email: juberti@google.com
 


--- abstract

This document describes a new end to end encryption and authentication schema for WebRTC media frames in a multiparty conference call where the central media server (SFU) will have access to the needed metadata in order for it work without getting access the encrypted media. 
This proposal uses the entire media frame instead of individual RTP packet as the encryptable unit to decrease the encryption overhead.

--- middle

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals, as shown here.

SFU: 
: Selective Forwarding Unit (AKA RTP Switch)
IV: 
: Initialization Vector
MAC:
: Message Authentication Code
E2EE:
: End to End Encryption (AKA Inner Encryption)
HBH:
 Hob By Hob (AKA Outer Encryption)


# Background
Modern multi-part conference call systems include SFU server to efficiently forward the RTP streams to the end points based on their bandwidth. In order for the SFU to work properly it needs to access and modify some metadata about these streams which is not possible if the RTP packets are end to end encrypted and authenticated. So two layers of encryptions and authentication are required:
	1- E2EE between the endpoints
	2- HBH between the the endpoints and SFU 
Intuitively SRTP+DTLS is used for HBH encryption, however it is more challenging to design the E2EE due to the bandwidth overhead, mainly the extra authentication tag per packet.

~~~~~
  +-------------------------------+-------------------------------+^+
  |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
  +-------------------------------+-------------------------------+ |
  |                           timestamp                           | |
  +---------------------------------------------------------------+ |
  |           synchronization source (SSRC) identifier            | |
  |=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=| |
  |            contributing source (CSRC) identifiers             | |
  |                               ....                            | |
  +---------------------------------------------------------------+ |
  |                   RTP extension(s) (OPTIONAL)                 | |
+^---------------------+------------------------------------------+ |
| |   payload header   |                                          | |
| +--------------------+     payload  ...                         | |
| |                                                               | |
+^+---------------------------------------------------------------+^+
| :                       authentication tag                      : |
| +---------------------------------------------------------------+ |
|                                                                   |
++ Encrypted Portion*                      Authenticated Portion +--+
                                                                     
                        SRTP packet format 
~~~~~

#SFrame
We propose a frame level encryption schema for the E2EE layer to decrease the overhead by having a single IV and authentication tag per the media frame and not per RTP packet, and the encrypted frame will be packetized using a generic
RTP packetized and not codec dependent packetized anymore. 
In order for SFU to work, media metadata will be moved to a generic frame frame header extension which will be authenticated end to end. This extensions will include metadata such as resolution, frame rate, frame begin and end marks, etc.

The SFrame payload is constructed by a generic packetizer that splits the E2E encrypted media frame into one or more RTP packet and add the SFrame header to the beginning of the first packet and auth tag to the end of the last packet.

~~~~~
                           +---------------+  +---------------+
                           |               |  | frame metadata+----+
                           |               |  +---------------+    |
                           |     frame     |                       |
                           |               |                       |
                           |               |                       |
                           +-------+-------+                       |
                                   |                               |
          CTR +---------------> IV |Enc Key <----Master Key        |
                 derive IV         |                  |            |
           +                       |                  |            |
           |                       +                  v            |
           |                    encrypt           Auth Key         |
           |                       |                  +            |
           |                       |                  |            |
           |                       v                  |            |
           |               +-------+-------+          |            |
           |               |               |          |            |
           |               |   encrypted   |          v            |
           |               |     frame     +---->Authenticat<------+
           +               |               |          +
       encode CTR          |               |          |
           +               +-------+-------+          |
           |                       |                  |
           |                       |                  |
           |                       |                  |
           |              generic RTP packetize       |
           |                       +                  |
           |                       |                  |
           |                       |                  +--------------+
+----------+                       v                                 |
|                                                                    |
|   +---------------+      +---------------+     +---------------+   |
+-> | SFrame header |      |               |     |               |   |
    +---------------+      |               |     |  payload N/N  |   |
    |               |      |  payload 2/N  |     |               |   |
    |  payload 1/N  |      |               |     +---------------+   |
    |               |      |               |     |    auth tag   | <-+
    +---------------+      +---------------+     +---------------+
 
                                         
~~~~~

The E2EE keys used to encrypt the frame are exchanged out of band using a secure channel. E2EE key management and rotation is out of the scope of this document. 


## SFrame header
Since each endpoint can send multiple media layers, each stream will have a unique frame counter that will be used to derive the encryption IV. To guarantee uniqueness across all streams and avoid IV reuse, the frame counter will have be prefixed by a stream id which will be 0 to N where N is the total number of outgoing streams.
The expected number of outgoing streams will be between 4 and 9 streams, using 5 bits for stream id will support up to 32 streams. 

The frame counter itself can be encoded in a variable length format to decrease the overhead, the following encoding schema is used 

~~~~~
+---------+---------------------------------+
|LEN |SRC |           CTR...                |
+---------+---------------------------------+
            SFrame header format 
~~~~~

LEN (3 bits)
The CTR length fields in bytes. 
SRC (5 bits)
4 bits source stream id
CTR (Variable length) 
Frame counter up to 8 bytes long



## Encryption Schema
Each client creates a 32 bytes secret key K and share it with with other participants via an E2EE channel. From K, we derive 3 secrets:

1- Salt key used to calculate the IV

~~~~~
Key = HKDF(K, 'SFrameSaltKey', 16)
~~~~~

2- Encryption key to encrypt the media frame

~~~~~
Key = HKDF(K, 'SFrameEncryptionKey', 16)
~~~~~

3- Authentication key to authenticate the encrypted frame and the media metadata

~~~~~
Key = HKDF(K, 'SFrameAuthenticationKey', 32)
~~~~~


The IV is 128 bits long and calculated from the SRC and CTR field of the Frame header:

~~~~~
IV = (SRC||CTR) XOR Salt key
~~~~~


### Cipher suites
SFrame supports two ciphers, the only difference is the length of the authentication tag, where 10 bytes is used for video and 4 bytes for audio

1- AES_CM_128_HMAC_SHA256_80
1- AES_CM_128_HMAC_SHA256_32

It uses AES counter mode for encryption with 128 bit key, SHA256 hash for the HKDF key derivation.

### Outer encryption
SRTP is used as an outer encryption for HBH, since the media payload is already encrypted, and SRTP only protects the RTP headers, one implementation could use 4 bytes outer auth tag to decrease the overhead.

## Authentication
Every client in the call knows the secret key for all other clients so it can decrypt their traffic, it means a malicious client can impersonate any other client in the call by using the victim key to encrypt their traffic. This might not be a problem for consumer application where the number of clients in the call is small and users know each others, however for enterprise use case where large conference call is common, an authentication mechanism is needed to protect against malicious users. This authentication will come with extra cost.

Adding a digital signature to each encrypted frame will be an overkill, instead we propose adding signature over N frames. 

~~~~~
Signature = Sign(Hash(Frame1) || Hash(Frame(2) || ...|| Hash(FrameN))
~~~~~

Because some frames could be lost and never delivered, when the signature is sent, it will also send all the hashes it used to calculate the signature, and the recipient client will only use these hashes if they didn't receive the matching frame. For example Client A sends a signature	every 5 frames, so it sends the signature and Hash(Frame1), ...,Hash(Frame5), client B received only frames 1,2,4 and 5. When B receives the signature and the hashes, it will compute the hashes of frames 1,2,4 and 5 locally and use the received Hash(Frame3) to verify the signature. It is up to the application to decide what to do when signature verification fails.

The signature keys are exchanged out of band along the secret keys. 

# Overhead
The encryption overhead will vary between audio and video streams, because in audio each packet is considered a separate frame, so it will always have extra MAC and IV, however a video frame usually consists of multiple RTP packets.
The number of bytes overhead per frame is calculated as the following
1 + FrameCounter length + 4
The constant 1 is the frame counter header that has the srcId and frame counter length. The MAC length is constant 4 bytes even for video that uses 10 bytes length MAC because we assume the outer encryption will always use 4 bytes MAC length

## Audio
Using three different audio frame durations
20ms (50 packets/s)
40ms (25 packets/s)
100ms (10 packets/s)
Up to 3 bytes frame counter (3.8 days of data for 20ms frame duration) and 4 bytes fixed MAC length.

~~~~~
+------------+-----------+-----------+----------+-----------+
| Counter len| Packets   | Overhead  | Overhead | Overhead  |
|            |           | bps@20ms  | bps@40ms | bps@100ms |
+------------+-----------+-----------+----------+-----------+
|          1 | 0-255     |      2400 |     1200 |       480 |
|          2 | 255 - 65K |      2800 |     1400 |       560 |
|          3 | 65K - 16M |      3200 |     1600 |       640 |
+------------+--------- -+-----------+----------+-----------+
~~~~~

## Video
The per-stream overhead bits per second as calculated for the following video encodings:
30fps@1000Kbps (4 packets per frame)
30fps@512Kbps (2 packets per frame)
15fps@200Kbps (2 packets per frame)
7.5fps@30Kbps (1 packet per frame)
Overhead bps = (Counter length + 1 + 4 ) * 8 * fps

~~~~~
+------------+-----------+------------+------------+------------+
| Counter len| Frames    | Overhead   | Overhead   | Overhead   |
|            |           | bps@30fps  | bps@15fps  | bps@7.5fps |
+------------+-----------+------------+------------+------------+
|          1 | 0-255     |       1440 |       1440 |        720 |
|          2 | 256 - 65K |       1680 |       1680 |        840 |
|          3 | 56K - 16M |       1920 |       1920 |        960 |
|          4 | 16M - 4B  |       2160 |       2160 |       1080 |
+------------+-----------+------------+------------+------------+
~~~~~

## SFrame vs PERC-lite
PERC has significant overhead over SFrame because the overhead is per packet, not per frame, and OHB which duplicates any RTP header/extension field modified by the SFU.
PERC-Lite is slightly better because it doesn’t use the OHB anymore, however it still does per packet encryption using SRTP. 
Below the the ovherad in PERC_lite implemented by Cosmos Software which uses extra 11 bytes per packet to preserve the PT, SEQ_NUM, TIME_STAMP and SSRC fields in addition to the extra MAC tag per packet.

OverheadPerPacket = 11 + MAC length 
Overhead bps = PacketPerSecond * OverHeadPerPacket * 8

Similar to SFrame, we will assume the MAC length will always be 4 bytes for audio and video even though it is not the case in this PERC-lite implementation

### Audio
~~~~~
+-------------------+--------------------+--------------------+
| Overhead bps@20ms | Overhead  bps@40ms | Overhead bps@100ms |
+-------------------+--------------------+--------------------+
|              6000 |               3000 |               1200 |
+-------------------+--------------------+--------------------+
~~~~~

### Video
~~~~~
+---------------------+----------------------+-----------------------+
| Overhead  bps@30fps |  Overhead  bps@15fps |  Overhead  bps@7.5fps |
|(4 packets per frame)| (2 packets per frame)| (1 packet per frame)  |
+---------------------+----------------------+-----------------------+
|               14400 |                 7200 |                  3600 |
+---------------------+----------------------+-----------------------+
~~~~~

For a conference with a single incoming audio stream (@ 50 pps) and 4 incoming video streams (@200 Kbps), the savings in overhead is 34800 - 9600 = ~25 Kbps, or ~3%.


# Media Considerations

## Partial decoding
Some codes support partial decoding, where it can decrypt individual packets without waiting for the full frame to arrive, with SFrame this won't be possible because the decoder will not access the packets until the entire frame
Is arrived and decrypted. 

## SFU


# Security Considerations

## Key Management
Key exchange mechanism is out of scope of this document, however every client MUST change their keys when new clients joins or leaves the call for "Forward Secrecy" and "Post Compromise Security".

# IANA Considerations
This document makes no requests of IANA.
