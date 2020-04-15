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
E2E:
: End to End (AKA Inner Encryption)
HBH:
 Hob By Hob (AKA Outer Encryption)


# Background
Modern multi-part conference call systems include SFU server to efficiently forward the RTP streams to the end points based on their bandwidth. In order for the SFU to work properly it needs to access and modify some metadata about these streams which is not possible if the RTP packets are end to end encrypted and authenticated. So two layers of encryptions and authentication are required:
	1- E2E between the endpoints
	2- HBH between the the endpoints and SFU 
Intuitively SRTP+DTLS is used for HBH encryption, however it is more challenging to design the E2E encryption due to the bandwidth overhead.

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
We propose a media frame level encryption schema for the E2E layer to decrease the overhead by having a single IV and MAC per the media frame and not per RTP packet.

## Goals
Provide robust end-to-end encryption, using existing mechanisms
Allow partial encryption in order to facilitate routing of packets by SFUs
Minimize wire overhead for low-bandwidth scenarios
No dependencies on RTP (i.e., can be used in other protocols, e.g., data channels)


## Considerations
E2E encryption keys are exchanged between the endpoints out-of-bands using a secure channel
E2E keys should be changed whenever endpoints joins or leaves the call
Similar to SRTP, three keys are derived from the E2E master key
1- Salt key
2- Encryption key
3- Authentication key 
The RTP headers and header extensions are not authenticated end-to-end, SFUs are partially trusted to read and modify them.
The metadata required by SFUs is available in the RTP header extension, ideally by moving them from the payload to a generic payload metadata extension to avoid duplicating them for each RTP packet corresponding to the same media frame.
E2E IV is derived from a variable length frame counter which is included at the beginning of the first RTP packet of the frame. 
E2E uses 32bits MAC for audio frames and 80bits for video frames
HBH uses 32bits MAC for both audio and video packets.
Receiver endpoints can’t decode partial frames because they will have to wait for all packages of the frame to verify the MAC and decrypt it.


## Encryption Schema
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
  +---------------------------------------------------------------+ |
  |               generic payload header extension                | |
+^----------------------------------------------------------------+ |
| |                                                               | |
| |                      SFrame payload ....                      | |
| |                                                               | |
+^+---------------------------------------------------------------+^+
| :                  outer authentication tag                     : |
| +---------------------------------------------------------------+ |
|                                                                   |
++ Encrypted Portion*                      Authenticated Portion +--+
        (outer)                                  (outer)             
                        SFrame packet format    
~~~~~

In SFrame packets, the codec specific payload header will be moved to a generic payload header extension that is HBH authenticated , and could be HBH encrypted (Recommended) but not E2E encrypted nor authenticated. 

The SFrame payload is constructed by a generic packetizer that splits the E2E encrypted media frame into one or more RTP packet and add the SFrame header to the beginning of the first packet and auth tag to the end of the last packet.

The media payload will be encrypted , the media payload and SFrame header will be authenticated. The entire SFrame payload (header, media and auth tag) will be encrypted again for the HBH.

~~~~~


                          +---------------+                           
                          |               |                           
                          |               |                           
                          |     frame     |                           
                          |               |                           
                          |               |                           
                          +---------------+                           
                                                                      
                                   |                                  
          CTR +---------------> IV | key                              
                 derive IV         |                                  
           +                    encrypt                               
           |                       |                                  
           |                       v                                  
           |                                                          
           |               +---------------+                          
           |               |               |                          
           |               |   encrypted   |                          
           |               |     frame     |                          
           |               |               |                          
           |               |               |                          
           |               +---------------+                          
       encode CTR                                                     
           |               +---------------+         copy tag         
           |               |    auth tag   | +-----------------------+
           |               +---------------+                         |
           |                                                         |
           |                       +                                 |
           |                       |                                 |
           |                       |                                 |
           |              generic RTP packetize                      |
           |                       |                                 |
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

### SFrame header
Since each endpoint can send multiple media layers, each stream will have a unique frame counter that will be used to derive the encryption IV. To guarantee uniqueness across all streams and avoid IV reuse, the frame counter will have be prefixed by a stream id which will be 0 to N where N is the total number of outgoing streams.
The expected number of outgoing streams will be between 4 and 9 streams, so using 4 bits to support up to 16 streams should be good enough. 

The frame counter itself can be encoded in a variable length format to decrease the overhead, the following encoding schema is used 

~~~~~
+---------+---------------------------------+
|LEN |SRC |           CTR...                |
+---------+---------------------------------+
            SFrame header format 
~~~~~

LEN (4 bits)
The CTR length fields in bytes. 
SRC (4 bits)
4 bits source stream id
CTR (Variable length) 
Frame counter up to 16 bytes long

The IV is 128 bits long and calculated by the following:

~~~~~
IV = (SRC||CTR) XOR Salt key
~~~~~

### Encryption
Each frame is encrypted with a unique IV using AES_CTR and MAC using HMAC-SHA256.  Then the encrypted frame is split into multiple RTP packets using a generic RTP packetizer, and the encoded frame counter is added at the beginning of the first packet payload, while the MAC is added to the last packet of the frame payload 

### Decryption
When an endpoint receives all packets of a frame, it uses a generic RTP depacketizer to reconstruct the encrypted frame, Verifies the MAC code, then uses the frame counter in the encryption header to calculate the IV and decrypt the frame.

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
+----------------+---------------+-------------------+--------------------+--------------------+
| Counter length | Packets count | Overhead bps@20ms | Overhead  bps@40ms | Overhead bps@100ms |
+----------------+---------------+-------------------+--------------------+--------------------+
|              1 | 0-255         |              2400 |               1200 |                480 |
|              2 | 255 - 65K     |              2800 |               1400 |                560 |
|              3 | 65K - 16M     |              3200 |               1600 |                640 |
+----------------+---------------+-------------------+--------------------+--------------------+
~~~~~

## Video
The per-stream overhead bits per second as calculated for the following video encodings:
30fps@1000Kbps (4 packets per frame)
30fps@512Kbps (2 packets per frame)
15fps@200Kbps (2 packets per frame)
7.5fps@30Kbps (1 packet per frame)
Overhead bps = (Counter length + 1 + 4 ) * 8 * fps

~~~~~
+----------------+--------------+---------------------+---------------------+----------------------+
| Counter Length | Frames count | Overhead  bps@30fps | Overhead  bps@15fps | Overhead  bps@7.5fps |
+----------------+--------------+---------------------+---------------------+----------------------+
|              1 | 0-255        |                1440 |                1440 |                  720 |
|              2 | 256 - 65K    |                1680 |                1680 |                  840 |
|              3 | 56K - 16M    |                1920 |                1920 |                  960 |
|              4 | 16M - 4B     |                2160 |                2160 |                 1080 |
+----------------+--------------+---------------------+---------------------+----------------------+
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
+-----------------------+------------------------+-------------------------+
| Overhead  bps@30fps   |  Overhead  bps@15fps   |  Overhead  bps@7.5fps   |
|(4 packets per frame)  | (2 packets per frame). | (1 packet per frame)    |
+-----------------------+------------------------+-------------------------+
|                 14400 |                   7200 |                    3600 |
+-----------------------+------------------------+-------------------------+
~~~~~

For a conference with a single incoming audio stream (@ 50 pps) and 4 incoming video streams (@200 Kbps), the savings in overhead is 34800 - 9600 = ~25 Kbps, or ~3%.


# Security Considerations


# IANA Considerations
This document makes no requests of IANA.
