---
title: Secure Frame (SFrame)
abbrev: SFrame
docname: draft-ietf-sframe-enc-latest
category: std

ipr: trust200902
stream: IETF
area: "Applications and Real-Time"
keyword: Internet-Draft
v: 3
venue:
  group: "Secure Media Frames"
  type: "Working Group"
  mail: "sframe@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/sframe/"
  github: "sframe-wg/sframe"
  latest: "https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html"

author:
 -
    ins: E. Omara
    name: Emad Omara
    organization: Apple
    email: eomara@apple.com
 -
    ins: J. Uberti
    name: Justin Uberti
    organization: Google
    email: juberti@google.com
 -
    ins: S. Murillo
    name: Sergio Garcia Murillo
    organization: CoSMo Software
    email: sergio.garcia.murillo@cosmosoftware.io
 -
    ins: R.L. Barnes
    name: Richard L. Barnes
    organization: Cisco
    email: rlb@ipv.sx
    role: editor
 -
    ins: Y. Fablet
    name: Youenn Fablet
    organization: Apple
    email: youenn@apple.com

informative:
  TestVectors:
    title: "SFrame Test Vectors"
    target: https://github.com/eomara/sframe/blob/master/test-vectors.json
    date: 2021


--- abstract

This document describes the Secure Frame (SFrame) end-to-end encryption and
authentication mechanism for media frames in a multiparty conference call, in
which central media servers (selective forwarding units or SFUs) can access the
media metadata needed to make forwarding decisions without having access to the
actual media.

The proposed mechanism differs from the Secure Real-Time Protocol (SRTP) in that
it is independent of RTP (thus compatible with non-RTP media transport) and can
be applied to whole media frames in order to be more bandwidth efficient.

--- middle


# Introduction

Modern multi-party video call systems use Selective Forwarding Unit (SFU)
servers to efficiently route RTP streams to call endpoints based on factors such
as available bandwidth, desired video size, codec support, and other factors. An
SFU typically does not need access to the media content of the conference,
allowing for the media to be "end-to-end" encrypted so that it cannot be
decrypted by the SFU. In order for the SFU to work properly, though, it usually
needs to be able to access RTP metadata and RTCP feedback messages, which is not
possible if all RTP/RTCP traffic is end-to-end encrypted.

As such, two layers of encryptions and authentication are required:

  1. Hop-by-hop (HBH) encryption of media, metadata, and feedback messages
     between the the endpoints and SFU
  2. End-to-end (E2E) encryption of media between the endpoints

The Secure Real-Time Protocol (SRTP) is already widely used for HBH encryption
{{?RFC3711}}. The SRTP "double encryption" scheme defines a way to do E2E
encryption in SRTP {{?RFC8723}}. Unfortunately, this scheme has poor efficiency
and high complexity, and its entanglement with RTP makes it unworkable in
several realistic SFU scenarios.

This document proposes a new end-to-end encryption mechanism known as SFrame,
specifically designed to work in group conference calls with SFUs. SFrame is a
general encryption framing that can be used to protect payloads sent over SRTP

~~~ aasvg
   +---+-+-+-------+-+-------------+-------------------------------+<-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |  |
   +---+-+-+-------+-+-------------+-------------------------------+  |
   |                           timestamp                           |  |
   +---------------------------------------------------------------+  |
   |           synchronization source (SSRC) identifier            |  |
   +===============================================================+  |
   |            contributing source (CSRC) identifiers             |  |
   |                               ....                            |  |
   +---------------------------------------------------------------+  |
   |                   RTP extension(s) (OPTIONAL)                 |  |
+->+--------------------+------------------------------------------+  |
|  |   SFrame header    |                                          |  |
|  +--------------------+                                          |  |
|  |                                                               |  |
|  |          SFrame encrypted and authenticated payload           |  |
|  |                                                               |  |
+->+---------------------------------------------------------------+<-+
|  |                    SRTP authentication tag                    |  |
|  +---------------------------------------------------------------+  |
|                                                                     |
+--- SRTP Encrypted Portion             SRTP Authenticated Portion ---+
~~~~~
{: title="SRTP packet with SFrame-protected payload"}

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
: End to End Encryption

HBH:
: Hop By Hop

# Goals

SFrame is designed to be a suitable E2EE protection scheme for conference call
media in a broad range of scenarios, as outlined by the following goals:

1. Provide an secure E2EE mechanism for audio and video in conference calls
   that can be used with arbitrary SFU servers.

2. Decouple media encryption from key management to allow SFrame to be used
   with an arbitrary key management system.

3. Minimize packet expansion to allow successful conferencing in as many
   network conditions as possible.

4. Independence from the underlying transport, including use in non-RTP
   transports, e.g., WebTransport.

5. When used with RTP and its associated error resilience mechanisms, i.e., RTX
   and FEC, require no special handling for RTX and FEC packets.

6. Minimize the changes needed in SFU servers.

7. Minimize the changes needed in endpoints.

8. Work with the most popular audio and video codecs used in conferencing
   scenarios.


# SFrame

This document defines an encryption mechanism that provides effective end-to-end
encryption, is simple to implement, has no dependencies on RTP, and minimizes
encryption bandwidth overhead. Because SFrame can encrypt a full frame, rather
than individual packets, bandwidth overhead can be reduced by adding encryption
overhead only once per media frame, instead of once per packet.

## Application Context

SFrame is a general encryption framing, which is typically applied in one of two
ways: Either to encrypt whole media frames (per-frame) or individual media
payloads (per-packet).  The scale at which SFrame encryption is applied to media
determines the overall amount of overhead that SFrame adds to the media stream,
as well as the engineering complexity involved in integrating SFrame into a
particular environment.

For example, {{media-stack}} shows a typical media stack that takes media in
from some source, encodes it into frames, divides those frames into media
payloads, and then sends those payloads in SRTP packets.  Arrows indicate the
points where SFrame protection would be integrated into this media stack, when
applied per-frame or per-packet.

Applying SFrame per-frame in this system offers higher efficiency, but may
require a more complex integration in environments where depacketization relies
on the content of media packets. Applying SFrame per-packet avoids this
complexity, at the cost of higher bandwidth consumption.  Some quantitative
discussion of these trade-offs is provided in {{overhead-analysis}}.

As noted above, however, SFrame is a general media encapsulation, and can be
applied in other scenarios.  The precise efficiency and complexity trade-offs
will depend on the environment in which SFrame is being integrated.

~~~ aasvg
      +--------------------------------------------------------+
      |                                                        |
      |  +----------+      +-------------+      +-----------+  |
 .-.  |  |          |      |             |      |   SRTP    |  |
|   | |  |  Encode  |----->|  Packetize  |----->|  Encrypt  |-----------+
 '+'  |  |          |  ^   |             |  ^   |           |  |        |
 /|\  |  +----------+  |   +-----+-------+  |   +-----------+  |        |
/ + \ |                |         ^          |         ^        |        |
 / \  |              SFrame      |       SFrame       |        |        |
/   \ |              Protect     |       Protect      |        |        |
Alice |            (per-frame)   |     (per-packet)   |        |        |
      +--------------------------|--------------------|--------+        |
                                 |                    |                 v
                                 |                    |           +-----+------+
                       E2E Key   |          HBH Key   |           |   Media    |
                      Management |         Management |           |   Server   |
                                 |                    |           +-----+------+
                                 |                    |                 |
      +--------------------------|--------------------|--------+        |
 .-.  |              SFrame      |        SFrame      |        |        |
|   | |             Unprotect    |       Unprotect    |        |        |
 '+'  |            (per-frame)   |      (per-packet)  |        |        |
 /|\  |                 |        V           |        V        |        |
/ + \ |  +----------+   |  +-----+-------+   |  +-----------+  |        |
 / \  |  |          |   V  |             |   V  |   SRTP    |  |        |
/   \ |  |  Decode  |<-----| Depacketize |<-----|  Decrypt  |<----------+
 Bob  |  |          |      |             |      |           |  |
      |  +----------+      +-------------+      +-----------+  |
      |                                                        |
      +--------------------------------------------------------+
~~~~~
{: #media-stack "Integration of SFrame in a typical media stack" }

Like SRTP, SFrame does not define how the keys used for SFrame are exchanged by
the parties in the conference.  Keys for SFrame might be distributed over an
existing E2E-secure channel (see {{sender-keys}}), or derived from an E2E-secure
shared secret (see {{mls}}).  The key management system MUST ensure that each
key used for encrypting media is used by exactly one media sender, in order to
avoid reuse of IVs.

## SFrame Ciphertext

An SFrame ciphertext comprises an SFrame header followed by the output of an
AEAD encryption of the plaintext {{!RFC5116}}, with the header provided as additional
authenticated data (AAD).

The SFrame header is a variable-length structure described in detail in
{{sframe-header}}.  The structure of the encrypted data and authentication tag
are determined by the AEAD algorithm in use.

~~~ aasvg
  +-+---+-+----+------------------------------------------+^+
  |S|LEN|X|KID |         Frame Counter                    | |
+^+-+---+-+----+------------------------------------------+ |
| |                                                       | |
| |                                                       | |
| |                                                       | |
| |                                                       | |
| |                   Encrypted Data                      | |
| |                                                       | |
| |                                                       | |
| |                                                       | |
| |                                                       | |
+>+-------------------------------------------------------+<+
| |                 Authentication Tag                    | |
| +-------------------------------------------------------+ |
|                                                           |
|                                                           |
+---- Encrypted Portion            Authenticated Portion ---+
~~~~~

When SFrame is applied per-packet, the payload of each packet will be an SFrame
ciphertext.  When SFrame is applied per-frame, the SFrame ciphertext
representing an encrypted frame will span several packets, with the header
appearing in the first packet and the authentication tag in the last packet.

## SFrame Header

The SFrame header specifies two values from which encryption parameters are
derived:

* A Key ID (KID) that determines which encryption key should be used
* A counter (CTR) that is used to construct the IV for the encryption

Applications MUST ensure that each (KID, CTR) combination is used for exactly
one encryption operation.  Typically this is done by assigning each sender a KID
or set of KIDs, then having each sender use the CTR field as a monotonic
counter, incrementing for each plaintext that is encrypted.  Note that in
addition to its simplicity, this scheme minimizes overhead by keeping CTR values
as small as possible.

Both the counter and the key id are encoded as integers in network (big-endian)
byte order, in a variable length format to decrease the overhead.  The length of
each field is up to 8 bytes and is represented in 3 bits in the SFrame header:
000 represents a length of 1, 001 a length of 2, etc.

The first byte in the SFrame header has a fixed format and contains the header
metadata:

~~~~~ aasvg
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|R| LEN |X|  K  |
+-+-+-+-+-+-+-+-+
~~~~~
{: title="SFrame header metadata"}

Reserved (R, 1 bit):
: This field MUST be set to zero on sending, and MUST be ignored by receivers.

Counter Length (LEN, 3 bits):
: This field indicates the length of the CTR field in bytes, minus one (the
range of possible values is thus 1-8).

Extended Key Id Flag (X, 1 bit):
: Indicates if the key field contains the key id or the key length.

Key or Key Length (K, 3 bits):
: This field contains the key id (KID) if the X flag is set to 0, or the key
length (KLEN) if set to 1.

If X flag is 0, then the KID is in the range of 0-7 and the counter (CTR) is
found in the next LEN bytes:

~~~~~ aasvg
 0 1 2 3 4 5 6 7
+-+-----+-+-----+---------------------------------+
|R|LEN  |0| KID |    CTR... (length=LEN)          |
+-+-----+-+-----+---------------------------------+
~~~~~
{: title="SFrame header with short KID" }

If X flag is 1 then KLEN is the length of the key (KID) in bytes, minus one
(the range of possible lengths is thus 1-8). The KID is encoded in
the KLEN bytes following the metadata byte, and the counter (CTR) is encoded
in the next LEN bytes:

~~~~~ aasvg
 0 1 2 3 4 5 6 7
+-+-----+-+-----+---------------------------+---------------------------+
|R|LEN  |1|KLEN |   KID... (length=KLEN)    |    CTR... (length=LEN)    |
+-+-----+-+-----+---------------------------+---------------------------+
~~~~~

## Encryption Schema

SFrame encryption uses an AEAD encryption algorithm and hash function defined by
the ciphersuite in use (see {{ciphersuites}}).  We will refer to the following
aspects of the AEAD algorithm below:

* `AEAD.Encrypt` and `AEAD.Decrypt` - The encryption and decryption functions
  for the AEAD.  We follow the convention of RFC 5116 {{!RFC5116}} and consider
  the authentication tag part of the ciphertext produced by `AEAD.Encrypt` (as
  opposed to a separate field as in SRTP {{?RFC3711}}).

* `AEAD.Nk` - The size of a key for the encryption algorithm, in bytes

* `AEAD.Nn` - The size of a nonce for the encryption algorithm, in bytes

* `AEAD.Nt` - The overhead of the encryption algorithm, in bytes (typically the
  size of a "tag" that is added to the plaintext)

### Key Selection

Each SFrame encryption or decryption operation is premised on a single secret
`base_key`, which is labeled with an integer KID value signaled in the SFrame
header.

The sender and receivers need to agree on which key should be used for a given
KID.  The process for provisioning keys and their KID values is beyond the scope
of this specification, but its security properties will bound the assurances
that SFrame provides.  For example, if SFrame is used to provide E2E security
against intermediary media nodes, then SFrame keys need to be negotiated in a
way that does not make them accessible to these intermediaries.

For each known KID value, the client stores the corresponding symmetric key
`base_key`.  For keys that can be used for encryption, the client also stores
the next counter value CTR to be used when encrypting (initially 0).

When encrypting a plaintext, the application specifies which KID is to be used,
and the counter is incremented after successful encryption.  When decrypting,
the `base_key` for decryption is selected from the available keys using the KID
value in the SFrame Header.

A given key MUST NOT be used for encryption by multiple senders.  Such reuse
would result in multiple encrypted frames being generated with the same (key,
nonce) pair, which harms the protections provided by many AEAD algorithms.
Implementations SHOULD mark each key as usable for encryption or decryption,
never both.

Note that the set of available keys might change over the lifetime of a
real-time session.  In such cases, the client will need to manage key usage to
avoid media loss due to a key being used to encrypt before all receivers are
able to use it to decrypt.  For example, an application may make decryption-only
keys available immediately, but delay the use of keys for encryption until (a)
all receivers have acknowledged receipt of the new key or (b) a timeout expires.

### Key Derivation

SFrame encrytion and decryption use a key and salt derived from the `base_key`
associated to a KID.  Given a `base_key` value, the key and salt are derived
using HKDF {{!RFC5869}} as follows:

~~~~~
sframe_secret = HKDF-Extract(base_key, 'SFrame 1.0 ' + KID)
sframe_key = HKDF-Expand(sframe_secret, 'key', AEAD.Nk)
sframe_salt = HKDF-Expand(sframe_secret, 'salt', AEAD.Nn)
~~~~~

In the derivation of `sframe_secret`, the `+` operator represents concatenation
of octet strings and the KID value is encoded as an 8-byte big-endian integer
(not the compressed form used in the SFrame header).

The hash function used for HKDF is determined by the ciphersuite in use.

### Encryption

SFrame encryption uses the AEAD encryption algorithm for the ciphersuite in use.
The key for the encryption is the `sframe_key` and the nonce is formed by XORing
the `sframe_salt` with the current counter, encoded as a big-endian integer of
length `AEAD.Nn`.

The encryptor forms an SFrame header using the CTR, and KID values provided.
The encoded header is provided as AAD to the AEAD encryption operation, together
with application-provided metadata about the encrypted media.

~~~~~
def encrypt(S, CTR, KID, metadata, plaintext):
  sframe_key, sframe_salt = key_store[KID]

  ctr = encode_big_endian(CTR, AEAD.Nn)
  nonce = xor(sframe_salt, CTR)

  header = encode_sframe_header(CTR, KID)
  aad = header + metadata

  ciphertext = AEAD.Encrypt(sframe_key, nonce, aad, plaintext)
  return header + ciphertext
~~~~~

The metadata input to encryption allows for frame metadata to be authenticated
when SFrame is applied per-frame.  After encoding the frame and before
packetizing it, the necessary media metadata will be moved out of the encoded
frame buffer, to be sent in some channel visibile to the SFU (e.g., an RTP
header extension).

The encrypted payload is then passed to a generic RTP packetizer to construct
the RTP packets and encrypt it using SRTP keys for the HBH encryption to the
media server.

~~~ aasvg

   +----------------+  +---------------+
   | frame metadata |  |               |
   +-------+--------+  |               |
           |           |     frame     |
           |           |               |
           |           |               |
           |           +-------+-------+
           |                   |
header ----+------------------>| AAD
+-----+                        |
|  S  |                        |
+-----+                        |
| KID +--+--> sframe_key ----->| Key
|     |  |                     |
|     |  +--> sframe_salt --+  |
+-----+                     |  |
| CTR +---------------------+->| Nonce
|     |                        |
|     |                        |
+-----+                        |
   |                       AEAD.Encrypt
   |                           |
   |                           V
   |                   +-------+-------+
   |                   |               |
   |                   |               |
   |                   |   encrypted   |
   |                   |     frame     |
   |                   |               |
   |                   |               |
   |                   +-------+-------+
   |                           |
   |                  generic RTP packetize
   |                           |
   |                           |
   |    +----------------------+--------.....--------+
   |    |                      |                     |
   V    V                      V                     V
+---------------+      +---------------+     +---------------+
| SFrame header |      |               |     |               |
+---------------+      |               |     |               |
|               |      |  payload 2/N  | ... |  payload N/N  |
|  payload 1/N  |      |               |     |               |
|               |      |               |     |               |
+---------------+      +---------------+     +---------------+
~~~~~
{: title="Encryption flow with per-frame encryption" }

### Decryption

Before decrypting, a client needs to assemble a full SFrame ciphertext.  When
SFrame is applied per-packet, this is done by extracting the payload of a
decrypted SRTP packet.  When SFrame is applied per-frame, the receiving client
buffers all packets that belongs to the same frame using the frame beginning and
ending marks in the generic RTP frame header extension. Once all packets are
available and in order, the receiver forms an SFrame ciphertext by concatenating
their payloads, then passes the ciphertext to SFrame for decryption.

The KID field in the SFrame header is used to find the right key and salt for
the encrypted frame, and the CTR field is used to construct the nonce.

~~~~~
def decrypt(metadata, sframe):
  CTR, KID, ciphertext = parse_ciphertext(sframe)

  sframe_key, sframe_salt = key_store[KID]

  ctr = encode_big_endian(CTR, AEAD.Nn)
  nonce = xor(sframe_salt, ctr)
  aad = header + metadata

  return AEAD.Decrypt(sframe_key, nonce, aad, ciphertext)
~~~~~

If a ciphertext fails to decrypt because there is no key available for the KID
in the SFrame header, the client MAY buffer the ciphertext and retry decryption
once a key with that KID is received.

### Duplicate Frames

Unlike messaging application, in video calls, receiving a duplicate frame
doesn't necessarily mean the client is under a replay attack, there are other
reasons that might cause this, for example the sender might just be sending them
in case of packet loss. SFrame decryptors use the highest received frame counter
to protect against this. It allows only older frame pithing a short interval to
support out of order delivery.

## Ciphersuites

Each SFrame session uses a single ciphersuite that specifies the following
primitives:

* A hash function used for key derivation

* An AEAD encryption algorithm [RFC5116] used for frame encryption, optionally
  with a truncated authentication tag

This document defines the following ciphersuites:

| Value  | Name                          | Nh | Nk | Nn | Nt | Reference |
|:-------|:------------------------------|:---|----|:---|:---|:----------|
| 0x0001 | `AES_CTR_128_HMAC_SHA256_80`  | 32 | 16 | 12 | 10 | RFC XXXX  |
| 0x0002 | `AES_CTR_128_HMAC_SHA256_64`  | 32 | 16 | 12 |  8 | RFC XXXX  |
| 0x0003 | `AES_CTR_128_HMAC_SHA256_32`  | 32 | 16 | 12 |  4 | RFC XXXX  |
| 0x0004 | `AES_GCM_128_SHA256_128`      | 32 | 16 | 12 | 16 | RFC XXXX  |
| 0x0005 | `AES_GCM_256_SHA512_128`      | 64 | 32 | 12 | 16 | RFC XXXX  |


<!-- RFC EDITOR: Please replace XXXX above with the RFC number assigned to this
document -->

In the suite names, the length of the authentication tag is indicated by
the last value: "\_128" indicates a hundred-twenty-eight-bit tag, "\_80" indicates
a eighty-bit tag, "\_64" indicates a sixty-four-bit tag and "\_32" indicates a
thirty-two-bit tag.

In a session that uses multiple media streams, different ciphersuites might be
configured for different media streams.  For example, in order to conserve
bandwidth, a session might use a ciphersuite with eighty-bit tags for video frames
and another ciphersuite with thirty-two-bit tags for audio frames.

### AES-CTR with SHA2

In order to allow very short tag sizes, we define a synthetic AEAD function
using the authenticated counter mode of AES together with HMAC for
authentication.  We use an encrypt-then-MAC approach as in SRTP {{?RFC3711}}.

Before encryption or decryption, encryption and authentication subkeys are
derived from the single AEAD key using HKDF.  The subkeys are derived as
follows, where `Nk` represents the key size for the AES block cipher in use and
`Nh` represents the output size of the hash function:

~~~~~
def derive_subkeys(sframe_key):
  aead_secret = HKDF-Extract(sframe_key, 'SFrame10 AES CTR AEAD')
  enc_key = HKDF-Expand(aead_secret, 'enc', Nk)
  auth_key = HKDF-Expand(aead_secret, 'auth', Nh)
  return enc_key, auth_key
~~~~~

The AEAD encryption and decryption functions are then composed of individual
calls to the CTR encrypt function and HMAC.  The resulting MAC value is truncated
to a number of bytes `tag_len` fixed by the ciphersuite.

~~~~~
def compute_tag(auth_key, nonce, aad, ct):
  aad_len = encode_big_endian(len(aad), 8)
  ct_len = encode_big_endian(len(ct), 8)
  auth_data = aad_len + ct_len + nonce + aad + ct
  tag = HMAC(auth_key, auth_data)
  return truncate(tag, tag_len)

def AEAD.Encrypt(key, nonce, aad, pt):
  enc_key, auth_key = derive_subkeys(key)
  ct = AES-CTR.Encrypt(enc_key, nonce, pt)
  tag = compute_tag(auth_key, nonce, aad, ct)
  return ct + tag

def AEAD.Decrypt(key, nonce, aad, ct):
  inner_ct, tag = split_ct(ct, tag_len)

  enc_key, auth_key = derive_subkeys(key)
  candidate_tag = compute_tag(auth_key, nonce, aad, inner_ct)
  if !constant_time_equal(tag, candidate_tag):
    raise Exception("Authentication Failure")

  return AES-CTR.Decrypt(enc_key, nonce, inner_ct)
~~~~~

# Key Management

SFrame must be integrated with an E2E key management framework to exchange and
rotate the keys used for SFrame encryption. The key management
framework provides the following functions:

* Provisioning KID/`base_key` mappings to participating clients
* Updating the above data as clients join or leave

It is up to the application to define a rotation schedule for keys.  For example,
one application might have an ephemeral group for every call and keep rotating key
when end points joins or leave the call, while another application could have a
persistent group that can be used for multiple calls and simply derives
ephemeral symmetric keys for a specific call.

## Sender Keys

If the participants in a call have a pre-existing E2E-secure channel, they can
use it to distribute SFrame keys.  Each client participating in a call generates
a fresh encryption key. The client then uses
the E2E-secure channel to send their encryption key to
the other participants.

In this scheme, it is assumed that receivers have a signal outside of SFrame for
which client has sent a given frame, for example the RTP SSRC.  SFrame KID
values are then used to distinguish generations of the sender's key.  At the
beginning of a call, each sender encrypts with KID=0.  Thereafter, the sender
can ratchet their key forward for forward secrecy:

~~~~~
sender_key[i+1] = HKDF-Expand(
                    HKDF-Extract(sender_key[i], 'SFrame10 ratchet'),
                      '', AEAD.Nk)
~~~~~

The sender signals such an update by incrementing their KID value.  A receiver
who receives from a sender with a new KID computes the new key as above.  The
old key may be kept for some time to allow for out-of-order delivery, but should
be deleted promptly.

If a new participant joins mid-call, they will need to receive from each sender
(a) the current sender key for that sender and (b) the current KID value for the
sender. Evicting a participant requires each sender to send a fresh sender key
to all receivers.

## MLS

The Messaging Layer Security (MLS) protocol provides group authenticated key
exchange {{?I-D.ietf-mls-architecture}} {{?I-D.ietf-mls-protocol}}.  In
principle, it could be used to instantiate the sender key scheme above, but it
can also be used more efficiently directly.

MLS creates a linear sequence of keys, each of which is shared among the members
of a group at a given point in time.  When a member joins or leaves the group, a
new key is produced that is known only to the augmented or reduced group.  Each
step in the lifetime of the group is know as an "epoch", and each member of the
group is assigned an "index" that is constant for the time they are in the
group.

To generate keys and nonces for SFrame, we use the MLS exporter function to
generate a `base_key` value for each MLS epoch.  Each member of the group is
assigned a unique KID value, so that each member has a unique `sframe_key` and
`sframe_salt` that it uses to encrypt with.

~~~~~
base_key = MLS-Exporter("SFrame 1.0", "", AEAD.Nk)
~~~~~

For compactness, we do not send the whole epoch number.  Instead, we send only its
low-order E bits.  Note that E effectively defines a re-ordering window, since
no more than 2^E epochs can be active at a given time.  Receivers MUST be
prepared for the epoch counter to roll over, removing an old epoch when a new
epoch with the same E lower bits is introduced.  (Sender indices cannot be
similarly compressed.)

~~~~~
KID = (sender_index << E) + (epoch % (1 << E))
~~~~~

Once an SFrame stack has been provisioned with the `sframe_epoch_secret` for an
epoch, it can compute the required KIDs and `sender_base_key` values on demand,
as it needs to encrypt/decrypt for a given member.

~~~ aasvg
  ...
         |
Epoch 17 +--+-- index=33 --> KID = 0x211
         |  |
         |  +-- index=51 --> KID = 0x331
         |
         |
Epoch 16 +--+-- index=2 ---> KID = 0x20
         |
         |
Epoch 15 +--+-- index=3 ---> KID = 0x3f
         |  |
         |  +-- index=5 ---> KID = 0x5f
         |
         |
Epoch 14 +--+-- index=3 ---> KID = 0x3e
         |  |
         |  +-- index=7 ---> KID = 0x7e
         |  |
         |  +-- index=20 --> KID = 0x14e
         |
  ...
~~~~~

# Media Considerations

## SFU

Selective Forwarding Units (SFUs) as described in {{Section 3.7 of ?RFC7667}}
receive the RTP streams from each participant and select which ones should be
forwarded to each of the other participants.  There are several approaches about
how to do this stream selection but in general, in order to do so, the SFU needs
to access metadata associated to each frame and modify the RTP information of
the incoming packets when they are transmitted to the received participants.

This section describes how this normal SFU modes of operation interacts with the
E2EE provided by SFrame

### LastN and RTP stream reuse

The SFU may choose to send only a certain number of streams based on the voice
activity of the participants. To reduce the number of SDP O/A required to
establish a new RTP stream, the SFU may decide to reuse previously existing RTP
sessions or even pre-allocate a predefined number of RTP streams and choose in
each moment in time which participant media will be sending through it.

This means that in the same RTP stream (defined by either SSRC or MID) may carry
media from different streams of different participants. As different keys are
used by each participant for encoding their media, the receiver will be able to
verify which is the sender of the media coming within the RTP stream at any
given point in time, preventing the SFU trying to impersonate any of the
participants with another participant's media.

Note that in order to prevent impersonation by a malicious participant (not the
SFU), a mechanism based on digital signature would be required. SFrame does not
protect against such attacks.

### Simulcast

When using simulcast, the same input image will produce N different encoded
frames (one per simulcast layer) which would be processed independently by the
frame encryptor and assigned an unique counter for each.

### SVC

In both temporal and spatial scalability, the SFU may choose to drop layers in
order to match a certain bitrate or forward specific media sizes or frames per
second. In order to support it, the sender MUST encode each spatial layer of a
given picture in a different frame. That is, an RTP frame may contain more than
one SFrame encrypted frame with an incrementing frame counter.

## Video Key Frames

Forward and Post-Compromise Security requires that the e2ee keys are updated
anytime a participant joins/leave the call.

The key exchange happens asynchronously and on a different path than the SFU signaling
and media. So it may happen that when a new participant joins the call and the
SFU side requests a key frame, the sender generates the e2ee encrypted frame
with a key not known by the receiver, so it will be discarded. When the sender
updates his sending key with the new key, it will send it in a non-key frame, so
the receiver will be able to decrypt it, but not decode it.

Receiver will re-request an key frame then, but due to sender and SFU policies,
that new key frame could take some time to be generated.

If the sender sends a key frame when the new e2ee key is in use, the time
required for the new participant to display the video is minimized.

## Partial Decoding

Some codes support partial decoding, where it can decrypt individual packets
without waiting for the full frame to arrive, with SFrame this won't be possible
because the decoder will not access the packets until the entire frame has
arrived and was decrypted.

# Security Considerations

## No Per-Sender Authentication

SFrame does not provide per-sender authentication of media data.  Any sender in
a session can send media that will be associated with any other sender.  This is
because SFrame uses symmetric encryption to protect media data, so that any
receiver also has the keys required to encrypt packets for the sender.

## Key Management

Key exchange mechanism is out of scope of this document, however every client
SHOULD change their keys when new clients joins or leaves the call for "Forward
Secrecy" and "Post Compromise Security".

## Authentication tag length

The cipher suites defined in this draft use short authentication tags for
encryption, however it can easily support other ciphers with full authentication
tag if the short ones are proved insecure.

# IANA Considerations

This document makes no requests of IANA.

--- back

# Acknowledgements

The authors wish to specially thank Dr. Alex Gouaillard as one of the early
contributors to the document. His passion and energy were key to the design and
development of SFrame.

# Overhead Analysis

Any use of SFrame will impose overhead in terms of the amount of bandwidth
necessary to transmit a given media stream.  Exactly how much overhead will be added
depends on several factors:

* How many senders are involved in a conference (length of KID)
* How long the conference has been going on (length of CTR)
* The ciphersuite in use (length of authentication tag)
* Whether SFrame is used to encrypt packets, whole frames, or some other unit

Overall, the overhead rate in kilobits per second can be estimated as:

```
OverheadKbps = (1 + |CTR| + |KID| + |TAG|) * 8 * CTPerSecond / 1024
```

Here the constant value `1` reflects the fixed SFrame header; `|CTR|` and
`|KID|` reflect the lengths of those fields; `|TAG|` reflects the cipher
overhead; and `CTPerSecond` reflects the number of SFrame ciphertexts
sent per second (e.g., packets or frames per second).

In the remainder of this secton, we compute overhead estimates for a collection
of common scenarios.

## Assumptions

In the below calculations, we make conservative assumptions about SFrame
overhead, so that the overhead amounts we compute here are likely to be an upper
bound on those seen in practice.

| Field           | Bytes | Explanataion                                      |
|:----------------|------:|:--------------------------------------------------|
| Fixed header    | 1     | Fixed                                             |
| Key ID (KID)    | 2     | >255 senders; or MLS epoch (E=4) and >16 senders  |
| Counter (CTR)   | 3     | More than 24 hours of media in common cases       |
| Cipher overhead | 16    | Full GCM tag (longest defined here)               |

In total, then, we assume that each SFrame encryption will add 22 bytes of
overhead.

We consider two scenarios, applying SFrame per-frame and per-packet.  In each
scenario, we compute the SFrame overhead in absolute terms (Kbps) and as a
percentage of the base bandwidth.

## Audio

In audio streams, there is typically a one-to-one relationship between frames
and packets, so the overhead is the same whether one uses SFrame at a per-packet
or per-frame level.

The below table considers three scenarios, based on recommended configurations
of the Opus codec {{?RFC6716}}:

* Narrow-band speech: 120ms packets, 8Kbps
* Full-band speech: 20ms packets, 32Kbps
* Full-band stereo music: 10ms packets, 128Kbps

| Scenario                 | fps | Base Kbps | Overhead Kbps | Overhead % |
|:-------------------------|:---:|:---------:|:-------------:|:----------:|
| NB speech, 120ms packets | 8.3 |         8 |           1.4 |      17.9% |
| FB speech, 20ms packets  |  50 |        32 |           8.6 |      26.9% |
| FB stereo, 10ms packets  | 100 |       128 |          17.2 |      13.4% |
{: #audio-overhead title="SFrame overhead for audio streams" }

## Video

Video frames can be larger than an MTU and thus are commonly split across
multiple frames.  {{video-overhead-per-frame}} and {{video-overhead-per-packet}}
show the estimated overhead of encrypting a video stream, where SFrame is
applied per-frame and per-packet, respectively.  The choices of resolution,
frames per second, and bandwidth are chosen to roughly reflect the capabilities of
modern video codecs across a range from very low to very high quality.

| Scenario    | fps | Base Kbps | Overhead Kbps | Overhead % |
|:------------|:---:|:---------:|:-------------:|:----------:|
| 426 x 240   | 7.5 |        45 |           1.3 |       2.9% |
| 640 x 360   |  15 |       200 |           2.6 |       1.3% |
| 640 x 360   |  30 |       400 |           5.2 |       1.3% |
| 1280 x 720  |  30 |      1500 |           5.2 |       0.3% |
| 1920 x 1080 |  60 |      7200 |          10.3 |       0.1% |
{: #video-overhead-per-frame title="SFrame overhead for a video stream encrypted per-frame" }

| Scenario    | fps | pps | Base Kbps | Overhead Kbps | Overhead % |
|:------------|:---:|:---:|:---------:|:-------------:|:----------:|
| 426 x 240   | 7.5 | 7.5 |        45 |           1.3 |       2.9% |
| 640 x 360   |  15 |  30 |       200 |           5.2 |       2.6% |
| 640 x 360   |  30 |  60 |       400 |          10.3 |       2.6% |
| 1280 x 720  |  30 | 180 |      1500 |          30.9 |       2.1% |
| 1920 x 1080 |  60 | 780 |      7200 |         134.1 |       1.9% |
{: #video-overhead-per-packet title="SFrame overhead for a video stream encrypted per-packet" }

In the per-frame case, the SFrame percentage overhead approaches zero as the
quality of the video goes up, since bandwidth is driven more by picture size
than frame rate.  In the per-packet case, the SFrame percentage overhead
approaches the ratio between the SFrame overhead per packet and the MTU (here 22
bytes of SFrame overhead divided by an assumed 1200-byte MTU, or about 1.8%).

## Conferences

Real conferences usually involve several audio and video streams.  The overhead
of SFrame in such a conference is the aggregate of the overhead over all the
individual streams.  Thus, while SFrame incurs a large percentage overhead on an
audio stream, if the conference also involves a video stream, then the audio
overhead is likely negligible relative to the overall bandwidth of the
conference.

For example, {{conference-overhead}} shows the overhead estimates for a two
person conference where one person is sending low-quality media and the other
sending high-quality.  (And we assume that SFrame is applied per-frame.)  The
video streams dominate the bandwidth at the SFU, so the total bandwidth overhead
is only around 1%.

| Stream                 | Base Kbps | Overhead Kbps | Overhead % |
|:-----------------------|:---------:|:-------------:|:----------:|
| Participant 1 audio    |         8 |           1.4 |      17.9% |
| Participant 1 video    |        45 |           1.3 |       2.9% |
| Participant 2 audio    |        32 |           9   |      26.9% |
| Participant 2 video    |      1500 |           5   |       0.3% |
| Total at SFU           |      1585 |          16.5 |       1.0% |
{: #conference-overhead title="SFrame overhead for a two-person conference" }

# Test Vectors

This section provides a set of test vectors that implementations can use to
verify that they correctly implement SFrame encryption and decryption.  For each
ciphersuite, we provide:

* [in] The `base_key` value (hex encoded)
* [out] The `secret`, `key`, and `salt` values derived from the `base_key` (hex
  encoded)
* A plaintext value that is encrypted in the following encryption cases
* A sequence of encryption cases, including:
  * [in] The `KID` and `CTR` values to be included in the header
  * [out] The resulting encoded header (hex encoded)
  * [out] The nonce computed from the `salt` and `CTR` values
  * The ciphertext resulting from encrypting the plaintext with these parameters
    (hex encoded)

An implementation should reproduce the output values given the input values:

* An implementation should be able to encrypt with the input values and the
  plaintext to produce the ciphertext.

* An implementation must be able to decrypt with the input values and the
  ciphertext to generate the plaintext.

Line breaks and whitespace within values are inserted to conform to the width
requirements of the RFC format.  They should be removed before use.
These test vectors are also available in JSON format at {{TestVectors}}.

{::include test-vectors.md}
