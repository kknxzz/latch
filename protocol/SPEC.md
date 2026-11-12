# Latch wire protocol v1

Status: implementation specification; conformance work is in progress.

## Transport and limits

The public HTTP service exposes `/v1/info`, `/v1/enroll/challenge`,
`/v1/enroll`, and `/c/`. The WebSocket endpoint requires subprotocol `latch.v1`.
Production uses HTTPS/WSS with TLS 1.3 at the origin. Plain HTTP/WS is permitted
only with explicit development configuration and loopback endpoints. Never
redirect credentials or downgrade schemes. Browser-origin WebSockets are denied;
the native client sends no Origin. Proxy forwarding headers are ignored except
from configured trusted peer CIDRs.

One UTF-8 JSON object per text WebSocket frame. No compression. Maximum frame or
HTTP request body: 65,536 bytes. Maximum JSON nesting: 8 containers. Reject
duplicate object keys (including escaped equivalents), unknown fields, unknown
types, invalid UTF-8, trailing input, invalid base64, and version mismatches.
Authentication deadline: 30 seconds. Write deadline: 5 seconds. Ping every
15 seconds, dead-peer deadline: 45 seconds. Per-connection send queues are capped
at both 64 frames and 256 KiB. Full queues disconnect slow consumers.

```json
{"v":1,"type":"room.leave","request_id":"17","body":{}}
```

`request_id` is a 1–32 character ASCII identifier matching `[A-Za-z0-9_-]+` on
requests and their responses. Unsolicited events omit it. Every envelope has
exactly `v`, `type`, `body`, and optional `request_id`. `body` is an object.
Binary values use padded standard base64. Integers must be JSON integers.
UUIDs use lowercase RFC 9562 version-4 string form. Fingerprints are lowercase
SHA-256 hex of the Ed25519 public-key bytes. Short IDs display the first 12 hex
digits in uppercase and are not authorization identifiers.

## Public HTTP

`GET /v1/info` returns `{ "v":1, "server_id":"<uuid>", "limits":{
"connections":100,"rooms":20,"members":16,"message_bytes":4096} }`.
Server UUID is generated once in persistent protected state.

`POST /v1/enroll/challenge` accepts `{}` and returns `challenge_id`, 32-byte
`nonce` (base64), `server_id`, and `expires_at` (RFC 3339 UTC). IDs are random
128-bit hex; expiry is 30 seconds; cap outstanding challenges at 256.

`POST /v1/enroll` accepts `challenge_id`, `code` (six ASCII digits), `uuid`,
`public_key` (32 bytes, base64), `nickname` (optional), and `signature` (64 bytes,
base64). Success returns `uuid`, `fingerprint`, and `device_id`.

Ed25519 signature transcript: concatenate each field prefixed with its uint32
big-endian byte length, in this order: literal `Latch/enroll/v1`, server UUID,
challenge ID, raw nonce, client UUID, raw public key. The PIN is separately
verified within the same enrollment request; it is not an identity key.

Challenge IDs are one-use, including failed submissions. Code consumption and
registration are a single transaction. If the response is lost, the client tries
normal key authentication. Never add a production test-code bypass.

Use uniform `ENROLLMENT_FAILED` for bad/expired codes, key bans, and invalid
proofs. Source lockouts use `RATE_LIMITED`. No request body is logged.

## Connection authentication

Server sends `auth.challenge` with `server_id`, `connection_id` (random 128-bit
hex), `nonce` (32 bytes), `expires_at`. Client sends `auth.prove` with `uuid`,
`signature`, and optional `nickname`. Signature fields are length-prefixed as
above: `Latch/auth/v1`, server UUID, connection ID, nonce, literal `latch.v1`,
client UUID. Resolve the key from enrolled state; do not accept a replacement key.

Success: `auth.ok` with `uuid`, `fingerprint`, `device_id`, `nickname`.
Failure: `AUTH_FAILED`, then close. One active connection per registered key;
reject a duplicate. A nonce is never accepted twice. Only authentication traffic
is allowed before `auth.ok`. One room per connection.

## Request messages

| Type | Body | Allowed state |
|---|---|---|
| `room.create` | optional `pin`; `group_id` (16 random bytes); `key_package` | Lobby |
| `room.join` | `room_id`, optional `pin`, fresh `key_package` | Lobby |
| `room.leave` | empty | Room |
| `room.kick` | `target_uuid` | Host in ready room |
| `nickname.set` | `nickname` | Authenticated |
| `room.commit` | `room_id`, `revision`, `epoch`, `commit`, optional `welcome` | Host during transition |
| `room.ack` | `room_id`, `revision`, `epoch` | Member during transition |
| `message.send` | `room_id`, `revision`, `epoch`, `ciphertext` | Ready room |

Nicknames: optional, at most 32 Unicode scalar values / 128 UTF-8 bytes; reject
controls. Rendering must sanitize all remote text regardless of prior validation.
Message plaintext is at most 4,096 UTF-8 bytes. Ciphertext is at most 16,384 bytes.
Key packages, commits and Welcomes individually fit within 32,768 decoded bytes;
the full envelope limit still applies. No plaintext message field exists.

Room IDs contain exactly ten uppercase characters from
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, generated uniformly with `crypto/rand`.
Room PINs are exactly six ASCII digits; never use them as MLS input key material.
Room ID lookup must not enumerate available rooms.

## Events and responses

`ok` has `{}`; `error` has `code`, `message`, and optional bounded
`retry_after_seconds`. No stack traces or echoed input. Correlate both to requests.

`room.created`: `room_id`, `group_id`, `revision` (0), `epoch` (0), `host_uuid`.
`room.prepare`: `room_id`, `group_id`, `revision`, `action` (`add`, `remove`,
`update`), `members` (UUID, key, nickname), optional `key_package` for an add.
`room.commit`: same coordinates plus MLS `commit`, and `welcome` only to the
joining device. `room.ready`: room coordinates and current member roster.
`message.deliver`: room coordinates, `sender_uuid`, `ciphertext`.
`member.changed`: current nickname mapping. MLS authenticated sender identity
must agree with the enrolled roster; transport sender labels alone are untrusted.
`room.closed`: `reason` (`host_disconnected`, `rekey_failed`, `server_shutdown`).
`room.kicked`: no identity-bearing fields. `device.revoked`: empty, then close.

## Room state machine

States: lobby → ready room ↔ preparing → closed → lobby. The host owns room
lifetime. Any host transport loss destroys it; no reconnect grace, migration,
offline delivery, or restoration. Member transport loss removes that member and
starts an MLS removal transition. Restart destroys all rooms and room bans.

Membership transitions are serialized. Immediately stop application forwarding,
drop queued old-epoch application frames, exclude removed connections, increment
revision, and ask the host for the MLS change. All remaining clients, including
the host, validate roster/key bindings and acknowledge the new epoch. Resume only
after every acknowledgment. The newly joined member processes Welcome; existing
members process Commit. Host acknowledges its locally merged commit.
If any step takes over 15 seconds or fails validation, destroy the room.
Host makes a fresh self-update every ten minutes. No previous epoch retained.

MLS basic credentials bind server UUID, device UUID and enrolled Ed25519 key.
Use suite 0x0001 (X25519/AES-128-GCM/SHA-256/Ed25519). Only host membership
commits are accepted. No external joins. Key packages are one-use. Application
data must be MLS private messages. Configure bounded replay/skipped-message
state; refuse duplicate and obsolete-epoch application messages.

## Enrollment, room bans and errors

Enrollment codes expire after ten minutes. Generating a code invalidates the old
one. Five failed attempts per source bucket lock that bucket for eight hours,
surviving restart. Twenty failures invalidate the code. Global rate: 1/second,
burst 5. Source buckets are keyed digests of IPv4 addresses or IPv6 /64 prefixes.
Expired lockout records are removed. Never persist raw IPs for this policy.

Three incorrect room PIN attempts permanently ban that key from the room.
Host kick has the same ban effect. Banned and nonexistent room lookups return
exactly `{"code":"INVALID_ROOM","message":"Invalid room ID."}`.
Do not include reasons or different retry fields. No constant-time network
response guarantee is claimed. Rate limit joins per authenticated key and
globally to constrain probing.

Members render kick notice `* <nickname> has been kicked by Host.`;
target renders `You have been kicked by the host.`. Never name the host.

Error codes: `AUTH_FAILED`, `ENROLLMENT_FAILED`, `RATE_LIMITED`, `INVALID_ROOM`,
`INVALID_PIN`, `FORBIDDEN`, `ROOM_FULL`, `REKEY_IN_PROGRESS`, `PROTOCOL_ERROR`,
`RESOURCE_LIMIT`, `ALREADY_CONNECTED`. Error text is fixed, never derived from
untrusted input. Structural violations close with WebSocket 1008; oversized
messages close with 1009. Internal failures return generic errors.

## Persistence and privacy

Persist enrolled device records, key-ban tombstones, code digests/expiry,
administration credentials, server identity, and unexpired enrollment lockouts.
No room state or message payload may reach persistent storage. Dashboard removal
permanently bans the key and disconnects its connections. Changing UUID cannot
bypass the ban. A new key with a new enrollment code is outside this guarantee.
