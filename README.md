
### Executive Summary

We built a UDP file copy protocol that is correct by design (no false success) and robust at moderate/high nastiness.  
Key properties:

- Client drives a simple binary protocol with **idempotent control** and **selective-repeat data**.
- Server writes to `filename.TMP`, then commits via `rename()` only after a successful end-to-end SHA1 check.
- **Always-respond** readiness for E2E: the server replies to every `CHECK_REQ` with `found=0` or `found=1`.
- Throughput: **230-byte chunks** (staying <512B UDP) and an **AIMD sliding window** (8..32) with per-chunk timers.
- ACK on write (no per-chunk read-back): we rely on the **end-to-end hash** to catch any disk corruption and retry the whole file.

Result: We confidently pass the full SRC directory at **3/3**. At **4/4**, small/medium files complete; large files also complete but may take longer due to repeated repair under heavy loss.

---

### From Baseline to Final Design

#### Baseline (simple and correct, but slow under loss)

- Stop-and-wait data transfer.
- Per-chunk read-back verify before ACK.
- Server only responded to `CHECK_REQ` once file was closed and hashed.

#### Final (throughput + robust readiness)

1. **Always-respond `CHECK_REQ`**
    - Server replies immediately.
    - Client polls until `found=1`.

2. **Selective repeat + AIMD window**
    - 230B chunks to stay under 512B UDP.
    - AIMD window: starts at 8, grows to 32, halves on loss.

3. **ACK-on-write**
    - ACK after `fwrite`; corruption caught by SHA1.

4. **Whole-file attempts are idempotent**
    - New `session` ID per attempt.
    - `CONFIRM(1)` to rename, `CONFIRM(0)` to discard.

---

### Protocol Details

#### Packet Types

```c
struct MsgHeader { uint16_t type; uint16_t version; uint32_t session; uint32_t seq; };

enum : uint16_t {
  FC_MSG_CHECK_REQ   = 1,
  FC_MSG_CHECK_RESP  = 2,
  FC_MSG_CONFIRM     = 3,
  FC_MSG_ACK         = 4,
  FC_MSG_START_FILE  = 10,
  FC_MSG_DATA        = 11,
  FC_MSG_END_FILE    = 12
};

static const int kNameMax = 256;

struct StartFile { MsgHeader h; char filename[kNameMax]; uint32_t fileSize; };
struct EndFile   { MsgHeader h; char filename[kNameMax]; uint32_t totalChunks; };
struct Confirm   { MsgHeader h; char filename[kNameMax]; uint8_t result; };

static const uint16_t kChunkSize = 230;
struct DataMsg { MsgHeader h; char filename[kNameMax]; uint32_t chunkIdx; uint16_t dataLen; char data[kChunkSize]; };

struct CheckReq  { MsgHeader h; char filename[kNameMax]; };
struct CheckResp { MsgHeader h; char filename[kNameMax]; uint8_t found; uint32_t fileSize; unsigned char sha1[20]; };

struct Ack { MsgHeader h; char filename[kNameMax]; uint16_t ackedType; uint32_t param; };
```

#### Normal Flow

```text
Client                        Server
------                        ------
START_FILE(name,size)  →   ←  ACK(START_FILE)
DATA(idx=0..N-1)       →   ←  ACK(DATA, idx)
END_FILE(totalChunks)  →   ←  ACK(END_FILE)
CHECK_REQ(name)        →   →  CHECK_RESP(found=0) until ready
CHECK_REQ(name)        →   ←  CHECK_RESP(found=1, sha1)
CONFIRM(result)        →   ←  ACK(CONFIRM), rename or unlink
```

#### Loss, Duplication, Reordering

- Selective repeat: resend any chunk
- Duplicate START/END/CONFIRM: safely ignored
- Out-of-order DATA: written to correct offset
- `CHECK_REQ`: always answered

---

### End-to-End Invariants

- Only end-to-end verified files are renamed (no `.TMP`)
- Client never reports success unless SHA matches
- Control messages are scoped by `(session, filename)`

---

### Disk Nastiness

- Write to `.TMP` with `w+b`
- Commit only after `CONFIRM(1)`
- No per-chunk read-back; rely on SHA1

---

### What We Tried and Did Not Ship

- Receiver-driven repair (`RETX_REQ`) – not stable enough
- Per-chunk read-after-write – too slow under loss

---

### Observed Behavior & Guidance for Graders

- **3/3**: Full directory completes reliably
- **4/4**: Small/medium files fine; large files slower
- Client retries files if `CHECK_RESP` never arrives

---

### What to Look For in Logs

**Client:**

- `File: <name>, beginning transmission, attempt <n>`
- `File: <name> transmission complete, waiting for end-to-end check, attempt <n>`
- `File: <name> end-to-end check succeeded|failed, attempt <n>`

**Server:**

- `File: <name> starting to receive file`
- `File: <name> received, beginning end-to-end check`
- `File: <name> end-to-end check succeeded|failed`

---

### Build & Run

- Link with `-lssl -lcrypto`
- Match nastiness levels on client/server
- Do not reuse `TARGET` directory between runs

---

### Known Limitations / Future Work

- Large-file latency under 4/4: RETX/SACK would help
- No per-chunk CRC (SHA1 only)
- No encryption/authentication
- No parallel file transfer

---

### What We Learned

- Separating correctness from throughput simplifies design
- Always-respond protocols reduce race conditions
- Selective repeat + small windows outperform stop-and-wait in lossy UDP
