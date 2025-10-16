// --------------------------------------------------------------
//                        fileclient.cpp
//
//   Designs:
//     - kChunkSize = 230 (fits with headers in <512-byte UDP).
//     - Adaptive sliding window (AIMD): 8..32.
//     - CHECK_REQ loop: treats found=0 as "not ready"; keeps polling.
//     - Robust retry limits; end-to-end commit.
//
//   Command line:
//       fileclient <server> <networknastiness> <filenastiness> <srcdir>
// --------------------------------------------------------------

#include <dirent.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "c150debug.h"
#include "c150grading.h"
#include "c150nastydgmsocket.h"
#include "c150nastyfile.h"
#include "c150network.h"
#include "c150utility.h"

using namespace std;
using namespace C150NETWORK;

// ---------------- constants & protocol ----------------

static const int kCtrlTimeoutMs = 1200;  // START/END/CONFIRM waits
static const int kCheckTimeoutMs = 500;  // per poll during CHECK_REQ
static const int kDataTimeoutMs = 200;   // data-phase poll
static const int kChunkRtoMs = 600;      // per-chunk retransmit timer

static const int kMaxCtrlTries = 24;    // robust under high drop
static const int kMaxCheckTries = 300;  // ~150s at 500ms polls
static const int kMaxFileAttempts = 5;  // whole-file attempts

static const int kNameMax = 256;  // filename bytes in packets

static const uint16_t kProtoV = 1;
static const uint16_t kChunkSize = 230;  // payload per DATA

static const uint32_t kWinInit = 8;
static const uint32_t kWinMax = 32;
static const uint32_t kWinMin = 4;

#pragma pack(push, 1)

struct MsgHeader {
  uint16_t type;
  uint16_t version;
  uint32_t session;
  uint32_t seq;
};

enum : uint16_t {
  FC_MSG_CHECK_REQ = 1,
  FC_MSG_CHECK_RESP = 2,
  FC_MSG_CONFIRM = 3,
  FC_MSG_ACK = 4,

  FC_MSG_START_FILE = 10,
  FC_MSG_DATA = 11,
  FC_MSG_END_FILE = 12
};

struct StartFile {
  MsgHeader h;
  char filename[kNameMax];
  uint32_t fileSize;
};

struct DataMsg {
  MsgHeader h;
  char filename[kNameMax];
  uint32_t chunkIdx;
  uint16_t dataLen;
  char data[kChunkSize];
};

struct EndFile {
  MsgHeader h;
  char filename[kNameMax];
  uint32_t totalChunks;
};

struct CheckReq {
  MsgHeader h;
  char filename[kNameMax];
};

struct CheckResp {
  MsgHeader h;
  char filename[kNameMax];
  uint8_t found;
  uint32_t fileSize;
  unsigned char sha1[20];
};

struct Confirm {
  MsgHeader h;
  char filename[kNameMax];
  uint8_t result;  // 1 = success, 0 = failure
};

struct Ack {
  MsgHeader h;
  char filename[kNameMax];
  uint16_t ackedType;
  uint32_t param;
};

#pragma pack(pop)

// ---------------- utils ----------------

static void setUpDebugLogging(const char* logname, int argc, char* argv[]) {
  ofstream* outstreamp = new ofstream(logname);
  DebugStream* filestreamp = new DebugStream(outstreamp);
  DebugStream::setDefaultLogger(filestreamp);

  c150debug->setPrefix(argv[0]);
  c150debug->enableTimestamp();
  c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC |
                           C150NETWORKDELIVERY);
}

static string joinPath(const string& dir, const string& name) {
  if (!dir.empty() && dir[dir.size() - 1] == '/') return dir + name;

  return dir + "/" + name;
}

static void ensureDirectory(const char* dirname) {
  struct stat sb;

  if (lstat(dirname, &sb) != 0) {
    fprintf(stderr, "Error stating directory %s\n", dirname);
    exit(8);
  }

  if (!S_ISDIR(sb.st_mode)) {
    fprintf(stderr, "%s exists but is not a directory\n", dirname);
    exit(8);
  }
}

static bool isRegularFile(const string& path) {
  struct stat sb;

  if (lstat(path.c_str(), &sb) != 0) return false;

  return S_ISREG(sb.st_mode);
}

static void safeCopyName(char dst[kNameMax], const string& name) {
  memset(dst, 0, kNameMax);

  size_t n = name.size();
  if (n >= (size_t)kNameMax) n = kNameMax - 1;

  memcpy(dst, name.c_str(), n);
}

static uint32_t newSessionId() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);

  return uint32_t(tv.tv_sec) ^ uint32_t(tv.tv_usec) ^ uint32_t(getpid());
}

static uint64_t nowMillis() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);

  return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

static bool computeSHA1_Nasty(const string& path, int nastiness,
                              unsigned char out[20], uint32_t& fileSize) {
  struct stat sb;

  if (lstat(path.c_str(), &sb) != 0 || !S_ISREG(sb.st_mode)) return false;

  fileSize = (uint32_t)sb.st_size;
  size_t sz = (size_t)fileSize;

  if (sz == 0) {
    SHA1((const unsigned char*)"", 0, out);
    return true;
  }

  char* buf = (char*)malloc(sz);
  if (!buf) {
    cerr << "computeSHA1_Nasty: malloc failed\n";
    return false;
  }

  try {
    NASTYFILE in(nastiness);
    void* ok = in.fopen(path.c_str(), "rb");
    if (ok == NULL) {
      free(buf);
      return false;
    }

    size_t got = in.fread(buf, 1, sz);
    if (got != sz) {
      in.fclose();
      free(buf);
      return false;
    }

    if (in.fclose() != 0) {
      free(buf);
      return false;
    }

    SHA1((const unsigned char*)buf, sz, out);
    free(buf);
    return true;
  } catch (C150Exception&) {
    free(buf);
    return false;
  }
}

static bool shaEqual(const unsigned char a[20], const unsigned char b[20]) {
  return memcmp(a, b, 20) == 0;
}

template <typename T>
static bool recvTyped(C150DgmSocket* sock, uint16_t wantType, uint32_t session,
                      const string& fname, T& outMsg) {
  char buf[MAXDGMSIZE];

  for (;;) {
    ssize_t r = sock->read(buf, sizeof(buf));
    if (sock->timedout()) return false;
    if (r < (ssize_t)sizeof(MsgHeader)) continue;

    MsgHeader* h = (MsgHeader*)buf;
    if (h->type != wantType) continue;
    if (h->version != kProtoV) continue;
    if (h->session != session) continue;

    const char* namep = buf + sizeof(MsgHeader);
    if (strncmp(namep, fname.c_str(), kNameMax) != 0) continue;

    if ((ssize_t)sizeof(T) > r) continue;

    memcpy(&outMsg, buf, sizeof(T));
    return true;
  }
}

static bool waitAck(C150DgmSocket* sock, uint32_t session, const string& fname,
                    uint16_t wantAckType, uint32_t wantParam, Ack& ack) {
  int tries = 0;

  while (true) {
    if (!recvTyped(sock, FC_MSG_ACK, session, fname, ack)) {
      if (++tries >= kMaxCtrlTries) return false;
      continue;
    }

    if (ack.ackedType != wantAckType) continue;
    if (ack.param != wantParam) continue;

    return true;
  }
}

static bool tryReadAckForFile(C150DgmSocket* sock, uint32_t session,
                              const string& fname, Ack& ack) {
  char buf[MAXDGMSIZE];

  ssize_t r = sock->read(buf, sizeof(buf));
  if (sock->timedout()) return false;
  if (r < (ssize_t)sizeof(MsgHeader)) return false;

  MsgHeader* h = (MsgHeader*)buf;
  if (h->type != FC_MSG_ACK || h->version != kProtoV || h->session != session)
    return false;

  const char* namep = buf + sizeof(MsgHeader);
  if (strncmp(namep, fname.c_str(), kNameMax) != 0) return false;

  if ((ssize_t)sizeof(Ack) > r) return false;

  memcpy(&ack, buf, sizeof(Ack));
  return true;
}

static bool preloadSourceOnce(const string& path, int fileNasty,
                              vector<char>& out, uint32_t fileSize) {
  if (fileSize == 0) {
    out.clear();
    return true;
  }

  out.resize(fileSize);

  try {
    NASTYFILE in(fileNasty);
    void* ok = in.fopen(path.c_str(), "rb");
    if (ok == NULL) return false;

    size_t gotTotal = 0;
    while (gotTotal < fileSize) {
      size_t want = min<size_t>(8192, fileSize - gotTotal);
      size_t got = in.fread(out.data() + gotTotal, 1, want);

      if (got == 0) {
        in.fclose();
        return false;
      }

      gotTotal += got;
    }

    if (in.fclose() != 0) return false;

    return true;
  } catch (C150Exception&) {
    return false;
  }
}

// ---------------- main ----------------

int main(int argc, char* argv[]) {
  GRADEME(argc, argv);
  setUpDebugLogging("fileclientdebug.txt", argc, argv);

  if (argc != 5) {
    fprintf(stderr,
            "Correct syntax: %s <server> <networknastiness> <filenastiness> "
            "<srcdir>\n",
            argv[0]);
    return 1;
  }

  if (strspn(argv[2], "0123456789") != strlen(argv[2]) ||
      strspn(argv[3], "0123456789") != strlen(argv[3])) {
    fprintf(stderr, "networknastiness/filenastiness must be numeric\n");
    return 4;
  }

  const char* serverArg = argv[1];
  int netNasty = atoi(argv[2]);   // 0..4
  int fileNasty = atoi(argv[3]);  // 0..5
  const char* srcDir = argv[4];

  ensureDirectory((char*)srcDir);

  try {
    c150debug->printf(C150APPLICATION,
                      "Creating C150NastyDgmSocket(nastiness=%d)", netNasty);
    C150DgmSocket* sock = new C150NastyDgmSocket(netNasty);
    sock->setServerName(const_cast<char*>(serverArg));
    sock->turnOnTimeouts(kCtrlTimeoutMs);

    DIR* SRC = opendir(srcDir);
    if (!SRC) {
      fprintf(stderr, "Error opening SRC dir %s\n", srcDir);
      return 8;
    }

    struct dirent* de;

    while ((de = readdir(SRC)) != nullptr) {
      string name = de->d_name;
      if (name == "." || name == "..") continue;

      string srcPath = joinPath(srcDir, name);
      if (!isRegularFile(srcPath)) continue;

      struct stat sb;
      if (lstat(srcPath.c_str(), &sb) != 0) continue;

      uint32_t fileSize = (uint32_t)sb.st_size;
      uint32_t totalChunks = (fileSize + kChunkSize - 1) / kChunkSize;

      bool finalSuccess = false;

      for (int attempt = 1; attempt <= kMaxFileAttempts && !finalSuccess;
           ++attempt) {
        uint32_t session = newSessionId();
        uint32_t seq = 1;

        *GRADING << "File: " << name << ", beginning transmission, attempt "
                 << attempt << endl;

        // START_FILE
        StartFile start{};
        start.h.type = FC_MSG_START_FILE;
        start.h.version = kProtoV;
        start.h.session = session;
        start.h.seq = seq++;
        safeCopyName(start.filename, name);
        start.fileSize = fileSize;

        Ack ack{};
        int tries = 0;

        while (true) {
          sock->write((const char*)&start, sizeof(start));
          if (waitAck(sock, session, name, FC_MSG_START_FILE, 0, ack)) break;
          if (++tries >= kMaxCtrlTries)
            throw C150NetworkException("No ACK for START_FILE: " + name);
        }

        // Preload source ONCE per attempt
        vector<char> fileBuf;
        if (!preloadSourceOnce(srcPath, fileNasty, fileBuf, fileSize)) {
          fileBuf.clear();  // E2E will fail and we may retry
        }

        // ---- DATA phase: adaptive sliding window (AIMD) ----
        sock->turnOnTimeouts(kDataTimeoutMs);

        struct ChunkState {
          bool acked = false;
          uint64_t lastSent = 0;
          int sends = 0;
          uint16_t len = 0;
        };

        vector<ChunkState> cs(totalChunks);

        for (uint32_t i = 0; i < totalChunks; i++) {
          uint32_t off = i * kChunkSize;
          uint32_t remain = fileSize - off;
          cs[i].len = (uint16_t)(remain >= kChunkSize ? kChunkSize : remain);
        }

        uint32_t base = 0, nextToSend = 0, ackedCount = 0;
        uint32_t cwnd = kWinInit, acksForAI = 0;

        auto sendChunk = [&](uint32_t i) {
          DataMsg d{};
          d.h.type = FC_MSG_DATA;
          d.h.version = kProtoV;
          d.h.session = session;
          d.h.seq = seq++;
          safeCopyName(d.filename, name);
          d.chunkIdx = i;
          d.dataLen = cs[i].len;
          if (fileSize > 0 && d.dataLen > 0) {
            const char* src = fileBuf.data() + (size_t)i * kChunkSize;
            memcpy(d.data, src, d.dataLen);
          }
          size_t wireLen = sizeof(DataMsg) - kChunkSize + d.dataLen;
          sock->write((const char*)&d, wireLen);
          cs[i].lastSent = nowMillis();
          cs[i].sends += 1;
        };

        while (ackedCount < totalChunks) {
          while (nextToSend < totalChunks && (nextToSend - base) < cwnd) {
            if (!cs[nextToSend].acked && cs[nextToSend].sends == 0)
              sendChunk(nextToSend);
            ++nextToSend;
          }

          Ack a{};
          if (tryReadAckForFile(sock, session, name, a)) {
            if (a.ackedType == FC_MSG_DATA) {
              uint32_t idx = a.param;
              if (idx < totalChunks && !cs[idx].acked) {
                cs[idx].acked = true;
                ++ackedCount;
                if (idx == base) {
                  while (base < totalChunks && cs[base].acked) base++;
                }
                if (++acksForAI >= cwnd) {
                  if (cwnd < kWinMax) cwnd++;
                  acksForAI = 0;
                }
              }
            }
          } else {
            bool didRetransmit = false;
            uint64_t now = nowMillis();
            for (uint32_t i = base; i < min<uint32_t>(totalChunks, base + cwnd);
                 ++i) {
              if (!cs[i].acked && cs[i].sends > 0 &&
                  (now - cs[i].lastSent >= (uint64_t)kChunkRtoMs)) {
                sendChunk(i);
                didRetransmit = true;
              }
            }
            if (didRetransmit) {
              cwnd = max(kWinMin, cwnd / 2);
              acksForAI = 0;
            }
          }
        }

        // END_FILE
        sock->turnOnTimeouts(kCtrlTimeoutMs);
        EndFile end{};
        end.h.type = FC_MSG_END_FILE;
        end.h.version = kProtoV;
        end.h.session = session;
        end.h.seq = seq++;
        safeCopyName(end.filename, name);
        end.totalChunks = totalChunks;

        tries = 0;
        while (true) {
          sock->write((const char*)&end, sizeof(end));
          if (waitAck(sock, session, name, FC_MSG_END_FILE, 0, ack)) break;
          if (++tries >= kMaxCtrlTries)
            throw C150NetworkException("No ACK for END_FILE: " + name);
        }

        *GRADING
            << "File: " << name
            << " transmission complete, waiting for end-to-end check, attempt "
            << attempt << endl;

        // CHECK_REQ polling
        sock->turnOnTimeouts(kCheckTimeoutMs);
        CheckResp resp{};
        int checkTries = 0;

        while (true) {
          CheckReq req{};
          req.h.type = FC_MSG_CHECK_REQ;
          req.h.version = kProtoV;
          req.h.session = session;
          req.h.seq = seq++;
          safeCopyName(req.filename, name);
          sock->write((const char*)&req, sizeof(req));

          if (recvTyped(sock, FC_MSG_CHECK_RESP, session, name, resp)) {
            if (resp.found == 1) break;
            continue;
          }

          if (++checkTries >= kMaxCheckTries)
            throw C150NetworkException("No CHECK_RESP for " + name);
        }

        sock->turnOnTimeouts(kCtrlTimeoutMs);

        // SHA1 compare
        unsigned char localSha[20];
        uint32_t localSize = 0;
        bool success = false;

        if (resp.found == 1) {
          bool oksha =
              computeSHA1_Nasty(srcPath, fileNasty, localSha, localSize);
          success = oksha && (localSize == resp.fileSize) &&
                    shaEqual(localSha, resp.sha1);
        }

        if (success)
          *GRADING << "File: " << name
                   << " end-to-end check succeeded, attempt " << attempt
                   << endl;
        else
          *GRADING << "File: " << name << " end-to-end check failed, attempt "
                   << attempt << endl;

        // CONFIRM
        Confirm conf{};
        conf.h.type = FC_MSG_CONFIRM;
        conf.h.version = kProtoV;
        conf.h.session = session;
        conf.h.seq = seq++;
        safeCopyName(conf.filename, name);
        conf.result = success ? 1 : 0;

        tries = 0;
        while (true) {
          sock->write((const char*)&conf, sizeof(conf));
          if (waitAck(sock, session, name, FC_MSG_CONFIRM, 0, ack)) break;
          if (++tries >= kMaxCtrlTries)
            throw C150NetworkException("No ACK for CONFIRM: " + name);
        }

        finalSuccess = success;
      }  // attempts
    }  // files

    closedir(SRC);
    delete sock;
    return 0;

  } catch (C150NetworkException& e) {
    c150debug->printf(C150ALWAYSLOG, "Caught C150NetworkException: %s\n",
                      e.formattedExplanation().c_str());
    cerr << argv[0]
         << ": caught C150NetworkException: " << e.formattedExplanation()
         << endl;
    return 4;
  }
}
