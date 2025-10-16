// --------------------------------------------------------------
//                        fileserver.cpp
//
//   Designs:
//     - kChunkSize = 230 (match client).
//     - ACK(DATA, idx) after fwrite (no per-chunk readback).
//     - On CHECK_REQ: always reply. If not ready yet -> found=0.
//       Only log "received, beginning end-to-end check" when actually hashing.
//     - If all chunks present but not closed yet, close on CHECK_REQ.
//
//   Command line:
//       fileserver <networknastiness> <filenastiness> <targetdir>
// --------------------------------------------------------------

#include <dirent.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
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

static const int kNameMax = 256;
static const uint16_t kProtoV = 1;
static const uint16_t kChunkSize = 230;  // match client

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
  uint8_t result;
};

struct Ack {
  MsgHeader h;
  char filename[kNameMax];
  uint16_t ackedType;
  uint32_t param;
};

#pragma pack(pop)

static void setUpDebugLogging(const char* logname, int argc, char* argv[]) {
  ofstream* outstreamp = new ofstream(logname);
  DebugStream* filestreamp = new DebugStream(outstreamp);
  DebugStream::setDefaultLogger(filestreamp);

  c150debug->setPrefix(argv[0]);
  c150debug->enableTimestamp();
  c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC |
                           C150NETWORKDELIVERY);
  c150debug->setIndent("    ");
}

static string joinPath(const string& dir, const string& name) {
  if (!dir.empty() && dir[dir.size() - 1] == '/') return dir + name;

  return dir + "/" + name;
}

static string tmpNameOf(const string& finalPath) { return finalPath + ".TMP"; }

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
  if (!buf) return false;

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

static void sendAck(C150DgmSocket* sock, const MsgHeader& h,
                    const char filename[kNameMax], uint16_t ackType,
                    uint32_t param) {
  Ack ack{};
  ack.h.type = FC_MSG_ACK;
  ack.h.version = kProtoV;
  ack.h.session = h.session;
  ack.h.seq = h.seq;

  memcpy(ack.filename, filename, kNameMax);
  ack.ackedType = ackType;
  ack.param = param;

  sock->write((const char*)&ack, sizeof(ack));
}

// Per-file receiver state
struct FileState {
  bool loggedStart = false;
  bool started = false;
  bool closed = false;

  uint32_t expectedSize = 0;
  uint32_t expectedChunks = 0;

  string tmpPath;
  string finalPath;

  NASTYFILE* fp = nullptr;  // open while receiving (mode "w+b")
  vector<uint8_t> have;     // bitmap: 1 if chunk written
  uint32_t haveCount = 0;
};

int main(int argc, char* argv[]) {
  GRADEME(argc, argv);
  setUpDebugLogging("fileserverdebug.txt", argc, argv);

  if (argc != 4) {
    fprintf(
        stderr,
        "Correct syntax: %s <networknastiness> <filenastiness> <targetdir>\n",
        argv[0]);
    return 1;
  }

  if (strspn(argv[1], "0123456789") != strlen(argv[1]) ||
      strspn(argv[2], "0123456789") != strlen(argv[2])) {
    fprintf(stderr, "networknastiness/filenastiness must be numeric\n");
    return 4;
  }

  int netNasty = atoi(argv[1]);   // 0..4
  int fileNasty = atoi(argv[2]);  // 0..5
  const char* targetDir = argv[3];

  ensureDirectory((char*)targetDir);

  map<string, FileState> states;  // key = session:filename
  map<string, int> confirmedLogged;

  try {
    c150debug->printf(C150APPLICATION,
                      "Creating C150NastyDgmSocket(nastiness=%d)", netNasty);
    C150DgmSocket* sock = new C150NastyDgmSocket(netNasty);

    char buf[MAXDGMSIZE];

    auto closeIfComplete = [&](FileState& st) {
      if (st.closed || !st.started || st.fp == nullptr) return;
      bool complete =
          (st.expectedChunks == 0) || (st.haveCount == st.expectedChunks);
      if (complete) {
        try {
          st.fp->fclose();
        } catch (...) {
        }
        delete st.fp;
        st.fp = nullptr;
        st.closed = true;
      }
    };

    while (true) {
      ssize_t r = sock->read(buf, sizeof(buf));
      if (r == 0 && sock->timedout()) continue;
      if (r < (ssize_t)sizeof(MsgHeader)) continue;

      MsgHeader* h = (MsgHeader*)buf;
      if (h->version != kProtoV) continue;

      const char* namep = buf + sizeof(MsgHeader);
      string fname(namep, strnlen(namep, kNameMax));
      string key = to_string(h->session) + ":" + fname;
      string fFinal = joinPath(targetDir, fname);
      string fTmp = tmpNameOf(fFinal);

      // START_FILE
      if (h->type == FC_MSG_START_FILE && r >= (ssize_t)sizeof(StartFile)) {
        StartFile start;
        memcpy(&start, buf, sizeof(start));

        FileState& st = states[key];
        st.finalPath = fFinal;
        st.tmpPath = fTmp;
        st.expectedSize = start.fileSize;
        st.expectedChunks = (st.expectedSize + kChunkSize - 1) / kChunkSize;
        st.have.assign(st.expectedChunks ? st.expectedChunks : 1, 0);
        st.haveCount = 0;

        if (!st.started) {
          try {
            if (st.fp) { /* defensive */
            }
            st.fp = new NASTYFILE(fileNasty);
            void* ok = st.fp->fopen(st.tmpPath.c_str(), "w+b");
            if (ok == NULL) {
              // Can't open; still ACK for idempotence
            }
            st.started = true;
            if (!st.loggedStart) {
              *GRADING << "File: " << fname << " starting to receive file"
                       << endl;
              st.loggedStart = true;
            }
          } catch (C150Exception&) {
            // keep idempotence
          }
        }

        sendAck(sock, *h, namep, FC_MSG_START_FILE, 0);
        continue;
      }

      // DATA
      if (h->type == FC_MSG_DATA &&
          r >= (ssize_t)(sizeof(DataMsg) - kChunkSize)) {
        DataMsg dm;
        memcpy(&dm, buf, sizeof(DataMsg));

        auto it = states.find(key);
        if (it == states.end()) continue;

        FileState& st = it->second;
        if (!st.started || st.closed || st.fp == nullptr) continue;

        if (dm.chunkIdx >= st.expectedChunks && st.expectedChunks != 0)
          continue;

        size_t minWire = sizeof(DataMsg) - kChunkSize + dm.dataLen;
        if (r < (ssize_t)minWire) continue;

        if (st.expectedChunks != 0 && dm.chunkIdx < st.have.size() &&
            st.have[dm.chunkIdx]) {
          sendAck(sock, *h, namep, FC_MSG_DATA, dm.chunkIdx);
          continue;
        }

        bool wrote = false;
        try {
          long off = (long)dm.chunkIdx * kChunkSize;
          st.fp->fseek(off, SEEK_SET);
          size_t n = st.fp->fwrite(dm.data, 1, dm.dataLen);
          wrote = (n == dm.dataLen);
        } catch (C150Exception&) {
          wrote = false;
        }

        if (wrote) {
          if (st.expectedChunks != 0 && !st.have[dm.chunkIdx]) {
            st.have[dm.chunkIdx] = 1;
            st.haveCount += 1;
          }
          sendAck(sock, *h, namep, FC_MSG_DATA, dm.chunkIdx);
          closeIfComplete(st);
        }
        continue;
      }

      // END_FILE
      if (h->type == FC_MSG_END_FILE && r >= (ssize_t)sizeof(EndFile)) {
        auto it = states.find(key);
        if (it != states.end()) {
          FileState& st = it->second;
          closeIfComplete(st);
        }
        sendAck(sock, *h, namep, FC_MSG_END_FILE, 0);
        continue;
      }

      // CHECK_REQ
      if (h->type == FC_MSG_CHECK_REQ && r >= (ssize_t)sizeof(CheckReq)) {
        string pathToCheck;
        auto it = states.find(key);

        if (it == states.end()) {
          if (isRegularFile(fTmp))
            pathToCheck = fTmp;
          else if (isRegularFile(fFinal))
            pathToCheck = fFinal;
        } else {
          FileState& st = it->second;
          if (!st.closed && st.fp != nullptr &&
              (st.expectedChunks == 0 || st.haveCount == st.expectedChunks)) {
            try {
              st.fp->fclose();
            } catch (...) {
            }
            delete st.fp;
            st.fp = nullptr;
            st.closed = true;
          }
          if (st.closed) {
            if (isRegularFile(st.tmpPath))
              pathToCheck = st.tmpPath;
            else if (isRegularFile(st.finalPath))
              pathToCheck = st.finalPath;
          }
        }

        CheckResp resp{};
        resp.h.type = FC_MSG_CHECK_RESP;
        resp.h.version = kProtoV;
        resp.h.session = h->session;
        resp.h.seq = h->seq;
        memcpy(resp.filename, namep, kNameMax);

        if (!pathToCheck.empty()) {
          *GRADING << "File: " << fname
                   << " received, beginning end-to-end check" << endl;
          unsigned char sha[20];
          uint32_t fsz = 0;
          bool ok = computeSHA1_Nasty(pathToCheck, fileNasty, sha, fsz);
          resp.found = ok ? 1 : 0;
          resp.fileSize = ok ? fsz : 0;
          if (ok)
            memcpy(resp.sha1, sha, 20);
          else
            memset(resp.sha1, 0, 20);
        } else {
          resp.found = 0;
          resp.fileSize = 0;
          memset(resp.sha1, 0, 20);
        }

        sock->write((const char*)&resp, sizeof(resp));
        continue;
      }

      // CONFIRM
      if (h->type == FC_MSG_CONFIRM && r >= (ssize_t)sizeof(Confirm)) {
        Confirm conf;
        memcpy(&conf, buf, sizeof(conf));

        if (confirmedLogged.find(key) == confirmedLogged.end()) {
          if (conf.result == 1)
            *GRADING << "File: " << fname << " end-to-end check succeeded"
                     << endl;
          else
            *GRADING << "File: " << fname << " end-to-end check failed" << endl;
          confirmedLogged[key] = 1;
        }

        string tmpP = fTmp, finP = fFinal;
        auto it2 = states.find(key);
        if (it2 != states.end()) {
          tmpP = it2->second.tmpPath;
          finP = it2->second.finalPath;
        }

        if (conf.result == 1) {
          if (isRegularFile(tmpP)) ::rename(tmpP.c_str(), finP.c_str());
        } else {
          if (isRegularFile(tmpP)) ::unlink(tmpP.c_str());
        }

        sendAck(sock, *h, conf.filename, FC_MSG_CONFIRM, 0);
        states.erase(key);
        continue;
      }

      // Unknown message, ignore
    }

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
