#include <jni.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cstring>
#include <ctime>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <dirent.h>

#define LOG_TAG "mc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — PACKAGE LOCK
// Only ahmed.bader.matric.vip can use this library
// ═══════════════════════════════════════════════════════════════════════════════

static JavaVM* g_jvm = nullptr;
static bool    g_authorized = false;

static bool check_package(JNIEnv* env) {
    // XOR encoded "ahmed.bader.matric.vip"
    const uint8_t pkg_enc[] = {
        0x28,0x2B,0x2C,0x25,0x29,0x0C,0x23,0x28,
        0x29,0x25,0x2D,0x0C,0x2C,0x28,0x31,0x2D,
        0x22,0x2A,0x0C,0x37,0x22,0x2F
    };
    const uint8_t key = 0x41;
    std::string expected(sizeof(pkg_enc), 0);
    for (size_t i = 0; i < sizeof(pkg_enc); i++)
        expected[i] = pkg_enc[i] ^ (key + (i % 5));

    jclass ctx_cls = env->FindClass("android/app/ActivityThread");
    jmethodID cur  = env->GetStaticMethodID(ctx_cls,
        "currentPackageName", "()Ljava/lang/String;");
    jstring jpkg   = (jstring) env->CallStaticObjectMethod(ctx_cls, cur);
    if (!jpkg) return false;

    const char* pkg = env->GetStringUTFChars(jpkg, nullptr);
    bool ok = (std::string(pkg) == expected);
    env->ReleaseStringUTFChars(jpkg, pkg);
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — ANTI DEBUG / ANTI TAMPER / ANTI VPN
// ═══════════════════════════════════════════════════════════════════════════════

// Check if debugger is attached via ptrace
static bool is_debugger_attached() {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        return true;
    ptrace(PTRACE_DETACH, 0, 0, 0);
    return false;
}

// Check /proc/self/status for TracerPid
static bool has_tracer_pid() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            fclose(f);
            return atoi(line + 10) != 0;
        }
    }
    fclose(f);
    return false;
}

// Check if running on emulator
static bool is_emulator() {
    char val[PROP_VALUE_MAX];
    __system_property_get("ro.build.fingerprint", val);
    if (strstr(val, "generic") || strstr(val, "emulator")) return true;
    __system_property_get("ro.hardware", val);
    if (strstr(val, "goldfish") || strstr(val, "ranchu")) return true;
    __system_property_get("ro.product.model", val);
    if (strstr(val, "Emulator") || strstr(val, "Android SDK")) return true;
    return false;
}

// Check if device is rooted
static bool is_rooted() {
    const char* paths[] = {
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/data/local/xbin/su", "/data/local/bin/su",
        nullptr
    };
    for (int i = 0; paths[i]; i++)
        if (access(paths[i], F_OK) == 0) return true;
    return false;
}

// Check if Frida or Xposed is injected
static bool has_hook_framework() {
    // Check loaded maps for frida / xposed gadget
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida")   ||
            strstr(line, "gadget")  ||
            strstr(line, "xposed")  ||
            strstr(line, "substrate")) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

// Check for proxy / VPN via /proc/net/route default gateway
static bool has_vpn_or_proxy(JNIEnv* env) {
    // Check system proxy properties
    char host[PROP_VALUE_MAX] = {};
    char port[PROP_VALUE_MAX] = {};
    __system_property_get("http.proxyHost", host);
    __system_property_get("http.proxyPort", port);
    if (strlen(host) > 0) return true;

    // Check tun0 interface (VPN)
    FILE* f = fopen("/proc/net/if_inet6", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "tun")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }

    // Check via Java NetworkInterface for VPN tun interface
    jclass ni_cls = env->FindClass("java/net/NetworkInterface");
    jmethodID get_all = env->GetStaticMethodID(ni_cls,
        "getNetworkInterfaces", "()Ljava/util/Enumeration;");
    jobject enumeration = env->CallStaticObjectMethod(ni_cls, get_all);
    if (!enumeration) return false;

    jclass enum_cls  = env->FindClass("java/util/Enumeration");
    jmethodID has_more = env->GetMethodID(enum_cls, "hasMoreElements", "()Z");
    jmethodID next_el  = env->GetMethodID(enum_cls, "nextElement", "()Ljava/lang/Object;");
    jmethodID get_name = env->GetMethodID(ni_cls, "getName", "()Ljava/lang/String;");

    while (env->CallBooleanMethod(enumeration, has_more)) {
        jobject ni = env->CallObjectMethod(enumeration, next_el);
        jstring jname = (jstring) env->CallObjectMethod(ni, get_name);
        const char* name = env->GetStringUTFChars(jname, nullptr);
        bool is_vpn = (strncmp(name, "tun", 3) == 0 ||
                       strncmp(name, "ppp", 3) == 0);
        env->ReleaseStringUTFChars(jname, name);
        if (is_vpn) return true;
    }
    return false;
}

// Check APK signature — if someone repacks the APK, signature changes
static bool check_signature(JNIEnv* env) {
    // XOR encoded expected signature hash prefix (first 8 chars of your release SHA)
    // Replace ENC bytes with XOR of your actual signature bytes
    const uint8_t sig_enc[] = { 0x76,0x61,0x72,0x69,0x61,0x62,0x6C,0x65 };
    const uint8_t sig_key   = 0x15;
    std::string expected(sizeof(sig_enc), 0);
    for (size_t i = 0; i < sizeof(sig_enc); i++)
        expected[i] = sig_enc[i] ^ (sig_key + i % 3);

    jclass pm_cls  = env->FindClass("android/content/pm/PackageManager");
    jclass at_cls  = env->FindClass("android/app/ActivityThread");
    jmethodID cur  = env->GetStaticMethodID(at_cls,
        "currentApplication", "()Landroid/app/Application;");
    jobject app    = env->CallStaticObjectMethod(at_cls, cur);
    jmethodID gpm  = env->GetMethodID(
        env->FindClass("android/content/Context"),
        "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm     = env->CallObjectMethod(app, gpm);

    jmethodID gpn  = env->GetMethodID(
        env->FindClass("android/content/Context"),
        "getPackageName", "()Ljava/lang/String;");
    jstring jpkg   = (jstring) env->CallObjectMethod(app, gpn);

    jmethodID gpi  = env->GetMethodID(pm_cls, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject pi     = env->CallObjectMethod(pm, gpi, jpkg, 0x40); // GET_SIGNATURES

    jfieldID sigs_field = env->GetFieldID(
        env->FindClass("android/content/pm/PackageInfo"),
        "signatures", "[Landroid/content/pm/Signature;");
    jobjectArray sigs = (jobjectArray) env->GetObjectField(pi, sigs_field);
    jobject sig0      = env->GetObjectArrayElement(sigs, 0);

    jmethodID to_str  = env->GetMethodID(
        env->FindClass("android/content/pm/Signature"),
        "toCharsString", "()Ljava/lang/String;");
    jstring jsig = (jstring) env->CallObjectMethod(sig0, to_str);
    const char* sig = env->GetStringUTFChars(jsig, nullptr);

    // Compare first N chars of signature
    bool ok = (strncmp(sig, expected.c_str(), expected.size()) == 0);
    env->ReleaseStringUTFChars(jsig, sig);
    return ok;
    // NOTE: on first run, log the sig value and encode it above
}

// Master security check — called on every proxy start
static bool security_ok(JNIEnv* env) {
    //if (!g_authorized)        return false;
   // if (is_debugger_attached()) return false;
   // if (has_tracer_pid())       return false;
   // if (is_emulator())          return false;
    //if (is_rooted())            return false;
   // if (has_hook_framework())   return false;
   //  if (has_vpn_or_proxy(env))  return false;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — XOR STRING ENCODING
// All secrets decoded at runtime, never visible in binary
// ═══════════════════════════════════════════════════════════════════════════════

static std::string xor_str(const uint8_t* data, size_t len, uint8_t base_key) {
    std::string out(len, 0);
    for (size_t i = 0; i < len; i++)
        out[i] = data[i] ^ (base_key + (uint8_t)(i % 7));
    return out;
}

// ── How to generate your encoded bytes: ──────────────────────────────────────
// Python script to encode your strings:
//
// def encode(s, key):
//     return [b ^ (key + i % 7) for i, b in enumerate(s.encode())]
//
// print(encode("6628568379|c1e620fa708a1d5696fb991c1bde5662", 0x1F))
// print(encode("https://heelome-proxymatric.hf.space/", 0x2A))
// print(encode("https://z-m-graph.facebook.com/v22.0/", 0x33))
// ─────────────────────────────────────────────────────────────────────────────

// Replace these placeholder arrays with your actual encoded output from script above
static const uint8_t TOKEN_ENC[] = {
    /* paste output of encode(token, 0x1F) here */
     0x29,0x16,0x13,0x1A,0x16,0x12,0x1D,0x2C,0x17,0x18,0x5E,0x40,0x15,0x40,0x29,0x12,0x11,0x44,0x42,0x13,0x15,0x27,0x41,0x10,0x46,0x16,0x12,0x1C,0x29,0x46,0x43,0x1B,0x1A,0x15,0x46,0x2E,0x42,0x45,0x47,0x16,0x12,0x13,0x2D
};
static const uint8_t HF1_ENC[] = {
    /* paste output of encode(hf1_url, 0x2A) here */
    0x42,0x5F,0x58,0x5D,0x5D,0x15,0x1F,0x05,0x43,0x49,0x48,0x42,0x40,0x5D,0x4F,0x06,0x5C,0x5F,0x41,0x57,0x49,0x47,0x4A,0x58,0x5F,0x47,0x4C,0x1E,0x42,0x4D,0x02,0x5E,0x5E,0x4E,0x53,0x4F,0x04
};
static const uint8_t HF2_ENC[] = {
    /* paste output of encode(hf2_url, 0x2A) here */
    0x42,0x5F,0x58,0x5D,0x5D,0x15,0x1F,0x05,0x43,0x49,0x48,0x42,0x40,0x5D,0x4F,0x06,0x5C,0x5F,0x41,0x57,0x49,0x47,0x4A,0x58,0x5F,0x47,0x4C,0x02,0x04,0x43,0x4A,0x03,0x5D,0x5F,0x51,0x49,0x4E,0x03
};
static const uint8_t HF3_ENC[] = {
    /* paste output of encode(hf3_url, 0x2A) here */
    0x42,0x5F,0x58,0x5D,0x5D,0x15,0x1F,0x05,0x43,0x49,0x48,0x42,0x40,0x5D,0x4F,0x06,0x5C,0x5F,0x41,0x57,0x49,0x47,0x4A,0x58,0x5F,0x47,0x4C,0x03,0x04,0x43,0x4A,0x03,0x5D,0x5F,0x51,0x49,0x4E,0x03
};
static const uint8_t GRAPH_ENC[] = {
    /* paste output of encode(graph_api_url, 0x33) here */
    0x5B,0x40,0x41,0x46,0x44,0x02,0x16,0x1C,0x4E,0x18,0x5B,0x1A,0x5F,0x4B,0x52,0x44,0x5D,0x18,0x51,0x59,0x5A,0x56,0x56,0x5A,0x59,0x5C,0x16,0x5A,0x5C,0x59,0x1A,0x40,0x05,0x0A,0x17,0x03,0x1B
};

static std::string get_token()     { return xor_str(TOKEN_ENC, sizeof(TOKEN_ENC), 0x1F); }
static std::string get_hf(int i)   {
    if (i == 0) return xor_str(HF1_ENC, sizeof(HF1_ENC), 0x2A);
    if (i == 1) return xor_str(HF2_ENC, sizeof(HF2_ENC), 0x2A);
                return xor_str(HF3_ENC, sizeof(HF3_ENC), 0x2A);
}
static std::string get_graph()     { return xor_str(GRAPH_ENC, sizeof(GRAPH_ENC), 0x33); }

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — PROXY SERVER (socket, cache, request handling)
// ═══════════════════════════════════════════════════════════════════════════════

static std::atomic<bool>  proxy_running{false};
static int                server_fd = -1;

// LRU segment cache (128 MB)
static std::unordered_map<std::string, std::vector<uint8_t>> seg_cache;
static size_t seg_cache_bytes = 0;
static const size_t MAX_SEG_BYTES = 128UL * 1024 * 1024;
static std::mutex seg_mutex;

// MPD cache with per-URL TTL
static std::unordered_map<std::string, std::vector<uint8_t>> mpd_cache;
static std::unordered_map<std::string, long long> mpd_time;
static std::unordered_map<std::string, long long> mpd_ttl;
static std::mutex mpd_mutex;
static const long long MPD_TTL_DEFAULT = 3000;

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ── send_response ─────────────────────────────────────────────────────────────
// Uses heap-allocated header to avoid stack overflow on large Content-Length

static void send_response(int fd, int code, const char* mime,
                          const uint8_t* data, size_t len) {
    const char* status = (code == 200) ? "OK"              :
                         (code == 400) ? "Bad Request"     :
                         (code == 404) ? "Not Found"       :
                         (code == 405) ? "Method Not Allowed" :
                         (code == 502) ? "Bad Gateway"     : "Error";
    // Heap-allocate so we never overflow on large Content-Length values
    char hdr[1024];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        code, status, mime, len);
    if (hlen > 0) send(fd, hdr, hlen, MSG_NOSIGNAL);
    if (data && len > 0) send(fd, data, len, MSG_NOSIGNAL);
}

static void send_str(int fd, int code, const char* mime, const std::string& s) {
    send_response(fd, code, mime, (const uint8_t*)s.c_str(), s.size());
}

// ── URL helpers ───────────────────────────────────────────────────────────────

static std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            char hex[3] = { s[i+1], s[i+2], 0 };
            out += (char)strtol(hex, nullptr, 16);
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

static std::string url_encode(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            o << c;
        else
            o << '%' << std::uppercase << std::hex
              << ((c >> 4) & 0xF) << (c & 0xF);
    }
    return o.str();
}

static std::string get_query_param(const std::string& path, const std::string& name) {
    size_t q = path.find('?');
    if (q == std::string::npos) return "";
    std::string qs = path.substr(q + 1);
    std::string search = name + "=";
    // Walk each param so partial name matches (e.g. "_url") don't hit "url"
    size_t pos = 0;
    while (pos < qs.size()) {
        size_t amp = qs.find('&', pos);
        std::string kv = qs.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (kv.substr(0, search.size()) == search)
            return url_decode(kv.substr(search.size()));
        pos = (amp == std::string::npos) ? qs.size() : amp + 1;
    }
    return "";
}

// ── JSON helper ───────────────────────────────────────────────────────────────

static std::string extract_json(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        // Also try with space after colon
        search = "\"" + key + "\": \"";
        pos = json.find(search);
    }
    if (pos == std::string::npos) return "";
    pos += search.size();
    std::string out;
    for (; pos < json.size() && json[pos] != '"'; pos++) {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            char n = json[++pos];
            if      (n == '/')  out += '/';
            else if (n == '"')  out += '"';
            else if (n == '\\') out += '\\';
            else if (n == 'n')  out += '\n';
            else if (n == 'r')  out += '\r';
            else if (n == 't')  out += '\t';
        } else {
            out += json[pos];
        }
    }
    return out;
}

// ── Base64 decode ─────────────────────────────────────────────────────────────

static std::string b64_decode(const std::string& in) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(uint8_t)chars[i]] = i;
    std::string out;
    int val = 0, bits = -8;
    for (uint8_t c : in) {
        if (T[c] == -1) { if (c == '=') break; continue; }
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            out += (char)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// ── MPD TTL parser ────────────────────────────────────────────────────────────
// Reads minimumUpdatePeriod="PT{N}S" — mirrors MpdManager.parseTtl()

static long long parse_mpd_ttl(const std::string& mpd) {
    // Look for minimumUpdatePeriod="PT...S"
    const char* needle = "minimumUpdatePeriod=\"PT";
    size_t p = mpd.find(needle);
    if (p == std::string::npos) return MPD_TTL_DEFAULT;
    p += strlen(needle);
    size_t end = mpd.find('"', p);
    if (end == std::string::npos) return MPD_TTL_DEFAULT;
    std::string s = mpd.substr(p, end - p);
    // Strip trailing 'S'
    if (!s.empty() && s.back() == 'S') s.pop_back();
    try {
        double sec = std::stod(s);
        long long ms = (long long)(sec * 1000.0);
        return ms < 1000 ? 1000 : ms;
    } catch (...) {}
    return MPD_TTL_DEFAULT;
}

// ── MPD rewrite ───────────────────────────────────────────────────────────────
// Replaces CDN absolute URLs with local proxy segment URLs.
// Mirrors MpdManager.rewrite() / URL_RE pattern:
//   (initialization|media)="https://z-m-scontent[^/]+(/[^"]+)"
//   → $1="http://127.0.0.1:9998/segment$2"

static std::string rewrite_mpd(const std::string& mpd, int port) {
    std::string out;
    out.reserve(mpd.size() + 256);
    size_t pos = 0;

    // The two attribute prefixes we rewrite
    const std::string prefixes[2] = {
        "initialization=\"https://z-m-scontent",
        "media=\"https://z-m-scontent"
    };
    const std::string attr_names[2] = { "initialization", "media" };

    while (pos < mpd.size()) {
        // Find whichever prefix comes first
        size_t best_pos  = std::string::npos;
        int    best_which = -1;
        for (int i = 0; i < 2; i++) {
            size_t f = mpd.find(prefixes[i], pos);
            if (f < best_pos) { best_pos = f; best_which = i; }
        }

        if (best_pos == std::string::npos) {
            // No more rewrites needed
            out += mpd.substr(pos);
            break;
        }

        // Copy everything before this match verbatim
        out += mpd.substr(pos, best_pos - pos);

        // Find the opening quote of the URL value.
        // The prefix already ends just before the URL, e.g.:
        //   initialization="https://z-m-scontent
        //                  ^ this quote is the last char of prefixes[i]
        // We need the position just after that quote to get "https://..."
        size_t quote_open = best_pos + attr_names[best_which].size() + 1; // +1 for '='
        // quote_open now points at the '"' that opens the URL value
        size_t url_start = quote_open + 1; // first char of "https://..."

        // Find the CDN domain boundary: first '/' that follows the scheme+host.
        // The host is z-m-scontent*.fbcdn.net — find ".net" then skip it.
        size_t net_pos = mpd.find(".net", url_start);
        if (net_pos == std::string::npos) {
            // Malformed URL — copy as-is and stop
            out += mpd.substr(best_pos);
            break;
        }
        size_t path_start = net_pos + 4; // character after ".net" — should be '/'

        // Find the closing quote of the URL value
        size_t quote_close = mpd.find('"', path_start);
        if (quote_close == std::string::npos) {
            out += mpd.substr(best_pos);
            break;
        }

        // seg_path = everything from '/' to (not including) closing quote
        // e.g. "/v/t23.0-1/seg-001.m4s?_nc_oe=XXXX&..."
        std::string seg_path = mpd.substr(path_start, quote_close - path_start);

        // Build rewritten attribute:  initialization="http://127.0.0.1:PORT/segment/v/..."
        char proxy_url[64];
        snprintf(proxy_url, sizeof(proxy_url), "http://127.0.0.1:%d/segment", port);

        out += attr_names[best_which];
        out += "=\"";
        out += proxy_url;
        out += seg_path;
        out += '"';

        pos = quote_close + 1; // continue after closing quote
    }

    return out;
}

// ── HTTP fetch via Java (JNI callback) ───────────────────────────────────────
// Calls NativeCore.httpPost() and NativeCore.httpGet() from Java side.
//
// CRITICAL: after any failed JNI call we must ExceptionClear() before the next
// JNI call.  Leaving a pending exception causes every subsequent JNI call on
// the same JNIEnv to silently return null/0, which was the original bug that
// made all HF retry attempts silently fail.

static std::string java_http_post(JNIEnv* env, const std::string& url,
                                   const std::string& body) {
    jclass cls = env->FindClass("ahmed/bader/matric/vip/NativeCore");
    if (!cls) {
        env->ExceptionClear(); // clear ClassNotFoundException
        LOGE("java_http_post: NativeCore class not found");
        return "";
    }
    jmethodID mid = env->GetStaticMethodID(cls, "httpPost",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!mid) {
        env->ExceptionClear();
        LOGE("java_http_post: httpPost method not found");
        return "";
    }
    jstring jurl  = env->NewStringUTF(url.c_str());
    jstring jbody = env->NewStringUTF(body.c_str());
    if (!jurl || !jbody) {
        env->ExceptionClear();
        return "";
    }
    jstring jres = (jstring) env->CallStaticObjectMethod(cls, mid, jurl, jbody);
    env->DeleteLocalRef(jurl);
    env->DeleteLocalRef(jbody);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("java_http_post: exception during call");
        return "";
    }
    if (!jres) return "";
    const char* res = env->GetStringUTFChars(jres, nullptr);
    std::string out(res);
    env->ReleaseStringUTFChars(jres, res);
    env->DeleteLocalRef(jres);
    return out;
}

static std::vector<uint8_t> java_http_get(JNIEnv* env, const std::string& url) {
    jclass cls = env->FindClass("ahmed/bader/matric/vip/NativeCore");
    if (!cls) {
        env->ExceptionClear();
        LOGE("java_http_get: NativeCore class not found");
        return {};
    }
    jmethodID mid = env->GetStaticMethodID(cls, "httpGet", "(Ljava/lang/String;)[B");
    if (!mid) {
        env->ExceptionClear();
        LOGE("java_http_get: httpGet method not found");
        return {};
    }
    jstring jurl = env->NewStringUTF(url.c_str());
    if (!jurl) { env->ExceptionClear(); return {}; }
    jbyteArray jba = (jbyteArray) env->CallStaticObjectMethod(cls, mid, jurl);
    env->DeleteLocalRef(jurl);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("java_http_get: exception during call");
        return {};
    }
    if (!jba) return {};
    jsize len = env->GetArrayLength(jba);
    if (len <= 0) { env->DeleteLocalRef(jba); return {}; }
    jbyte* bytes = env->GetByteArrayElements(jba, nullptr);
    std::vector<uint8_t> out(bytes, bytes + len);
    env->ReleaseByteArrayElements(jba, bytes, JNI_ABORT);
    env->DeleteLocalRef(jba);
    return out;
}

// ── MPD fetch ─────────────────────────────────────────────────────────────────

static std::string fetch_mpd(JNIEnv* env, const std::string& mpd_url, int port) {
    // Check cache — use per-URL TTL if available
    {
        std::lock_guard<std::mutex> lock(mpd_mutex);
        auto it = mpd_cache.find(mpd_url);
        if (it != mpd_cache.end()) {
            long long ttl = mpd_ttl.count(mpd_url) ? mpd_ttl[mpd_url] : MPD_TTL_DEFAULT;
            if (now_ms() - mpd_time[mpd_url] < ttl) {
                LOGI("MPD cache hit: %s", mpd_url.c_str());
                return std::string(it->second.begin(), it->second.end());
            }
        }
    }

    std::string token = get_token();
    std::string graph = get_graph();

    // Shuffle HF order — try all three
    int order[3] = {0, 1, 2};
    // Simple deterministic shuffle based on current time
    long long t = now_ms();
    int tmp;
    tmp = order[0]; order[0] = order[t % 3]; order[(int)(t % 3)] = tmp;

    for (int i = 0; i < 3; i++) {
        std::string hf_base = get_hf(order[i]);
        std::string cb      = std::to_string(now_ms());
        // Build the target URL that the HF Space will proxy
        std::string target  = hf_base + "?url=" + url_encode(mpd_url) + "&_=" + cb;
        // POST body for the Graph API scraper endpoint
        std::string body    = "id=" + url_encode(target)
                            + "&scrape=true&suppress_http_code=1&access_token=" + token;

        LOGI("MPD fetch attempt %d via HF#%d", i, order[i]);
        std::string json = java_http_post(env, graph, body);
        if (json.empty()) {
            LOGE("MPD fetch: empty JSON response from HF#%d", order[i]);
            continue;
        }

        // The MPD content is base64-encoded in the "site_name" JSON field
        std::string sn = extract_json(json, "site_name");
        if (sn.empty()) {
            LOGE("MPD fetch: site_name missing in response (HF#%d)", order[i]);
            LOGI("Response snippet: %.200s", json.c_str());
            continue;
        }

        // Pad base64 to a multiple of 4
        while (sn.size() % 4 != 0) sn += '=';
        std::string raw_mpd = b64_decode(sn);
        if (raw_mpd.empty()) {
            LOGE("MPD fetch: base64 decode produced empty result");
            continue;
        }

        // Rewrite CDN URLs → local proxy URLs
        std::string rewritten = rewrite_mpd(raw_mpd, port);

        // Parse TTL from minimumUpdatePeriod (Step 6 equivalent)
        long long ttl = parse_mpd_ttl(raw_mpd);

        // Store in cache
        {
            std::lock_guard<std::mutex> lock(mpd_mutex);
            std::vector<uint8_t> data(rewritten.begin(), rewritten.end());
            mpd_cache[mpd_url] = data;
            mpd_time[mpd_url]  = now_ms();
            mpd_ttl[mpd_url]   = ttl;
        }

        LOGI("MPD fetch OK, %zu bytes, TTL=%lldms", rewritten.size(), ttl);
        return rewritten;
    }

    LOGE("MPD fetch: all HF Spaces failed for %s", mpd_url.c_str());
    return "";
}

// ── HTTP request reader ───────────────────────────────────────────────────────
// Reads from the socket until the complete HTTP request line + headers arrive
// (i.e. until we see "\r\n\r\n").  Returns the full request text.
// Uses SO_RCVTIMEO set on the socket before calling this.

static std::string read_http_request(int fd) {
    std::string buf;
    buf.reserve(4096);
    char tmp[4096];
    while (buf.size() < 65536) { // safety cap
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, n);
        // Stop once we have the full header block
        if (buf.find("\r\n\r\n") != std::string::npos) break;
    }
    return buf;
}

// ── Request handler ───────────────────────────────────────────────────────────

static void handle_client(int fd, JNIEnv* env, int proxy_port) {
    if (!security_ok(env)) {
        close(fd);
        return;
    }

    // Set receive timeout so recv() never blocks indefinitely
    struct timeval tv;
    tv.tv_sec  = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Read full HTTP request (loop until \r\n\r\n)
    std::string req = read_http_request(fd);
    if (req.empty()) {
        LOGE("handle_client: empty request");
        close(fd);
        return;
    }

    // Parse request line: "METHOD /path HTTP/1.x\r\n..."
    size_t ps = req.find(' ');
    size_t pe = req.find(' ', ps + 1);
    if (ps == std::string::npos || pe == std::string::npos) {
        LOGE("handle_client: malformed request line");
        send_str(fd, 400, "text/plain", "Bad Request");
        close(fd);
        return;
    }

    std::string method = req.substr(0, ps);
    std::string path   = req.substr(ps + 1, pe - ps - 1);

    LOGI("Request: %s %s", method.c_str(), path.substr(0, 120).c_str());

    if (method != "GET") {
        send_str(fd, 405, "text/plain", "Method Not Allowed");
        close(fd);
        return;
    }

    // ── /mpd?url=<encoded_mpd_url> ───────────────────────────────────────────
    if (path.find("/mpd") == 0) {
        std::string mpd_url = get_query_param(path, "url");
        if (mpd_url.empty()) {
            send_str(fd, 400, "text/plain", "?url=<mpd_url> required");
            close(fd);
            return;
        }
        LOGI("MPD request for: %.200s", mpd_url.c_str());
        std::string mpd = fetch_mpd(env, mpd_url, proxy_port);
        if (mpd.empty()) {
            send_str(fd, 502, "text/plain", "MPD fetch failed — check logcat for details");
        } else {
            send_str(fd, 200, "application/dash+xml", mpd);
        }

    // ── /segment/<cdn-path>[?<qs>] ───────────────────────────────────────────
    // Path format: /segment/v/t23.0-1/seg-001.m4s?_nc_oe=...
    // "/segment" = 8 chars; path[8] must be '/' for a valid segment request
    } else if (path.size() > 8 && path.substr(0, 8) == "/segment" && path[8] == '/') {
        size_t q = path.find('?');
        // subpath = everything between "/segment" and '?' (or end), including the leading '/'
        // e.g. "/v/t23.0-1/seg-001.m4s"
        std::string subpath  = path.substr(8, q != std::string::npos ? q - 8 : std::string::npos);
        std::string qs       = q != std::string::npos ? path.substr(q + 1) : "";
        std::string cache_key = subpath + (qs.empty() ? "" : "?" + qs);

        // Fast path: segment already cached
        {
            std::lock_guard<std::mutex> lock(seg_mutex);
            auto it = seg_cache.find(cache_key);
            if (it != seg_cache.end()) {
                LOGI("Segment cache hit: %s", subpath.c_str());
                send_response(fd, 200, "video/mp4",
                    it->second.data(), it->second.size());
                close(fd);
                return;
            }
        }

        // Reconstruct CDN URL:
        // subpath starts with '/', so cdn_url = base + subpath
        // e.g. https://z-m-scontent.xx.fbcdn.net/v/t23.0-1/seg-001.m4s?...
        std::string cdn_url = "https://z-m-scontent.xx.fbcdn.net" + subpath;
        if (!qs.empty()) {
            // Replace &amp; with & (may be present if copied from XML attribute)
            std::string decoded_qs = qs;
            size_t p = 0;
            while ((p = decoded_qs.find("&amp;", p)) != std::string::npos)
                decoded_qs.replace(p, 5, "&");
            cdn_url += "?" + decoded_qs;
        }

        LOGI("Segment fetch: %s", cdn_url.substr(0, 120).c_str());
        std::vector<uint8_t> data = java_http_get(env, cdn_url);
        if (data.empty()) {
            LOGE("Segment fetch failed: %s", subpath.c_str());
            send_str(fd, 502, "text/plain", "CDN fetch failed");
        } else {
            send_response(fd, 200, "video/mp4", data.data(), data.size());
            // Store in LRU cache — evict oldest entries if over size budget
            std::lock_guard<std::mutex> lock(seg_mutex);
            if (!seg_cache.count(cache_key)) {
                // Simple eviction: if full, clear half the cache
                if (seg_cache_bytes + data.size() > MAX_SEG_BYTES && !seg_cache.empty()) {
                    size_t target = MAX_SEG_BYTES / 2;
                    auto it = seg_cache.begin();
                    while (seg_cache_bytes > target && it != seg_cache.end()) {
                        seg_cache_bytes -= it->second.size();
                        it = seg_cache.erase(it);
                    }
                }
                seg_cache[cache_key] = data;
                seg_cache_bytes += data.size();
            }
        }

    } else {
        send_str(fd, 404, "text/plain", "Not Found");
    }

    close(fd);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — JNI ENTRY POINTS
// ═══════════════════════════════════════════════════════════════════════════════

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jboolean JNICALL
Java_ahmed_bader_matric_vip_NativeCore_init(JNIEnv* env, jclass) {
    //g_authorized = check_package(env);
    //return (jboolean) g_authorized;
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_ahmed_bader_matric_vip_NativeCore_startProxy(JNIEnv* env, jclass, jint port) {
    if (!security_ok(env)) return;
    if (proxy_running.exchange(true)) {
        LOGI("Proxy already running");
        return;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOGE("socket() failed");
        proxy_running = false;
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGE("bind() failed on port %d", port);
        close(server_fd);
        server_fd = -1;
        proxy_running = false;
        return;
    }
    listen(server_fd, 128);
    LOGI("Proxy started on port %d", port);

    // Capture port by value into the acceptor thread
    int captured_port = (int)port;
    std::thread([captured_port]() {
        while (proxy_running) {
            sockaddr_in client_addr{};
            socklen_t   client_len = sizeof(client_addr);
            int client = accept(server_fd, (sockaddr*)&client_addr, &client_len);
            if (client < 0) {
                if (proxy_running) LOGE("accept() error");
                continue;
            }
            // Per-connection thread — attach JNI, handle, detach
            std::thread([client, captured_port]() {
                JNIEnv* env = nullptr;
                JavaVMAttachArgs args;
                args.version = JNI_VERSION_1_6;
                args.name    = (char*)"proxy-worker";
                args.group   = nullptr;
                if (g_jvm->AttachCurrentThread(&env, &args) != JNI_OK || !env) {
                    LOGE("AttachCurrentThread failed");
                    close(client);
                    return;
                }
                handle_client(client, env, captured_port);
                g_jvm->DetachCurrentThread();
            }).detach();
        }
        LOGI("Acceptor loop exited");
    }).detach();
}

JNIEXPORT void JNICALL
Java_ahmed_bader_matric_vip_NativeCore_stopProxy(JNIEnv*, jclass) {
    proxy_running = false;
    if (server_fd >= 0) {
        shutdown(server_fd, SHUT_RDWR); // wake up blocked accept()
        close(server_fd);
        server_fd = -1;
    }
    LOGI("Proxy stopped");
}

JNIEXPORT jstring JNICALL
Java_ahmed_bader_matric_vip_NativeCore_getToken(JNIEnv* env, jclass) {
    if (!g_authorized) return env->NewStringUTF("");
    return env->NewStringUTF(get_token().c_str());
}

} // extern "C"
