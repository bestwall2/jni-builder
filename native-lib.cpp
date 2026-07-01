
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
    if (!g_authorized)        return false;
    if (is_debugger_attached()) return false;
    if (has_tracer_pid())       return false;
    if (is_emulator())          return false;
    if (is_rooted())            return false;
    if (has_hook_framework())   return false;
    if (has_vpn_or_proxy(env))  return false;
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

// MPD cache (3s TTL)
static std::unordered_map<std::string, std::vector<uint8_t>> mpd_cache;
static std::unordered_map<std::string, long long> mpd_time;
static std::mutex mpd_mutex;
static const long long MPD_TTL = 3000;

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void send_response(int fd, int code, const char* mime,
                          const uint8_t* data, size_t len) {
    const char* status = (code == 200) ? "OK" :
                         (code == 400) ? "Bad Request" :
                         (code == 404) ? "Not Found" : "Error";
    char hdr[512];
    int  hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        code, status, mime, len);
    send(fd, hdr, hlen, MSG_NOSIGNAL);
    send(fd, data, len, MSG_NOSIGNAL);
}

static void send_str(int fd, int code, const char* mime, const std::string& s) {
    send_response(fd, code, mime, (const uint8_t*)s.c_str(), s.size());
}

// ── URL helpers ───────────────────────────────────────────────────────────────

static std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i+2 < s.size()) {
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
        if (isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') o << c;
        else o << '%' << std::uppercase << std::hex
               << ((c>>4)&0xF) << (c&0xF);
    }
    return o.str();
}

static std::string get_query_param(const std::string& path, const std::string& name) {
    size_t q = path.find('?');
    if (q == std::string::npos) return "";
    std::string qs = path.substr(q + 1);
    std::string search = name + "=";
    size_t pos = qs.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = qs.find('&', pos);
    std::string val = qs.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    return url_decode(val);
}

// ── JSON helper ───────────────────────────────────────────────────────────────

static std::string extract_json(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    std::string out;
    for (; pos < json.size() && json[pos] != '"'; pos++) {
        if (json[pos] == '\\' && pos+1 < json.size()) {
            char n = json[++pos];
            if (n == '/') out += '/';
            else if (n == '"') out += '"';
            else if (n == '\\') out += '\\';
        } else out += json[pos];
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
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) { out += (char)((val >> bits) & 0xFF); bits -= 8; }
    }
    return out;
}

// ── MPD rewrite ───────────────────────────────────────────────────────────────

static std::string rewrite_mpd(const std::string& mpd) {
    // Replace CDN URLs with local proxy segment URLs
    std::string out;
    out.reserve(mpd.size());
    size_t pos = 0;
    const std::string needle_init = "initialization=\"https://z-m-scontent";
    const std::string needle_media = "media=\"https://z-m-scontent";
    while (pos < mpd.size()) {
        size_t fi = mpd.find(needle_init,  pos);
        size_t fm = mpd.find(needle_media, pos);
        size_t f  = std::min(fi, fm);
        if (f == std::string::npos) { out += mpd.substr(pos); break; }
        out += mpd.substr(pos, f - pos);
        // Find which attribute
        bool is_init = (f == fi);
        out += is_init ? "initialization=\"" : "media=\"";
        // Skip original https://z-m-scontent*.fbcdn.net
        size_t url_start = mpd.find('"', f) + 1;
        // Find the path part after the domain
        size_t path_start = mpd.find(".net", url_start);
        if (path_start == std::string::npos) { out += mpd.substr(f); break; }
        path_start += 4; // skip ".net"
        size_t url_end = mpd.find('"', path_start);
        std::string seg_path = mpd.substr(path_start, url_end - path_start);
        out += "http://127.0.0.1:9998/segment" + seg_path + "\"";
        pos = url_end + 1;
    }
    return out;
}

// ── HTTP fetch via Java (JNI callback) ───────────────────────────────────────
// Calls NativeCore.httpPost() and NativeCore.httpGet() from Java side
// so we reuse OkHttp's connection pool

static std::string java_http_post(JNIEnv* env, const std::string& url,
                                   const std::string& body) {
    jclass cls = env->FindClass("ahmed/bader/matric/vip/NativeCore");
    if (!cls) return "";
    jmethodID mid = env->GetStaticMethodID(cls, "httpPost",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!mid) return "";
    jstring jurl  = env->NewStringUTF(url.c_str());
    jstring jbody = env->NewStringUTF(body.c_str());
    jstring jres  = (jstring) env->CallStaticObjectMethod(cls, mid, jurl, jbody);
    if (!jres) return "";
    const char* res = env->GetStringUTFChars(jres, nullptr);
    std::string out(res);
    env->ReleaseStringUTFChars(jres, res);
    return out;
}

static std::vector<uint8_t> java_http_get(JNIEnv* env, const std::string& url) {
    jclass cls = env->FindClass("ahmed/bader/matric/vip/NativeCore");
    if (!cls) return {};
    jmethodID mid = env->GetStaticMethodID(cls, "httpGet", "(Ljava/lang/String;)[B");
    if (!mid) return {};
    jstring jurl = env->NewStringUTF(url.c_str());
    jbyteArray jba = (jbyteArray) env->CallStaticObjectMethod(cls, mid, jurl);
    if (!jba) return {};
    jsize len = env->GetArrayLength(jba);
    jbyte* bytes = env->GetByteArrayElements(jba, nullptr);
    std::vector<uint8_t> out(bytes, bytes + len);
    env->ReleaseByteArrayElements(jba, bytes, JNI_ABORT);
    return out;
}

// ── MPD fetch ─────────────────────────────────────────────────────────────────

static std::string fetch_mpd(JNIEnv* env, const std::string& mpd_url) {
    // Check cache
    {
        std::lock_guard<std::mutex> lock(mpd_mutex);
        auto it = mpd_cache.find(mpd_url);
        if (it != mpd_cache.end()) {
            long long t = mpd_time[mpd_url];
            if (now_ms() - t < MPD_TTL)
                return std::string(it->second.begin(), it->second.end());
        }
    }

    std::string token    = get_token();
    std::string graph    = get_graph();
    int hf_count = 3;

    for (int attempt = 0; attempt < hf_count; attempt++) {
        std::string hf_base  = get_hf(attempt);
        std::string cb       = std::to_string(now_ms());
        std::string target   = hf_base + "?url=" + url_encode(mpd_url) + "&_=" + cb;
        std::string body     = "id=" + url_encode(target)
                             + "&scrape=true&suppress_http_code=1&access_token=" + token;

        std::string json = java_http_post(env, graph, body);
        if (json.empty()) continue;

        std::string sn = extract_json(json, "site_name");
        if (sn.empty()) continue;

        // Pad base64
        while (sn.size() % 4 != 0) sn += '=';
        std::string raw_mpd = b64_decode(sn);
        if (raw_mpd.empty()) continue;

        std::string rewritten = rewrite_mpd(raw_mpd);

        // Store in cache
        std::lock_guard<std::mutex> lock(mpd_mutex);
        std::vector<uint8_t> data(rewritten.begin(), rewritten.end());
        mpd_cache[mpd_url] = data;
        mpd_time[mpd_url]  = now_ms();
        return rewritten;
    }
    return "";
}

// ── Request handler ───────────────────────────────────────────────────────────

static void handle_client(int fd, JNIEnv* env) {
    // Security check on every request
    if (!security_ok(env)) {
        close(fd);
        return;
    }

    char buf[8192] = {};
    ssize_t n = r
