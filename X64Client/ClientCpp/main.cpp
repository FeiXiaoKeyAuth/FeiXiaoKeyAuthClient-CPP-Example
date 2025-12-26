// ⚠ 以下 main 函数仅为示例调用方式：
//   - 不要直接把此示例 main 作为最终成品客户端发布，否则流程、日志、输出都过于固定，易被逆向。
//   - 你可以根据自己项目需求，自定义 UI / 调用时机 / 线程模型。

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <iphlpapi.h>
#include <ctime>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Curl
#include <curl/curl.h>

// Utils
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <random>
#include <intrin.h>

// JSON
#include <nlohmann/json.hpp>

// VMProtect
#include "VMProtectSDK.h"

// skCrypt（字符串加密）
#include "skStr.h"

// Link with
#pragma comment(lib, "Iphlpapi.lib")

using json = nlohmann::json;

// ============================================================
// 服务器连接配置开始  请从作者后台 软件管理 操作按钮 那边获取相应配置 Py就是复制Python配置 C++就是复制C++配置
// ============================================================
// C++ 配置
const std::string API_URL = skCrypt("https://feixiaokeyauth.top").decrypt();
const uint32_t AUTHOR_ID = 2;
const uint32_t SOFTWARE_ID = 1;
const std::string SECRET_KEY = skCrypt("c3a05165514d51d0ad86dc7ff4e05a44").decrypt();
const std::string VERSION = skCrypt("1.0").decrypt();

// 安全配置
#define CRYPTO_TYPE skCrypt("AES").decrypt()
#define USE_SIGNATURE true

// RSA 公钥
const std::string PUBLIC_KEY_PEM =
skCrypt("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsqArxmtuGwDTPuGJd6MK\n5HCsk+08loR95uWJCe/mjHaIMtpjNHvE1WQyip9QZoInQONyH+N07I0N8t/vrgb4\nEuEQPbn3xRgbDdSBb/WTZ8vTAm1rr8UoDC2+bFNqehhqT3vSscGpbyCmBloNjdTH\nU5fwvR1p1UYejPiCbu/t3G6jIbaOX6lUcmKdNOQsB70ZIzmXWlCHIi5fdGEckMQr\nEo1P+/2je+AY1eu/SDCe7iKclimCsyQJw1+q05ps+NjJE9XUZH5r4GzeVw8vY/yA\nayoEY2rLFC8fD8e/eMF17oxn2ZMIaB8ZNI6peLaB5ckfO44ECSQzDoM72In+vuai\nQQIDAQAB\n-----END PUBLIC KEY-----\n").decrypt();

// ============================================================
// 服务器连接配置结束
// ============================================================

namespace Tools
{
    // ============================================================
    // 十六进制编码操作
    // ============================================================
    namespace Encoding
    {
        // 十六进制编码
        std::string to_hex(const std::vector<unsigned char>& buf) {
            VMProtectBegin("ToHex");
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (auto b : buf) oss << std::setw(2) << (int)b;
            VMProtectEnd();
            return oss.str();
        }

        // 十六进制解码
        std::vector<unsigned char> from_hex(const std::string& hex) {
            VMProtectBegin("FromHex");
            std::vector<unsigned char> out;
            if (hex.size() % 2 != 0) {
                VMProtectEnd();
                return out;
            }
            out.reserve(hex.size() / 2);
            for (size_t i = 0; i < hex.size(); i += 2) {
                unsigned int v;
                std::stringstream ss;
                ss << std::hex << hex.substr(i, 2);
                ss >> v;
                out.push_back((unsigned char)v);
            }
            VMProtectEnd();
            return out;
        }
    }

    // ============================================================
    // 系统工具
    // ============================================================
    namespace System
    {
        // 生成随机 Nonce
        std::string gen_nonce() {
            unsigned char buf[16];
            RAND_bytes(buf, sizeof(buf));
            return Encoding::to_hex(std::vector<unsigned char>(buf, buf + 16));
        }

        // 获取当前 Unix 时间戳
        long long get_timestamp() {
            return std::time(nullptr);
        }

        // MD5 哈希
        bool md5_hash(const void* data, size_t len, unsigned char out[16]) {
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) return false;
            bool res = (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) == 1 &&
                EVP_DigestUpdate(ctx, data, len) == 1 &&
                EVP_DigestFinal_ex(ctx, out, nullptr) == 1);
            EVP_MD_CTX_free(ctx);
            return res;
        }

        // 获取 HWID（当前简单示例：网卡 MAC 或 计算机名 MD5）
        // ⚠ 建议实际项目自行增强 HWID 算法
        std::string get_hwid() {
            VMProtectBegin("GETHWID");
            ULONG buflen = 0;
            GetAdaptersInfo(nullptr, &buflen);
            std::vector<unsigned char> mem(buflen);
            PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)mem.data();

            unsigned char md[16];
            if (GetAdaptersInfo(info, &buflen) == NO_ERROR) {
                md5_hash(info->Address, info->AddressLength, md);
            }
            else {
                char name[256]; DWORD sz = 256;
                GetComputerNameA(name, &sz);
                md5_hash(name, sz, md);
            }
            VMProtectEnd();
            return Encoding::to_hex(std::vector<unsigned char>(md, md + 16));
        }
    }

    // ============================================================
    // 文本处理工具
    // ============================================================
    namespace Text
    {
        // UTF8 -> GBK
        std::string utf8_to_gbk(const std::string& utf8) {
            if (utf8.empty()) {
                return "No Result";
            }
            const UINT targetCP = 936;
            int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
            if (wlen <= 0) {
                return "No Result";
            }
            std::vector<wchar_t> wstr(wlen);
            if (MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wstr.data(), wlen) == 0) {
                return "No Result";
            }
            int len = WideCharToMultiByte(targetCP, 0, wstr.data(), -1, nullptr, 0, nullptr, nullptr);
            if (len <= 0) {
                return "No Result";
            }
            std::vector<char> gbk(len);
            if (WideCharToMultiByte(targetCP, 0, wstr.data(), -1, gbk.data(), len, nullptr, nullptr) == 0) {
                return "No Result";
            }
            if (len > 0 && gbk[len - 1] == '\0') {
                return std::string(gbk.data(), len - 1);
            }
            return std::string(gbk.data(), len);
        }

		// GBK -> UTF8
        std::string gbk_to_utf8(const std::string& gbk) {
            if (gbk.empty()) return "";
            int wlen = MultiByteToWideChar(CP_ACP, 0, gbk.c_str(), -1, nullptr, 0);
            if (wlen <= 0) return "";
            std::vector<wchar_t> wstr(wlen);
            MultiByteToWideChar(CP_ACP, 0, gbk.c_str(), -1, wstr.data(), wlen);
            int len = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), -1, nullptr, 0, nullptr, nullptr);
            if (len <= 0) return "";
            std::vector<char> utf8(len);
            WideCharToMultiByte(CP_UTF8, 0, wstr.data(), -1, utf8.data(), len, nullptr, nullptr);
            if (len > 0 && utf8[len - 1] == '\0') {
                return std::string(utf8.data(), len - 1);
            }
            return std::string(utf8.data(), len);
        }
    }

    // ============================================================
    // AES 加密/解密
    // ============================================================
    namespace Crypto
    {
        static std::string build_aad()
        {
            return "author=" + std::to_string(AUTHOR_ID) +
                "|software=" + std::to_string(SOFTWARE_ID);
        }


        bool aes_gcm_encrypt(
            const std::vector<unsigned char>& plaintext,
            const std::vector<unsigned char>& key,
            std::vector<unsigned char>& nonce,
            std::vector<unsigned char>& out
        ) {
            const std::string aad = build_aad();

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            const EVP_CIPHER* cipher = nullptr;
            if (key.size() == 16) cipher = EVP_aes_128_gcm();
            else if (key.size() == 32) cipher = EVP_aes_256_gcm();
            else { EVP_CIPHER_CTX_free(ctx); return false; }

            nonce.resize(12);
            RAND_bytes(nonce.data(), (int)nonce.size());

            int len = 0, ciphertext_len = 0;
            int tmp = 0;

            if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) goto err;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) goto err;
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) goto err;

            if (EVP_EncryptUpdate(ctx, nullptr, &tmp,
                reinterpret_cast<const unsigned char*>(aad.data()),
                (int)aad.size()) != 1) goto err;

            out.resize(plaintext.size());

            if (EVP_EncryptUpdate(ctx, out.data(), &len,
                plaintext.data(), (int)plaintext.size()) != 1) goto err;

            ciphertext_len = len;

            if (EVP_EncryptFinal_ex(ctx, out.data() + len, &len) != 1) goto err;
            ciphertext_len += len;

            unsigned char tag[16];
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto err;

            out.resize(ciphertext_len);
            out.insert(out.end(), tag, tag + 16);

            EVP_CIPHER_CTX_free(ctx);
            return true;

        err:
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }


        bool aes_gcm_decrypt(
            const std::vector<unsigned char>& data,
            const std::vector<unsigned char>& key,
            const std::vector<unsigned char>& nonce,
            std::vector<unsigned char>& out_plain
        ) {
            if (nonce.size() != 12 || data.size() < 16) return false;

            const std::string aad = build_aad();

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            const EVP_CIPHER* cipher = nullptr;
            if (key.size() == 16) cipher = EVP_aes_128_gcm();
            else if (key.size() == 32) cipher = EVP_aes_256_gcm();
            else { EVP_CIPHER_CTX_free(ctx); return false; }

            const size_t cipher_len = data.size() - 16;
            const unsigned char* tag = data.data() + cipher_len;

            int len = 0, plain_len = 0;
            int tmp = 0;

            if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) goto err;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) goto err;
            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) goto err;

            if (EVP_DecryptUpdate(ctx, nullptr, &tmp,
                reinterpret_cast<const unsigned char*>(aad.data()),
                (int)aad.size()) != 1) goto err;

            out_plain.resize(cipher_len);

            if (EVP_DecryptUpdate(ctx, out_plain.data(), &len,
                data.data(), (int)cipher_len) != 1) goto err;

            plain_len = len;

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto err;

            if (EVP_DecryptFinal_ex(ctx, out_plain.data() + len, &len) != 1) goto err;

            plain_len += len;
            out_plain.resize(plain_len);

            EVP_CIPHER_CTX_free(ctx);
            return true;

        err:
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }




    }

    // ============================================================
    // RSA 验签
    // ============================================================
    namespace Signature
    {
        bool verify_signature(
            const std::string& data_hex,
            const std::string& iv_hex,
            long long /*server_time*/,
            const std::string& sig_hex)
        {
            VMProtectBeginUltra("VerifySign");
            using namespace Encoding;

            std::vector<unsigned char> raw_data = from_hex(data_hex);

            unsigned char hash[32];
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                VMProtectEnd();
                return false;
            }

            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, raw_data.data(), raw_data.size());
            EVP_DigestFinal_ex(mdctx, hash, nullptr);
            EVP_MD_CTX_free(mdctx);

            BIO* bio = BIO_new_mem_buf(PUBLIC_KEY_PEM.c_str(), -1);
            if (!bio) {
                VMProtectEnd();
                return false;
            }

            EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!pubkey) {
                std::cout << skCrypt("❌ 公钥解析失败\n").decrypt();
                VMProtectEnd();
                return false;
            }

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
            bool result = false;

            if (EVP_PKEY_verify_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0)
            {
                std::vector<unsigned char> sig = from_hex(sig_hex);
                result = (EVP_PKEY_verify(
                    ctx,
                    sig.data(),
                    (size_t)sig.size(),
                    hash,
                    sizeof(hash)
                ) == 1);
            }

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pubkey);
            VMProtectEnd();
            return result;
        }
    }

    // ============================================================
    // 网络
    // ============================================================
    namespace Network
    {
        size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, std::string* s) {
            s->append((char*)ptr, size * nmemb);
            return size * nmemb;
        }

        std::string http_post(const std::string& url, const std::string& body) {
            VMProtectBegin("HttpPost");

            CURL* curl = curl_easy_init();
            if (!curl) {
                VMProtectEnd();
                return "";
            }

            std::string resp;
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

            CURLcode code = curl_easy_perform(curl);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            VMProtectEnd();

            if (code != CURLE_OK) {
                std::cout << skCrypt("❌ 网络请求失败: ").decrypt() << curl_easy_strerror(code) << "\n";
                return "";
            }

            return resp;
        }
    }

    // ============================================================
    // 反调试
    // ============================================================
    namespace AntiDebug
    {
        void SecureAbort() {
            VMProtectBeginUltra("SecureAbort");
            __ud2();
            TerminateProcess(GetCurrentProcess(), 0);
            VMProtectEnd();
        }

        bool Check() {
            VMProtectBegin("AntiCheck");

            if (VMProtectIsDebuggerPresent(true)) { VMProtectEnd(); return true; }
            if (VMProtectIsVirtualMachinePresent()) { VMProtectEnd(); return true; }
            if (!VMProtectIsValidImageCRC()) { VMProtectEnd(); return true; }

            VMProtectEnd();
            return false;
        }
    }
}

// ============================================================
// 验证主要逻辑
// ============================================================
namespace KeyAuth
{
    static std::string session_id;
    static std::string token;
    static std::string hwid;
    static std::vector<unsigned char> secret_key_bytes;

    static std::atomic<bool> running{ false };
    static std::thread      th_main;

    // 上次登录用的卡密
    static std::string g_last_license;
    // 重连失败原因
    static std::string g_last_error;
    // 防止心跳线程并发重登
    static std::mutex g_relogin_mtx;
    static bool is_token_error(const std::string& err)
    {
        return (err.find("invalid token") != std::string::npos) ;
    }

    // 初始化
    bool Init()
    {
        curl_global_init(CURL_GLOBAL_ALL);
        secret_key_bytes = Tools::Encoding::from_hex(SECRET_KEY);
        hwid = Tools::System::get_hwid();
        std::cout << skCrypt("   [验证] KeyAuth 初始化完成\n").decrypt();
        return true;
    }

    // 加密封装
    static bool encrypt_payload(const json& data, std::string& out_data, std::string& out_iv)
    {
        VMProtectBegin("EncryptPayload");

        std::string plain = data.dump(-1, ' ', false);  // 紧凑 JSON
        std::vector<unsigned char> bin(plain.begin(), plain.end());

        if (std::string(CRYPTO_TYPE) == "Plain")
        {
            out_data = Tools::Encoding::to_hex(bin);
            out_iv = "";
            VMProtectEnd();
            return true;
        }

        // AES 模式
        std::vector<unsigned char> nonce, cipher;
        if (!Tools::Crypto::aes_gcm_encrypt(bin, secret_key_bytes, nonce, cipher))
        {
            VMProtectEnd();
            return false;
        }


        out_data = Tools::Encoding::to_hex(cipher);
        out_iv = Tools::Encoding::to_hex(nonce);


        VMProtectEnd();
        return true;
    }

    // 解密封装
    static json decrypt_payload(const std::string& data_hex, const std::string& iv_hex)
    {
        VMProtectBegin("DecryptPayload");

        try
        {
            if (std::string(CRYPTO_TYPE) == "Plain")
            {
                std::vector<unsigned char> bin = Tools::Encoding::from_hex(data_hex);
                VMProtectEnd();
                return json::parse(std::string(bin.begin(), bin.end()));
            }

            // AES 模式
            std::vector<unsigned char> data = Tools::Encoding::from_hex(data_hex);
            std::vector<unsigned char> nonce = Tools::Encoding::from_hex(iv_hex);
            std::vector<unsigned char> plain;

            if (!Tools::Crypto::aes_gcm_decrypt(data, secret_key_bytes, nonce, plain))
            {
                VMProtectEnd();
                return nullptr;
            }

            VMProtectEnd();
            return json::parse(std::string(plain.begin(), plain.end()));
        }
        catch (...)
        {
            VMProtectEnd();
            return nullptr;
        }
    }


    // 通用请求
    static json send_request(const std::string& endpoint, const json& req_data)
    {
        VMProtectBegin("SendRequest");

        constexpr int MAX_RETRY = 3;
        g_last_error.clear();

        for (int attempt = 1; attempt <= MAX_RETRY; ++attempt)
        {
            json inner = req_data;
            inner["timestamp"] = Tools::System::get_timestamp();

            // 防重放攻击
            std::string current_nonce = Tools::System::gen_nonce();
            inner["nonce"] = current_nonce;

            std::string data_hex, iv_hex;
            if (!encrypt_payload(inner, data_hex, iv_hex))
            {
                g_last_error = "encrypt failed";
                std::cout << skCrypt("   [请求]  加密失败\n").decrypt();
                VMProtectEnd();
                return nullptr;
            }

            json payload = {
                {"author_id",   AUTHOR_ID},
                {"software_id", SOFTWARE_ID},
                {"data",        data_hex},
                {"iv",          iv_hex},
                {"signature",   ""}
            };

            std::string resp_str = Tools::Network::http_post(
                API_URL + endpoint,
                payload.dump()
            );

            // 网络失败 → 重试
            if (resp_str.empty())
            {
                g_last_error = "network error";
                std::cout << skCrypt("   [请求]  网络失败").decrypt()
                    << " (" << attempt << "/" << MAX_RETRY << ")\n";

                if (attempt < MAX_RETRY)
                {
                    Sleep(30000);
                    continue;
                }

                VMProtectEnd();
                return nullptr;
            }

            json resp;
            try
            {
                resp = json::parse(resp_str);
            }
            catch (...)
            {
                g_last_error = "json parse failed";
                std::cout << skCrypt("   [请求]  响应 JSON 解析失败\n").decrypt();
                VMProtectEnd();
                return nullptr;
            }

            // 服务端返回错误
            if (resp.contains("error"))
            {
                try {
                    g_last_error = resp["error"].get<std::string>();
                }
                catch (...) {
                    g_last_error = "server error";
                }

                std::cout << skCrypt("   [请求] 服务器返回错误：").decrypt()
                    << g_last_error << "\n";

                VMProtectEnd();
                return nullptr;
            }

            // 基本字段检查
            if (!resp.contains("data"))
            {
                g_last_error = "protocol missing data";
                std::cout << skCrypt("   [请求]  协议错误：缺少 data 字段\n").decrypt();
                VMProtectEnd();
                return nullptr;
            }

            // 验签
            if (USE_SIGNATURE)
            {
                if (!resp.contains("sign"))
                {
                    g_last_error = "protocol missing sign";
                    std::cout << skCrypt("   [请求]  协议错误：缺少 sign 字段\n").decrypt();
                    VMProtectEnd();
                    return nullptr;
                }

                if (!Tools::Signature::verify_signature(
                    resp["data"],
                    resp.contains("iv") ? resp["iv"] : "",
                    resp.contains("server_time") ? resp["server_time"].get<long long>() : 0,
                    resp["sign"]))
                {
                    g_last_error = "signature verify failed";
                    std::cout << skCrypt("   [请求]  签名校验失败\n").decrypt();
                    VMProtectEnd();
                    return nullptr;
                }
            }

            // 解密
            json decrypted_data = decrypt_payload(
                resp["data"],
                resp.contains("iv") ? resp["iv"] : ""
            );

            if (decrypted_data.is_null())
            {
                g_last_error = "decrypt failed";
                VMProtectEnd();
                return nullptr;
            }

            // 防重放检验
            if (!decrypted_data.contains("nonce") ||
                decrypted_data["nonce"] != current_nonce)
            {
                g_last_error = "nonce mismatch";
                std::cout << skCrypt("   [严重安全警告] 遭到重放攻击！Nonce 不匹配！\n").decrypt();

                Tools::AntiDebug::SecureAbort();
                VMProtectEnd();
                return nullptr;
            }

            g_last_error.clear();
            VMProtectEnd();
            return decrypted_data;
        }

        VMProtectEnd();
        return nullptr;
    }



    // 登录
    bool Login(const std::string& license)
    {
        VMProtectBegin("Login");

        json req = {
            {"license", license},
            {"hwid",    hwid},
            {"version", VERSION}
        };

        json res = send_request("/api/client/login", req);
        if (res.is_null())
        {
            VMProtectEnd();
            return false;
        }

        if (!res.contains("session_id") || !res.contains("token"))
        {
            std::cout << skCrypt("   [验证] 登录响应缺少 session_id/token\n").decrypt();
            VMProtectEnd();
            return false;
        }

        session_id = res["session_id"].get<std::string>();
        token = res["token"].get<std::string>();

        g_last_license = license;

        std::cout << skCrypt("   [验证] 登录成功！\n").decrypt();

        if (res.contains("announcement"))
        {
            std::string ann = res["announcement"];
            std::cout << skCrypt("   [公告] ").decrypt()
                << Tools::Text::utf8_to_gbk(ann) << "\n";
        }

        // 版本检查
        std::string localVer = VERSION;
        std::string cloudVer = res.contains("latest_version")
            ? res["latest_version"].get<std::string>()
            : "";

        if (cloudVer.empty()) {
            std::cout << skCrypt("   [更新] 无法获取服务器版本号,跳过更新\n").decrypt();
        }
        else if (cloudVer != localVer) {
            std::cout << skCrypt("   [更新] 发现新版本！请更新客户端！\n").decrypt();
            std::cout << "   [更新] 当前版本：" << localVer << "  →  最新版本：" << cloudVer << "\n";
            if (res.contains("download_url"))
                std::cout << "   [更新] 下载链接： " << res["download_url"].get<std::string>() << "\n";
        }
        else {
            std::cout << skCrypt("   [更新]客户端已是最新版本。\n").decrypt();
        }

        if (res.contains("expiry"))
        {
            long long exp = res["expiry"];
            std::time_t t = (std::time_t)exp;
            tm ti{};
            localtime_s(&ti, &t);
            char buf[64]{};
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ti);
            std::cout << skCrypt("   [到期]: ").decrypt() << buf << "\n";
        }

        VMProtectEnd();
        return true;
    }


    // 获取软件公告/状态
    bool GetSoftwareInfo()
    {
        VMProtectBegin("GetSoftwareInfo");
        std::cout << "   " << std::string(30, '-') << "\n"; //使用--------分割开
        json req = json::object();
        json res = send_request("/api/client/get_announcement", req);

        if (res.is_null())
        {
            VMProtectEnd();
            return false;
        }

        // 软件开启维护状态
        if (res.contains("maintenance") && res["maintenance"].get<bool>() == true)
        {
            std::cout << skCrypt("   [状态] 服务器正在维护中，无法登录！\n").decrypt();
        }

        // 显示公告
        if (res.contains("announcement"))
        {
            std::string ann = res["announcement"].get<std::string>();
            if (!ann.empty()) {
                std::cout << skCrypt("   [公告] ").decrypt()
                    << Tools::Text::utf8_to_gbk(ann) << "\n";
            }
        }

        // 版本检测
        if (res.contains("latest_version"))
        {
            std::string cloudVer = res["latest_version"].get<std::string>();
            if (!cloudVer.empty() && cloudVer != VERSION)
            {
                std::cout << skCrypt("   [更新] 发现新版本！请更新客户端！\n").decrypt();
                std::cout << "   [更新] 当前版本：" << VERSION << "  →  最新版本：" << cloudVer << "\n";

                if (res.contains("download_url")) {
                    std::cout << "   [更新] 下载链接： " << res["download_url"].get<std::string>() << "\n";
                }
            }
        }

        std::cout << "   " << std::string(30, '-') << "\n";//使用--------分割开

        VMProtectEnd();
        return true;
    }

    // 自助解绑
    bool Unbind(const std::string& license)
    {
        VMProtectBegin("Unbind");

        json req = {
            {"license", license}
        };

        json res = send_request("/api/client/unbind", req);
        if (res.is_null())
        {
            VMProtectEnd();
            return false;
        }

        std::string msg = "解绑指令已发送";
        if (res.contains("message")) {
            msg = res["message"].get<std::string>();
        }
        // 如果服务器返回了 success 或 message 字段
        std::cout << skCrypt("   [解绑] ").decrypt() << Tools::Text::utf8_to_gbk(msg) << "\n";

        VMProtectEnd();
        return true;
    }

    // 心跳
    int Heartbeat()
    {
        VMProtectBegin("Heartbeat");

        json req = {
            {"session_id", session_id},
            {"token",      token}
        };

        json res = send_request("/api/client/heartbeat", req);

        // 检查是不是 token 错误
        if (res.is_null())
        {
            // token 错误 自动重登一次 再心跳一次
            if (is_token_error(g_last_error) && !g_last_license.empty())
            {
                std::lock_guard<std::mutex> lk(g_relogin_mtx);

                std::cout << skCrypt("   [心跳] token 异常，尝试重新登录...\n").decrypt();

                if (Login(g_last_license))
                {
                    std::cout << skCrypt("   [心跳] 重登成功，重试心跳...\n").decrypt();

                    json req2 = {
                        {"session_id", session_id},
                        {"token",      token}
                    };

                    json res2 = send_request("/api/client/heartbeat", req2);
                    if (res2.is_null())
                    {
                        std::cout << skCrypt("   [心跳] 重登后心跳仍失败\n").decrypt();
                        VMProtectEnd();
                        return 0;
                    }

                    res = res2;
                }
                else
                {
                    std::cout << skCrypt("   [心跳] 重登失败\n").decrypt();
                    VMProtectEnd();
                    return 0;
                }
            }
            else
            {
                std::cout << skCrypt("   [心跳]  心跳失败\n").decrypt();
                VMProtectEnd();
                return 0;
            }
        }

        if (!res.contains("next_token"))
        {
            std::cout << skCrypt("   [心跳]  协议错误：缺少 next_token\n").decrypt();
            VMProtectEnd();
            return 0;
        }

        std::string server_next_token = res["next_token"].get<std::string>();

        token = server_next_token;

        long long server_time = res.contains("server_time") ? res["server_time"].get<long long>() : 0;

        std::cout << skCrypt("   [心跳]  心跳成功 | token=").decrypt()
            << token
            << skCrypt(" | server_time=").decrypt()
            << server_time
            << "\n";

        VMProtectEnd();
        return 1;
    }

    // 获取远程变量
    std::string GetVar(const std::string& key)
    {
        VMProtectBegin("GetVar");

        std::cout << skCrypt("   [远程变量]  请求远程变量: ").decrypt() << key << " ...\n";

        json req = {
            {"session_id", session_id},
            {"var_key",    key}
        };

        json res = send_request("/api/client/get_var", req);
        if (res.is_null())
        {
            VMProtectEnd();
            return "";
        }

        std::string v = res["var_value"];

        VMProtectEnd();
        return v;
    }

    // 保持心跳
    void StartKeepAlive(int interval_ms)
    {
        if (running.load()) return;
        running.store(true);

        th_main = std::thread([interval_ms]() {
            while (running.load())
            {
                if (!Heartbeat())
                {
                    std::cout << skCrypt("   [心跳线程]  心跳中断\n").decrypt();
                    running.store(false);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
            });
    }

    void StopKeepAlive()
    {
        running.store(false);
        if (th_main.joinable()) th_main.join();
    }
}

int main()
{
    KeyAuth::Init();


    // 获取软件公告
    KeyAuth::GetSoftwareInfo();

    // 获取无需登录的变量
    std::string pre_login_var = KeyAuth::GetVar("test233");
    if (!pre_login_var.empty()) {
        std::cout << skCrypt("   [远程变量(未登录)] = ").decrypt()
            << Tools::Text::utf8_to_gbk(pre_login_var) << "\n";
    }

    std::cout << skCrypt("   [1] 登录验证\n").decrypt();
    std::cout << skCrypt("   [2] 自助解绑\n").decrypt();
    std::cout << "   " << std::string(30, '-') << "\n";
    std::cout << skCrypt("   请选择功能: ").decrypt();

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "2")
    {
        std::cout << skCrypt("   [解绑] 请输入要解绑的卡密：").decrypt();
        std::string key_gbk;
        std::getline(std::cin, key_gbk);
        std::string key_utf8 = Tools::Text::gbk_to_utf8(key_gbk);

        if (KeyAuth::Unbind(key_utf8)) {
            std::cout << skCrypt("   [解绑] 操作成功。\n").decrypt();
        }
        else {
            std::cout << skCrypt("   [解绑] 解绑失败。\n").decrypt();
        }

        std::cout << skCrypt("   按回车退出...\n").decrypt();
        std::cin.get();
    }
    else
    {

        std::cout << skCrypt("   [验证] 请输入卡密：").decrypt();

        std::string key_gbk;
        std::getline(std::cin, key_gbk);

        std::string key_utf8 = Tools::Text::gbk_to_utf8(key_gbk);

        //仅演示反调试，实际项目请根据需要自行调整反调试策略，并且自行完善反调试逻辑 
        if (Tools::AntiDebug::Check()) {
            Tools::AntiDebug::SecureAbort();
            return 0;
        }



        if (KeyAuth::Login(key_utf8))
        {
            std::string var_value_utf8 = KeyAuth::GetVar("2333");//修改为你后台创建的变量名 请使用非中文防止编码问题

            if (var_value_utf8.empty()) {
                std::cout << skCrypt("   [远程变量] 获取失败.\n").decrypt();
            }
            else {
                std::string var_show = Tools::Text::utf8_to_gbk(var_value_utf8);
                std::cout << skCrypt("   [远程变量] 变量 =  ").decrypt() << var_show << "\n";
            }

            //  此处仅演示在独立线程里做心跳：

            //  实际项目建议把心跳逻辑合并到主循环 / 业务线程中

            //  避免心跳线程被单独挂起调试。

            //  心跳间隔建议设置为 30 秒以上，防止被Cloudflare拉黑。
            KeyAuth::StartKeepAlive(30000);

            std::cout << skCrypt("   [验证] 按下回车退出...\n").decrypt();
            std::cin.get();

            KeyAuth::StopKeepAlive();
        }
        else
        {
            std::cout << skCrypt("   [验证] 登录失败。\n").decrypt();
        }

    }
    system("pause");
    return 0;
}