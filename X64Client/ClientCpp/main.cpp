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
// 服务器连接配置开始 请从作者管理后台获取软件相应配置
// ============================================================
// C++ 配置
const std::string API_URL = skCrypt("http://127.0.0.1:8080").decrypt();
const uint32_t AUTHOR_ID = 31;
const uint32_t SOFTWARE_ID = 22;
const std::string SECRET_KEY = skCrypt("3ef3f0ce16e92d0ad526fc7d24bcf1d3").decrypt();
const std::string VERSION = skCrypt("1.0").decrypt();

// 安全配置
#define CRYPTO_TYPE skCrypt("AES").decrypt()
#define USE_SIGNATURE true

// RSA 公钥
const std::string PUBLIC_KEY_PEM =
skCrypt("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwL1HFzFAt1ar9jF/Q1VQ\n40A+byJh/tjekJUBgOV6CpOinSYVI2LEVq6aP8y17Qr9OFafdq69Awkx7ceueYcA\nuxlwuMa9/7vKWcMu4kKEcth4Kuec1KNGzCfbWGO/dszQCFX2E0lfxUCB6REcF7sh\nue5KitjIkcd07XWvPa6hR7qlW7nTMRWvCB0B812c89F3/2u42OgP57KDGjuKnZHm\nBoJvttFkUI4VsBFMYrbjfNBuUaTWMQXZRlseyKdp9jQtQ653euXoZroQSooURA+f\n/0jqxQ7Zk2OjYK6rIkP5SX+bMAM0h7qq/w76EbwQsbF9RuSJz0857+fpbKZUiU0R\nLQIDAQAB\n-----END PUBLIC KEY-----\n").decrypt();

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
    // 系统级工具
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
            int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
            std::wstring wstr(wlen, 0);
            MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], wlen);
            int len = WideCharToMultiByte(936, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string gbk(len, 0);
            WideCharToMultiByte(936, 0, wstr.c_str(), -1, &gbk[0], len, nullptr, nullptr);
            return gbk;
        }
    }

    // ============================================================
    // AES 加密/解密
    // ============================================================
    namespace Crypto
    {
        // PKCS7 填充
        std::vector<unsigned char> pkcs7_pad(const std::vector<unsigned char>& data) {
            size_t padLen = 16 - (data.size() % 16);
            std::vector<unsigned char> out = data;
            out.insert(out.end(), padLen, (unsigned char)padLen);
            return out;
        }

        // PKCS7 去填充
        std::vector<unsigned char> pkcs7_unpad(const std::vector<unsigned char>& data) {
            if (data.empty()) return {};
            unsigned char pad = data.back();
            if (pad == 0 || pad > data.size()) return {};
            return std::vector<unsigned char>(data.begin(), data.end() - pad);
        }

        // AES CBC 加/解密
        bool aes_cbc_crypt(
            bool encrypt,
            const std::vector<unsigned char>& in,
            const std::vector<unsigned char>& key,
            std::vector<unsigned char>& iv,
            std::vector<unsigned char>& out
        ) {
            VMProtectBeginUltra("AES");

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                VMProtectEnd();
                return false;
            }

            const EVP_CIPHER* cipher = EVP_aes_128_cbc();
            if (key.size() == 32) cipher = EVP_aes_256_cbc();

            if (encrypt) {
                iv.resize(16); RAND_bytes(iv.data(), 16);
                EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data());
                EVP_CIPHER_CTX_set_padding(ctx, 0);

                std::vector<unsigned char> padded = pkcs7_pad(in);
                out.resize(padded.size() + 16);

                int len1, len2;
                EVP_EncryptUpdate(ctx, out.data(), &len1, padded.data(), (int)padded.size());
                EVP_EncryptFinal_ex(ctx, out.data() + len1, &len2);
                out.resize(len1 + len2);
            }
            else {
                EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data());
                EVP_CIPHER_CTX_set_padding(ctx, 0);

                out.resize(in.size() + 16);
                int len1, len2;

                EVP_DecryptUpdate(ctx, out.data(), &len1, in.data(), (int)in.size());
                EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2);
                out.resize(len1 + len2);

                out = pkcs7_unpad(out);
            }

            EVP_CIPHER_CTX_free(ctx);
            VMProtectEnd();
            return true;
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
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

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
        std::vector<unsigned char> iv, cipher;
        if (!Tools::Crypto::aes_cbc_crypt(true, bin, secret_key_bytes, iv, cipher))
        {
            VMProtectEnd();
            return false;
        }

        out_data = Tools::Encoding::to_hex(cipher);
        out_iv = Tools::Encoding::to_hex(iv);

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
            std::vector<unsigned char> cipher = Tools::Encoding::from_hex(data_hex);
            std::vector<unsigned char> iv = Tools::Encoding::from_hex(iv_hex);
            std::vector<unsigned char> bin;

            if (!Tools::Crypto::aes_cbc_crypt(false, cipher, secret_key_bytes, iv, bin))
            {
                VMProtectEnd();
                return nullptr;
            }

            VMProtectEnd();
            return json::parse(std::string(bin.begin(), bin.end()));
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

        json inner = req_data;
        inner["timestamp"] = Tools::System::get_timestamp();
        inner["nonce"] = Tools::System::gen_nonce();

        std::string data_hex, iv_hex;
        if (!encrypt_payload(inner, data_hex, iv_hex))
        {
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

        std::string resp_str = Tools::Network::http_post(API_URL + endpoint, payload.dump());
        if (resp_str.empty())
        {
            std::cout << skCrypt("   [请求]  网络失败\n").decrypt();
            VMProtectEnd();
            return nullptr;
        }

        json resp;
        try {
            resp = json::parse(resp_str);
        }
        catch (...) {
            std::cout << skCrypt("   [请求]  响应 JSON 解析失败\n").decrypt();
            VMProtectEnd();
            return nullptr;
        }

        if (resp.contains("error"))
        {
            std::cout << skCrypt("   [请求] 登录失败,服务器返回：").decrypt() << resp["error"] << "\n";
            VMProtectEnd();
            return nullptr;
        }

        // 验签
        if (USE_SIGNATURE)
        {
            if (!Tools::Signature::verify_signature(
                resp["data"],
                resp.contains("iv") ? resp["iv"] : "",
                resp["server_time"],
                resp["sign"]))
            {
                std::cout << skCrypt("   [请求]  签名校验失败\n").decrypt();
                VMProtectEnd();
                return nullptr;
            }
        }

        VMProtectEnd();
        return decrypt_payload(resp["data"], resp.contains("iv") ? resp["iv"] : "");
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

        session_id = res["session_id"];
        token = res["token"];

        std::cout << skCrypt("   [验证] 登录成功！\n").decrypt();

        if (res.contains("announcement"))
        {
            std::string ann = res["announcement"];
            std::cout << skCrypt("   [公告] ").decrypt()
                << Tools::Text::utf8_to_gbk(ann) << "\n";
        }

        // === 版本检查 ===
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

    // 心跳
    int Heartbeat()
    {
        VMProtectBegin("Heartbeat");

        json req = {
            {"session_id", session_id},
            {"token",      token}
        };

        json res = send_request("/api/client/heartbeat", req);

        if (res.is_null())
        {
            std::cout << skCrypt("   [心跳]  心跳失败\n").decrypt();
            VMProtectEnd();
            return 0;
        }

        token = res["next_token"];

        long long server_time = res["server_time"];
        std::cout << skCrypt("   [心跳]  心跳成功，服务器时间戳: ").decrypt()
            << server_time << "\n";

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

    // 保持心跳（独立线程示例）
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

    std::cout << skCrypt("   [验证] 请输入卡密：").decrypt();
    std::string key;
    std::getline(std::cin, key);

	//仅演示反调试，实际项目请根据需要自行调整反调试策略，并且自行完善反调试逻辑
    if (Tools::AntiDebug::Check())
    {
        Tools::AntiDebug::SecureAbort();
    }

    if (KeyAuth::Login(key))
    {
		std::string v = KeyAuth::GetVar("变量名");//修改为你后台创建的变量名
        std::cout << skCrypt("   [远程变量] 变量 = ").decrypt()
            << Tools::Text::utf8_to_gbk(v) << "\n";

        // ⚠ 此处仅演示在独立线程里做心跳：
        //   实际项目建议把心跳逻辑合并到主循环 / 业务线程中，
        //   避免心跳线程被单独挂起调试。
        KeyAuth::StartKeepAlive(60000);

        std::cout << skCrypt("   [验证] 按下回车退出...\n").decrypt();
        std::cin.get();

		// 停止心跳线程
        KeyAuth::StopKeepAlive();
    }
    else
    {
        std::cout << skCrypt("   [验证] 登录失败。\n").decrypt();
    }
    system("pause");

    return 0;
}
