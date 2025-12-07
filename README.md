# 🔐 C++ Authentication Client Example  
**AES 加密 · RSA 签名验证 · HWID 绑定 · 心跳 · 远程变量 · 反调试 · VMProtect**

本项目示例展示了如何在 C++ 中构建一个安全、可扩展的网络验证 / 软件授权客户端，具备完整的通信加密、会话管理和安全防护能力。

该示例中的逻辑包括：

- ✔ AES-CBC 数据加密（PKCS7 Padding）  
- ✔ RSA-SHA256 服务端签名验证  
- ✔ Curl HTTP 请求  
- ✔ HWID 绑定（MAC 或 ComputerName → MD5）  
- ✔ 卡密登录  
- ✔ 心跳保持（Keep-Alive）  
- ✔ 远程变量（后台可热更新）  
- ✔ 版本检查 / 公告  
- ✔ VMProtect 虚拟化 & 字符串加密（skCrypt）  
- ✔ 反调试（Debugger、VM、Image CRC）  
- ✔ 可扩展 API Framework

---

# 📦 功能特性

### 🔐 加密通信  
所有请求使用 AES-CBC 加密。  
响应采用 RSA-SHA256 验签，确保数据未被篡改。

### 🖥 HWID 绑定  
默认使用：
- 网卡 MAC → MD5  
- 若失败则使用电脑名 → MD5

可根据需求扩展为更多硬件指纹。

### 🌐 API 封装  
内置常用接口：

| 接口名 | 说明 |
|-------|------|
| `Init()` | 初始化环境、HWID、密钥、Curl |
| `Login(license)` | 卡密登录 |
| `GetVar(key)` | 获取远程变量 |
| `Heartbeat()` | 心跳包 |
| `StartKeepAlive()` | 自动心跳线程 |
| `StopKeepAlive()` | 停止心跳线程 |

### 🛡 反调试保护  
集成 VMProtect：

- 检测调试器  
- 检测沙箱 / 虚拟机  
- 检测文件 CRC  
- 检测到攻击后 `SecureAbort()` 强制终止进程

### 🧵 心跳线程  
可后台自动保持 Token 刷新，避免卡密掉线。

---

# ⚙️ 配置说明

请修改在 `main.cpp` 顶部配置，他可以在作者后台对应软件位获取：

```cpp
const std::string API_URL
const uint32_t AUTHOR_ID
const uint32_t SOFTWARE_ID
const std::string SECRET_KEY
const std::string VERSION
const std::string PUBLIC_KEY_PEM
```

# ⚙️ 配置说明

```cpp
KeyAuth::Init();

std::cout << "请输入卡密：";
std::string key;
std::getline(std::cin, key);

if (KeyAuth::Login(key))
{
    std::string v = KeyAuth::GetVar("变量名");
    std::cout << "远程变量 = " << utf8_to_gbk(v) << "\n";

    KeyAuth::StartKeepAlive(60000);

    std::cout << "按回车退出...\n";
    std::cin.get();

    KeyAuth::StopKeepAlive();
}
else
{
    std::cout << "登录失败，请检查卡密或网络。\n";
}
``` 

#  📝 License
你可以自由修改并集成本项目到你的授权系统中。
如用于商业用途，请确保你了解相关法律法规。

#  ⭐ 鸣谢

OpenSSL

Curl

nlohmann/json

VMProtect

skCrypt
