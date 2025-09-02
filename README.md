# 🔐 Frida Hook - Android 加密算法监控框架

```
███████╗██████╗ ██╗██████╗  █████╗     ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
██╔════╝██╔══██╗██║██╔══██╗██╔══██╗    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
█████╗  ██████╔╝██║██║  ██║███████║    ███████║██║   ██║██║   ██║█████╔╝ 
██╔══╝  ██╔══██╗██║██║  ██║██╔══██║    ██╔══██║██║   ██║██║   ██║██╔═██╗ 
██║     ██║  ██║██║██████╔╝██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

> 一个功能强大的 Frida Hook 框架，专门用于监控和分析 Android 应用中的各种加密算法操作

## 📋 目录

- [项目简介](#-项目简介)
- [主要功能](#-主要功能)
- [支持的算法](#-支持的算法)
- [架构设计](#-架构设计)
- [安装使用](#-安装使用)
- [配置说明](#-配置说明)
- [输出格式](#-输出格式)
- [使用示例](#-使用示例)
- [注意事项](#-注意事项)
- [作者信息](#-作者信息)

## 🎯 项目简介

本项目是一个基于 Frida 的 Android 加密算法监控框架，能够实时监控和分析 Android 应用中的各种加密操作，包括对称加密、非对称加密、哈希算法和编码操作。通过 Hook Java 层的加密 API，可以获取加密算法的输入输出数据、密钥信息、算法参数等详细信息。

## 🔧 主要功能

### 🔐 加密算法监控
- **对称加密**：AES、DES、3DES、RC4、ChaCha20
- **非对称加密**：RSA 加密/解密/签名/验签
- **哈希算法**：MD5、SHA-1、SHA-256、SHA-384、SHA-512、SHA-3 系列
- **消息认证码**：HMAC-MD5、HMAC-SHA1、HMAC-SHA256、HMAC-SHA384、HMAC-SHA512
- **校验算法**：CRC32
- **编码算法**：Base64、Base32、Hex、URL、HTML、Unicode

### 🛠️ 核心特性
- **密钥管理监控**：密钥生成、密钥规格、密钥工厂、参数规格
- **多格式输出**：支持 JSON、十六进制、Base64、字符串、ASCII、UTF-8 等格式
- **调用堆栈跟踪**：详细的方法调用链分析，便于定位加密操作位置
- **实时日志系统**：可配置的日志级别和彩色输出
- **配置驱动**：通过配置对象统一管理所有 Hook 开关
- **异常处理**：完善的异常捕获和错误处理机制

## 🎨 支持的算法

### 对称加密算法
| 算法 | 支持模式 | 密钥长度 | 状态 |
|------|----------|----------|------|
| AES | ECB/CBC/CFB/OFB/GCM/CTR | 128/192/256 bit | ✅ |
| DES | ECB/CBC/CFB/OFB | 56 bit | ✅ |
| 3DES | ECB/CBC/CFB/OFB | 112/168 bit | ✅ |
| RC4 | Stream | 40-2048 bit | ✅ |
| ChaCha20 | Stream | 256 bit | ✅ |

### 非对称加密算法
| 算法 | 操作类型 | 密钥长度 | 状态 |
|------|----------|----------|------|
| RSA | 加密/解密 | 1024/2048/4096 bit | ✅ |
| RSA | 签名/验签 | 1024/2048/4096 bit | ✅ |

### 哈希算法
| 算法 | 输出长度 | 状态 |
|------|----------|------|
| MD5 | 128 bit | ✅ |
| SHA-1 | 160 bit | ✅ |
| SHA-256 | 256 bit | ✅ |
| SHA-384 | 384 bit | ✅ |
| SHA-512 | 512 bit | ✅ |
| SHA-3 系列 | 224/256/384/512 bit | ✅ |
| HMAC 系列 | 可变 | ✅ |
| CRC32 | 32 bit | ✅ |

### 编码算法
| 编码类型 | 状态 |
|----------|------|
| Base64 | ✅ |
| Base32 | ✅ |
| Hex | ✅ |
| URL 编码 | ✅ |
| HTML 编码 | ✅ |
| Unicode | ✅ |

## 🏗️ 架构设计

### 核心组件

```
┌─────────────────────────────────────────────────────────────┐
│                        CONFIG                               │
│                    (全局配置对象)                            │
├─────────────────────────────────────────────────────────────┤
│  Logger  │  HookUtils  │  FormatUtils  │  BaseHook         │
│ (日志系统) │ (Hook工具类) │ (格式化工具)   │ (Hook基类)        │
├─────────────────────────────────────────────────────────────┤
│                      Hook 实现类                            │
├─────────────────────────────────────────────────────────────┤
│ HashHook │ RSACipherHook │ AESCipherHook │ DESCipherHook    │
│ HMACHook │ RSASignatureHook │ AESKeyGenHook │ ChaCha20Hook  │
│ CRC32Hook│ RSAKeyPairHook │ AESKeySpecHook │ DESKeyGenHook │
└─────────────────────────────────────────────────────────────┘
```

### 设计特点
- **模块化设计**：每个算法独立的 Hook 类，便于维护和扩展
- **继承体系**：BaseHook 基类提供通用功能，减少代码重复
- **配置驱动**：通过 CONFIG 对象统一管理所有开关和参数
- **工具类库**：Logger、HookUtils、FormatUtils 提供通用支持
- **数据格式化**：多种编码格式的自动转换和展示

## 🚀 安装使用

### 环境要求
- Frida 16.0+
- Android 设备或模拟器
- 已 Root 的 Android 设备（推荐）或可调试的应用

### 安装步骤

1. **安装 Frida**
   ```bash
   pip install frida-tools
   ```

2. **下载项目文件**
   ```bash
   git clone <repository-url>
   cd frida-hook
   ```

3. **连接设备**
   ```bash
   # USB 连接
   adb devices
   
   # 确认 Frida 服务运行
   frida-ps -U
   ```

4. **运行 Hook**
   ```bash
   # Hook 指定应用
   frida -U -l hook.js <package-name>
   
   # Hook 正在运行的应用
   frida -U -l hook.js -n <app-name>
   
   # 启动应用并 Hook
   frida -U -l hook.js -f <package-name> --no-pause
   ```

## ⚙️ 配置说明

### 主要配置项

```javascript
const CONFIG = {
  // 日志配置
  logger: {
    level: 'INFO',           // 日志级别: DEBUG, INFO, WARN, ERROR
    enableColors: true,      // 启用彩色输出
    showTimestamp: true,     // 显示时间戳
    showStackTrace: true     // 显示调用堆栈
  },
  
  // Hook 开关配置
  hook: {
    // 对称加密算法
    symmetricCrypto: {
      aes: true,             // AES 算法
      des: true,             // DES 算法
      des3: true,            // 3DES 算法
      rc4: true,             // RC4 算法
      chacha20: true         // ChaCha20 算法
    },
    
    // 非对称加密算法
    asymmetricCrypto: {
      rsa: true              // RSA 算法
    },
    
    // 编码算法
    encoding: {
      base64: true,          // Base64 编码
      base32: true,          // Base32 编码
      hex: true,             // 十六进制编码
      url: true,             // URL 编码
      html: true,            // HTML 编码
      unicode: true          // Unicode 编码
    },
    
    // 哈希算法
    hash: {
      md5: true,             // MD5 哈希
      sha1: true,            // SHA-1 哈希
      sha256: true,          // SHA-256 哈希
      sha384: true,          // SHA-384 哈希
      sha512: true,          // SHA-512 哈希
      sha3: true,            // SHA-3 系列
      hmac: true,            // HMAC 系列
      crc32: true            // CRC32 校验
    }
  },
  
  // 输出格式配置
  output: {
    enableJsonFormat: true,  // 启用 JSON 格式输出
    enabledFormats: {
      hex: true,             // 十六进制格式
      base64: true,          // Base64 格式
      string: true,          // 字符串格式
      ascii: true,           // ASCII 格式
      utf8: true,            // UTF-8 格式
      raw: false             // 原始字节格式
    },
    fields: {
      timestamp: true,       // 时间戳
      algorithm: true,       // 算法名称
      input: true,           // 输入数据
      output: true,          // 输出数据
      key: true,             // 密钥信息
      stackTrace: true       // 调用堆栈
    }
  }
};
```

## 📊 输出格式

### JSON 格式输出示例

```json
{
  "timestamp": "2025-01-15 10:30:45.123",
  "algorithm": "AES/CBC/PKCS5Padding",
  "operation": "encrypt",
  "method": "doFinal",
  "input": {
    "hex": "48656c6c6f20576f726c64",
    "base64": "SGVsbG8gV29ybGQ=",
    "string": "Hello World",
    "length": 11
  },
  "output": {
    "hex": "a1b2c3d4e5f6789012345678901234567890abcdef",
    "base64": "obLD1OX2eJASNFZ4kBNFZ4kKvN7w==",
    "length": 16
  },
  "key": {
    "algorithm": "AES",
    "format": "RAW",
    "length": 256,
    "hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

### 控制台彩色输出

```
═══════════════════════════════════════════════════════════════════════════════
🔐 AES Hook 启动
═══════════════════════════════════════════════════════════════════════════════
[2025-01-15 10:30:45.123] [INFO] [AESCipherHook] AES.getInstance 调用
  📋 算法: AES/CBC/PKCS5Padding
  🔑 密钥长度: 256 bit
  📊 输入数据: Hello World (11 bytes)
  📤 输出数据: a1b2c3d4... (16 bytes)
  📍 调用位置: com.example.app.CryptoUtils.encrypt:45
```

## 💡 使用示例

### 基础使用

```bash
# Hook 微信应用的加密操作
frida -U -l hook.js com.tencent.mm

# Hook 支付宝应用并保存日志
frida -U -l hook.js com.eg.android.AlipayGphone > crypto_log.txt

# Hook 指定进程 ID
frida -U -l hook.js -p 1234
```

### 高级配置

```javascript
// 只监控 AES 和 RSA 算法
CONFIG.hook.symmetricCrypto.aes = true;
CONFIG.hook.asymmetricCrypto.rsa = true;
CONFIG.hook.symmetricCrypto.des = false;
CONFIG.hook.hash.md5 = false;

// 启用详细调试日志
CONFIG.logger.level = 'DEBUG';
CONFIG.logger.showStackTrace = true;

// 自定义输出格式
CONFIG.output.enabledFormats.hex = true;
CONFIG.output.enabledFormats.base64 = true;
CONFIG.output.enabledFormats.string = false;
```

## ⚠️ 注意事项

### 法律声明
- **仅用于安全研究和合法的逆向分析**
- **请遵守相关法律法规和道德准则**
- **不得用于非法目的或恶意攻击**
- **建议在测试环境中使用**

### 使用限制
- 需要 Root 权限或可调试的应用
- 某些加固应用可能无法正常 Hook
- 部分 Native 层加密操作无法监控
- 高频率的加密操作可能影响应用性能

### 兼容性
- 支持 Android 5.0+ (API Level 21+)
- 兼容 ARM 和 x86 架构
- 支持大部分主流 Android 设备

## 🔧 故障排除

### 常见问题

1. **Hook 失败**
   ```
   Error: Java class not found
   ```
   - 检查目标应用是否使用了相应的加密算法
   - 确认 Frida 版本兼容性
   - 尝试使用不同的 Hook 时机

2. **权限不足**
   ```
   Error: Unable to access process
   ```
   - 确保设备已 Root 或应用可调试
   - 检查 SELinux 策略
   - 尝试使用 `frida-server` 提权

3. **数据格式错误**
   ```
   Error: Cannot convert byte array
   ```
   - 检查数据类型判断逻辑
   - 更新 `FormatUtils.isByteArray` 方法
   - 添加异常处理机制

## 👨‍💻 作者信息

```
 █████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗ ██████╗ 
██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
███████║██║   ██║   ██║   ███████║██║   ██║██████╔╝
██╔══██║██║   ██║   ██║   ██╔══██║██║   ██║██╔══██╗
██║  ██║╚██████╔╝   ██║   ██║  ██║╚██████╔╝██║  ██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

**作者**: Liao  
**联系方式**: liao529786580 (微信)  

---

⭐ 如果这个项目对你有帮助，请给个 Star！

🐛 发现问题？请提交 Issue

💡 有新想法？欢迎提交 Pull Request
