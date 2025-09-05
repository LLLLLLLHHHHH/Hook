/*
 * ███████╗██████╗ ██╗██████╗  █████╗     ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
 * ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
 * █████╗  ██████╔╝██║██║  ██║███████║    ███████║██║   ██║██║   ██║█████╔╝ 
 * ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║    ██╔══██║██║   ██║██║   ██║██╔═██╗ 
 * ██║     ██║  ██║██║██████╔╝██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
 * ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * 📱 Android 加密算法 Hook 框架 - Frida Cryptography Monitoring System
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * 🎯 项目描述：
 *    一个功能强大的 Frida Hook 框架，专门用于监控和分析 Android 应用中的
 *    各种加密算法操作，包括对称加密、非对称加密、哈希算法和编码操作。
 * 
 * 🔧 主要功能：
 *    • 对称加密监控：AES、DES、3DES、RC4、ChaCha20
 *    • 非对称加密监控：RSA 加密/解密/签名/验签
 *    • 哈希算法监控：MD5、SHA系列、SHA-3、HMAC、CRC32
 *    • 编码算法监控：Base64、Base32、Hex、URL、HTML、Unicode
 *    • 密钥生成和管理：密钥规格、密钥工厂、参数规格
 *    • 多格式输出：支持 JSON、十六进制、Base64、字符串等格式
 *    • 调用堆栈跟踪：详细的方法调用链分析
 *    • 实时日志系统：可配置的日志级别和彩色输出
 * 
 * 🏗️ 架构设计：
 *    • 模块化设计：每个算法独立的 Hook 类
 *    • 配置驱动：通过 CONFIG 对象统一管理所有开关
 *    • 继承体系：BaseHook 基类提供通用功能
 *    • 工具类库：Logger、HookUtils、FormatUtils 提供支持
 *    • 数据格式化：多种编码格式的自动转换和展示
 * 
 * 📋 使用方法：
 *    1. 修改 CONFIG 对象中的开关配置
 *    2. 使用 Frida 注入到目标 Android 应用
 *    3. 观察控制台输出的加密操作日志
 *    4. 分析加密算法的输入输出数据
 * 
 * ⚠️  注意事项：
 *    • 仅用于安全研究和合法的逆向分析
 *    • 请遵守相关法律法规和道德准则
 *    • 建议在测试环境中使用
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  █████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗ ██████╗
 * ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
 * ███████║██║   ██║   ██║   ███████║██║   ██║██████╔╝
 * ██╔══██║██║   ██║   ██║   ██╔══██║██║   ██║██╔══██╗
 * ██║  ██║╚██████╔╝   ██║   ██║  ██║╚██████╔╝██║  ██║
 * ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
 *
 * 👨‍💻 Author: Liao
 * 📧 Contact（VX）: liao529786580
 * 📅 Created: 2025/08
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗
 * ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝
 * ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗
 * ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║
 * ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝
 *  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝
 *
 * 全局配置对象 - 控制 Hook 系统的各种行为和输出格式
 * 包含日志配置、Hook 开关、输出格式等核心设置
 */
const CONFIG = {
  /*
   * ██╗      ██████╗  ██████╗  ██████╗ ███████╗██████╗
   * ██║     ██╔═══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗
   * ██║     ██║   ██║██║  ███╗██║  ███╗█████╗  ██████╔╝
   * ██║     ██║   ██║██║   ██║██║   ██║██╔══╝  ██╔══██╗
   * ███████╗╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██║
   * ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
   */
  // 日志系统配置
  // 控制日志输出的级别、格式和样式
  logger: {
    // ═══════════════════════════════════════════════════════════════════════════════
    // 日志级别和显示控制 - Log Level and Display Control
    // ═══════════════════════════════════════════════════════════════════════════════
    logLevel: 'DEBUG',             // 日志级别：DEBUG/INFO/WARN/ERROR
    enableColors: true,            // 是否启用彩色输出（终端颜色支持）
    showTimestamp: true,           // 是否显示时间戳（记录操作时间）
    showLevel: true,               // 是否显示日志级别标识
    timeFormat: 'YYYY-MM-DD HH:mm:ss', // 时间格式化模板
  },

  /*
   * ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
   * ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
   * ███████║██║   ██║██║   ██║█████╔╝
   * ██╔══██║██║   ██║██║   ██║██╔═██╗
   * ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
   * ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
   */
  // Hook 功能配置
  // 控制各种加密算法和编码的 Hook 开关
  hook: {
    // ═══════════════════════════════════════════════════════════════════════════════
    // 调试和跟踪配置 - Debug and Tracing Configuration
    // ═══════════════════════════════════════════════════════════════════════════════
    showStack: true,               // 显示调用堆栈（用于调试和分析调用链）

    // 对称加密 Hook 开关
    /*
     * ███████╗██╗   ██╗███╗   ███╗███╗   ███╗███████╗████████╗██████╗ ██╗ ██████╗
     * ██╔════╝╚██╗ ██╔╝████╗ ████║████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝
     * ███████╗ ╚████╔╝ ██╔████╔██║██╔████╔██║█████╗     ██║   ██████╔╝██║██║
     * ╚════██║  ╚██╔╝  ██║╚██╔╝██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗██║██║
     * ███████║   ██║   ██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║╚██████╗
     * ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝
     */
    // 对称加密算法 Hook 开关配置
    // 监控各种对称加密算法的加密和解密操作
    symmetricCrypto: {
      // ═══════════════════════════════════════════════════════════════════════════════
      // 高级加密标准 - Advanced Encryption Standard
      // ═══════════════════════════════════════════════════════════════════════════════
      aes: true,           // AES 加密算法 (128/192/256位密钥，当前最广泛使用的对称加密标准)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 数据加密标准 - Data Encryption Standard
      // ═══════════════════════════════════════════════════════════════════════════════
      des: true,           // DES 加密算法 (56位密钥，已不安全，仅用于兼容性)
      '3des': true,        // 3DES 加密算法 (168位有效密钥，DES的增强版本)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 流加密算法 - Stream Ciphers
      // ═══════════════════════════════════════════════════════════════════════════════
      rc4: true,           // RC4 流加密算法 (可变长度密钥，已不安全，仅用于兼容性)
      chacha: true,        // ChaCha20 流加密算法 (256位密钥，现代高性能流加密算法)
    },

    /*
     *  █████╗ ███████╗██╗   ██╗███╗   ███╗███╗   ███╗███████╗████████╗██████╗ ██╗ ██████╗
     * ██╔══██╗██╔════╝╚██╗ ██╔╝████╗ ████║████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝
     * ███████║███████╗ ╚████╔╝ ██╔████╔██║██╔████╔██║█████╗     ██║   ██████╔╝██║██║
     * ██╔══██║╚════██║  ╚██╔╝  ██║╚██╔╝██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗██║██║
     * ██║  ██║███████║   ██║   ██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║╚██████╗
     * ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝
     */
    // 非对称加密算法 Hook 开关配置
    // 监控公钥加密算法的加密、解密、签名和验签操作
    asymmetricCrypto: {
      // ═══════════════════════════════════════════════════════════════════════════════
      // RSA 算法 - Rivest-Shamir-Adleman
      // ═══════════════════════════════════════════════════════════════════════════════
      rsa: true,           // RSA 公钥加密算法 (支持加密/解密/数字签名/验签，密钥长度1024-4096位)
    },

    /*
     * ███████╗███╗   ██╗ ██████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗
     * ██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗██║████╗  ██║██╔════╝
     * █████╗  ██╔██╗ ██║██║     ██║   ██║██║  ██║██║██╔██╗ ██║██║  ███╗
     * ██╔══╝  ██║╚██╗██║██║     ██║   ██║██║  ██║██║██║╚██╗██║██║   ██║
     * ███████╗██║ ╚████║╚██████╗╚██████╔╝██████╔╝██║██║ ╚████║╚██████╔╝
     * ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝
     */
    // 编码算法 Hook 开关配置
    // 监控各种数据编码和解码操作
    encoding: {
      // ═══════════════════════════════════════════════════════════════════════════════
      // Base 编码系列 - Base Encoding Family
      // ═══════════════════════════════════════════════════════════════════════════════
      base64: true,        // Base64 编码 (64个字符集，常用于数据传输和存储)
      base32: true,        // Base32 编码 (32个字符集，对大小写不敏感)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 进制转换编码 - Radix Conversion Encoding
      // ═══════════════════════════════════════════════════════════════════════════════
      hex: true,           // 十六进制编码 (0-9, A-F字符集，常用于二进制数据表示)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 网络传输编码 - Network Transfer Encoding
      // ═══════════════════════════════════════════════════════════════════════════════
      url: true,           // URL 编码 (百分号编码，用于URL中的特殊字符处理)
      html: true,          // HTML 实体编码 (HTML特殊字符转义，防止XSS攻击)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 字符集编码 - Character Set Encoding
      // ═══════════════════════════════════════════════════════════════════════════════
      unicode: true,       // Unicode 编码 (万国码，支持全球所有字符)
      utf8: true,          // UTF-8 编码 (Unicode的变长编码实现，互联网标准)
      ascii: true,         // ASCII 编码 (7位字符编码，基础字符集)
    },

    /*
     * ██╗  ██╗ █████╗ ███████╗██╗  ██╗    ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗███████╗
     * ██║  ██║██╔══██╗██╔════╝██║  ██║    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝██╔════╝
     * ███████║███████║███████╗███████║    ███████║██║   ██║██║   ██║█████╔╝ ███████╗
     * ██╔══██║██╔══██║╚════██║██╔══██║    ██╔══██║██║   ██║██║   ██║██╔═██╗ ╚════██║
     * ██║  ██║██║  ██║███████║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗███████║
     * ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝
     */
    // 哈希算法 Hook 开关配置
    // 支持各种常见的哈希算法和消息认证码算法的监控
    hash: {
      // ═══════════════════════════════════════════════════════════════════════════════
      // 经典哈希算法 - Classic Hash Algorithms
      // ═══════════════════════════════════════════════════════════════════════════════
      md5: true,           // MD5 哈希算法 (128位输出，已不安全，仅用于兼容性)
      sha1: true,          // SHA-1 哈希算法 (160位输出，已不安全，仅用于兼容性)

      // ═══════════════════════════════════════════════════════════════════════════════
      // SHA-2 系列算法 - SHA-2 Family
      // ═══════════════════════════════════════════════════════════════════════════════
      sha256: true,        // SHA-256 哈希算法 (256位输出，广泛使用，安全性高)
      sha384: true,        // SHA-384 哈希算法 (384位输出，SHA-512的截断版本)
      sha512: true,        // SHA-512 哈希算法 (512位输出，高安全性要求场景)

      // ═══════════════════════════════════════════════════════════════════════════════
      // SHA-3 系列算法 - SHA-3 Family (Keccak)
      // ═══════════════════════════════════════════════════════════════════════════════
      'sha3-256': true,    // SHA3-256 哈希算法 (256位输出，基于Keccak算法)
      'sha3-384': true,    // SHA3-384 哈希算法 (384位输出，基于Keccak算法)
      'sha3-512': true,    // SHA3-512 哈希算法 (512位输出，基于Keccak算法)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 消息认证码算法 - Message Authentication Code
      // ═══════════════════════════════════════════════════════════════════════════════
      hmac: true,          // HMAC 系列算法 (基于哈希的消息认证码，用于验证数据完整性和真实性)

      // ═══════════════════════════════════════════════════════════════════════════════
      // 校验算法 - Checksum Algorithms
      // ═══════════════════════════════════════════════════════════════════════════════
      crc32: true,         // CRC32 循环冗余校验 (32位校验码，用于错误检测)
    }
  },

  /*
   *  ██████╗ ██╗   ██╗████████╗██████╗ ██╗   ██╗████████╗
   * ██╔═══██╗██║   ██║╚══██╔══╝██╔══██╗██║   ██║╚══██╔══╝
   * ██║   ██║██║   ██║   ██║   ██████╔╝██║   ██║   ██║
   * ██║   ██║██║   ██║   ██║   ██╔═══╝ ██║   ██║   ██║
   * ╚██████╔╝╚██████╔╝   ██║   ██║     ╚██████╔╝   ██║
   *  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝      ╚═════╝    ╚═╝
   */
  // 输出格式配置
  // 控制 Hook 数据的输出格式和显示内容
  output: {
    // ═══════════════════════════════════════════════════════════════════════════════
    // 输出格式控制 - Output Format Control
    // ═══════════════════════════════════════════════════════════════════════════════
    enableJsonFormat: true,    // 是否启用JSON格式化输出（结构化数据展示）
    showRawFormat: false,      // 是否显示原始raw格式（字节数组的原始表示）

    // ═══════════════════════════════════════════════════════════════════════════════
    // 数据编码格式配置 - Data Encoding Format Configuration
    // ═══════════════════════════════════════════════════════════════════════════════
    enabledFormats: {
      hex: true,               // 十六进制格式 (0-9, A-F字符表示)
      base64: true,            // Base64 编码格式 (64个字符集编码)
      str: true,               // 字符串格式 (直接字符串表示)
      ascii: true,             // ASCII 格式 (7位字符编码)
      utf8: true,              // UTF-8 格式 (Unicode变长编码)
      raw: true,               // 原始字节数组格式 (数值数组表示)
    },

    // ═══════════════════════════════════════════════════════════════════════════════
    // 输出字段控制 - Output Field Control
    // ═══════════════════════════════════════════════════════════════════════════════
    fields: {
      algorithm: true,         // 显示算法名称 (加密/哈希算法标识)
      input: true,             // 显示输入数据 (原始输入内容)
      result: true,            // 显示结果数据 (处理后的输出内容)
      timestamp: false,        // 显示时间戳 (操作执行时间)
      metadata: true,          // 显示元数据 (数据长度、密钥信息等)
    }
  }
};


/*
 * ██╗      ██████╗  ██████╗  ██████╗ ███████╗██████╗
 * ██║     ██╔═══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗
 * ██║     ██║   ██║██║  ███╗██║  ███╗█████╗  ██████╔╝
 * ██║     ██║   ██║██║   ██║██║   ██║██╔══╝  ██╔══██╗
 * ███████╗╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██║
 * ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
 *
 * 日志管理类 - 提供统一的日志输出和格式化功能
 * 支持多级别日志、颜色输出、时间戳等特性
 */
class Logger {
  // 日志级别数值，便于阈值判断（数值越大级别越高）
  static LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };

  // 颜色码（ANSI），Windows 新版终端和 PowerShell 默认支持
  static COLORS = {
    reset: '\x1b[0m', bright: '\x1b[1m', dim: '\x1b[2m',
    red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m'
  };

  /** 配置日志参数（可部分覆盖） */
  static configure(options = {}) {
    CONFIG.logger = { ...CONFIG.logger, ...options };
  }

  /** 设置日志级别（字符串：DEBUG/INFO/WARN/ERROR） */
  static setLevel(level) { CONFIG.logger.logLevel = (level || '').toUpperCase(); }

  /** 启用或关闭颜色 */
  static enableColors(enabled) { CONFIG.logger.enableColors = !!enabled; }

  /** 构造时间字符串 */
  static formatDate(d = new Date()) {
    // 读取全局配置中的时间格式，默认支持 YYYY MM DD HH mm ss SSS 这些占位符
    const fmt = (CONFIG && CONFIG.logger && CONFIG.logger.timeFormat) ? CONFIG.logger.timeFormat : 'YYYY-MM-DD HH:mm:ss.SSS';

    const pad = (n, w = 2) => String(n).padStart(w, '0');
    const yyyy = d.getFullYear();
    const MM = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const HH = pad(d.getHours());
    const mm = pad(d.getMinutes());
    const ss = pad(d.getSeconds());
    const SSS = pad(d.getMilliseconds(), 3);

    // 根据格式占位符替换生成输出
    return fmt
      .replace(/YYYY/g, String(yyyy))
      .replace(/MM/g, MM)
      .replace(/DD/g, dd)
      .replace(/HH/g, HH)
      .replace(/mm/g, mm)
      .replace(/ss/g, ss)
      .replace(/SSS/g, SSS);
  }

  /** 核心输出方法 */
  static log(level, message, options = {}) {
    const { enableColors, showTimestamp, showLevel } = CONFIG.logger;
    const upper = (level || '').toUpperCase();
    const threshold = this.LEVELS[(CONFIG.logger.logLevel || 'INFO').toUpperCase()] ?? this.LEVELS.INFO;
    const current = this.LEVELS[upper] ?? this.LEVELS.INFO;
    if (current < threshold) return; // 低于阈值则不输出

    // 颜色选择
    const { reset, bright, cyan, green, yellow, red } = this.COLORS;
    const levelColor = upper === 'DEBUG' ? cyan : upper === 'INFO' ? green : upper === 'WARN' ? yellow : red;

    // 头部：时间 + 级别
    const timeStr = showTimestamp ? this.formatDate() : '';
    const levelStr = showLevel ? upper : '';
    const headParts = [];
    if (timeStr) headParts.push(timeStr);
    if (levelStr) headParts.push(levelStr);
    const head = headParts.length ? `[${headParts.join(' ')}]` : '';

    // 消息字符串
    const msg = typeof message === 'string' ? message : JSON.stringify(message, null, 2);

    // 可选标签
    const tag = options.tag ? `[${options.tag}] ` : '';

    // 拼接完整输出
    let line = `${head} ${tag}${msg}`.trim();
    if (enableColors) line = `${levelColor}${bright}${line}${reset}`;

    // 选择对应控制台方法
    const printer = upper === 'ERROR' ? console.error : upper === 'WARN' ? console.warn : upper === 'DEBUG' ? (console.debug || console.log) : console.log;
    printer(line);

    // 附带错误与数据对象输出
    if (options.error instanceof Error) {
      const stack = options.error.stack || options.error.message || String(options.error);
      const stackLine = enableColors ? `${levelColor}Stack: ${stack}${reset}` : `Stack: ${stack}`;
      printer(stackLine);
    }
    if (options.data !== undefined) {
      try {
        const dataStr = typeof options.data === 'string' ? options.data : JSON.stringify(options.data, null, 2);
        printer(enableColors ? `${this.COLORS.blue}${dataStr}${this.COLORS.reset}` : dataStr);
      } catch (_) {
        printer(String(options.data));
      }
    }
  }

  // 便捷方法
  static debug(message, options = {}) { this.log('DEBUG', message, options); }
  static info(message, options = {}) { this.log('INFO', message, options); }
  static warn(message, options = {}) { this.log('WARN', message, options); }
  static error(message, options = {}) { this.log('ERROR', message, options); }

  /** 分隔线，便于在控制台中分割块内容 */
  static separator(title = '分割线', char = '─', width = 80) {
    const { enableColors } = CONFIG.logger;
    const line = char.repeat(Math.max(1, width));
    if (!title) {
      console.log(enableColors ? `${this.COLORS.cyan}${line}${this.COLORS.reset}` : line);
      return;
    }
    const text = ` ${title} `;
    const left = Math.max(2, Math.floor((width - text.length) / 2));
    const right = Math.max(2, width - text.length - left);
    const out = `${char.repeat(left)}${text}${char.repeat(right)}`;
    console.log(enableColors ? `${this.COLORS.cyan}${out}${this.COLORS.reset}` : out);
  }
}


/*
 * ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗████████╗██╗██╗     ███████╗
 * ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║╚══██╔══╝██║██║     ██╔════╝
 * ███████║██║   ██║██║   ██║█████╔╝ ██║   ██║   ██║   ██║██║     ███████╗
 * ██╔══██║██║   ██║██║   ██║██╔═██╗ ██║   ██║   ██║   ██║██║     ╚════██║
 * ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝   ██║   ██║███████╗███████║
 * ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚══════╝╚══════╝
 *
 * Hook 工具类 - 提供 Hook 操作的通用工具函数
 * 包含堆栈捕获、数据转换、字符串处理等实用功能
 */
class HookUtils {
  /**
   * 捕获并打印 Java 层调用堆栈（完整输出，不做任何截断）
   * @param {string} tag 打印的标签（例如 'Cipher.doFinal'）
   */
  static captureStack(tag = 'Hook') {
    if (!CONFIG?.hook?.showStack) return; // 未开启则不打印

    try {
      const Exception = Java.use('java.lang.Exception');
      const ins = Exception.$new('Exception');
      const straces = ins.getStackTrace();

      if (!straces || !straces.length) {
        Exception.$dispose();
        return;
      }

      const lines = [];
      for (let i = 0; i < straces.length; i++) {
        // toString() 展示 "com.xxx.Class.method(File.java:Line)" 格式
        lines.push(`   ${straces[i].toString()}`);
      }

      Exception.$dispose();

      const title = `Hook 调用堆栈 [Java]${tag ? ` @ ${tag}` : ''}`;
      const stack = lines.join('\n');

      // 一次性输出，避免多行日志被其它并发日志打断
      Logger.debug(`${title}\n${stack}`, { tag: 'HookStack' });
    } catch (e) {
      Logger.error(`Java 堆栈获取失败: ${e && e.message ? e.message : String(e)}`, { tag: 'HookStack' });
    }
  }

  /**
   * 将字节数组转换为十六进制字符串
   * @param {any} byteArray Java字节数组
   * @returns {string} 十六进制字符串
   */
  static bytesToHex(byteArray) {
    if (!byteArray) return '';
    try {
      const bytes = Java.array('byte', byteArray);
      let hex = '';
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i] & 0xFF;
        hex += byte.toString(16).padStart(2, '0');
      }
      return hex;
    } catch (e) {
      return String(byteArray);
    }
  }

  /**
   * 将字符串转换为十六进制字符串
   * @param {string} str 输入字符串
   * @returns {string} 十六进制字符串
   */
  static stringToHex(str) {
    if (!str) return '';
    try {
      return str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    } catch (e) {
      return String(str);
    }
  }
}



/*
 * ███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗   ██╗████████╗██╗██╗     ███████╗
 * ██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║   ██║╚══██╔══╝██║██║     ██╔════╝
 * █████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║   ██║   ██║   ██║██║     ███████╗
 * ██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║   ██║   ██║   ██║██║     ╚════██║
 * ██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ╚██████╔╝   ██║   ██║███████╗███████║
 * ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝    ╚═╝   ╚═╝╚══════╝╚══════╝
 *
 * 格式化工具类 - 提供数据格式转换和编码功能
 * 支持字节数组、Base64、UTF-8、ASCII、PEM 等多种格式转换
 */
class FormatUtils {
  /**
   * 判断数据是否为字节数组（兼容 Frida Java byte[]、原生 Array、Uint8Array 等）
   * @param {any} data 任意数据
   * @returns {boolean} 是否为字节数组
   */
  static isByteArray(data) {
    try {
      if (data === null || data === undefined) return false;

      // 显式判断常见类型
      if (Array.isArray(data)) return true;

      const ctorName = data && data.constructor ? data.constructor.name : '';
      if (ctorName === 'Uint8Array' || ctorName === 'Int8Array') return true;

      // Frida Java byte[]: 有 length，可下标访问，且可能带有$className为"[B"
      if (typeof data.length === 'number' && data.length >= 0) {
        // 检查$className为"[B"（Java字节数组标识）
        if (data.$className === '[B') return true;

        // 检查构造函数名为"g"（Frida Java字节数组的特殊标识）
        if (ctorName === 'g') return true;

        // 空数组也按字节数组处理
        if (data.length === 0) return true;

        // 采样首元素类型为 number 也视为字节数组
        if (data.length > 0 && typeof data[0] === 'number') return true;

        // 检查是否具有字节数组的特征（可通过索引访问且值为数字）
        try {
          if (data.length > 0 && typeof data[0] !== 'undefined') {
            const firstElement = data[0];
            if (typeof firstElement === 'number' && firstElement >= -128 && firstElement <= 255) {
              return true;
            }
          }
        } catch (e) {
          // 忽略访问异常
        }
      }
    } catch (e) {
      // 忽略判定异常
    }
    return false;
  }

  /**
   * 将字节数组转换为Base64字符串（纯源码实现）
   * @param {Array} byteArray Java字节数组
   * @returns {string} Base64字符串
   */
  static bytesToBase64(byteArray) {
    if (!byteArray || !byteArray.length) return '';

    try {
      // Base64字符表
      const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      let result = '';

      // 每3个字节为一组进行编码
      for (let i = 0; i < byteArray.length; i += 3) {
        const byte1 = byteArray[i] & 0xFF;
        const byte2 = i + 1 < byteArray.length ? byteArray[i + 1] & 0xFF : 0;
        const byte3 = i + 2 < byteArray.length ? byteArray[i + 2] & 0xFF : 0;

        // 将3个字节合并为24位数字
        const combined = (byte1 << 16) | (byte2 << 8) | byte3;

        // 分割为4个6位数字
        const char1 = base64Chars[(combined >> 18) & 0x3F];
        const char2 = base64Chars[(combined >> 12) & 0x3F];
        const char3 = i + 1 < byteArray.length ? base64Chars[(combined >> 6) & 0x3F] : '=';
        const char4 = i + 2 < byteArray.length ? base64Chars[combined & 0x3F] : '=';

        result += char1 + char2 + char3 + char4;
      }

      return result;
    } catch (e) {
      Logger.warn(`Base64编码失败: ${e.message}`);
      return '';
    }
  }

  /**
   * 将字符串转换为Base64字符串（纯源码实现）
   * @param {string} str 输入字符串
   * @returns {string} Base64字符串
   */
  static stringToBase64(str) {
    if (!str) return '';

    try {
      // 将字符串转换为UTF-8字节数组
      const utf8Bytes = [];
      for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        if (charCode < 0x80) {
          utf8Bytes.push(charCode);
        } else if (charCode < 0x800) {
          utf8Bytes.push(0xC0 | (charCode >> 6));
          utf8Bytes.push(0x80 | (charCode & 0x3F));
        } else if (charCode < 0xD800 || charCode >= 0xE000) {
          utf8Bytes.push(0xE0 | (charCode >> 12));
          utf8Bytes.push(0x80 | ((charCode >> 6) & 0x3F));
          utf8Bytes.push(0x80 | (charCode & 0x3F));
        } else {
          // 处理代理对
          i++;
          const surrogate = str.charCodeAt(i);
          const codePoint = 0x10000 + (((charCode & 0x3FF) << 10) | (surrogate & 0x3FF));
          utf8Bytes.push(0xF0 | (codePoint >> 18));
          utf8Bytes.push(0x80 | ((codePoint >> 12) & 0x3F));
          utf8Bytes.push(0x80 | ((codePoint >> 6) & 0x3F));
          utf8Bytes.push(0x80 | (codePoint & 0x3F));
        }
      }

      return this.bytesToBase64(utf8Bytes);
    } catch (e) {
      Logger.warn(`字符串Base64编码失败: ${e.message}`);
      return '';
    }
  }

  /**
   * 将字节数组转换为字符串（尝试UTF-8解码）
   * @param {Array} byteArray Java字节数组
   * @returns {string} UTF-8字符串
   */
  static bytesToUtf8(byteArray) {
    if (!byteArray || !byteArray.length) return '';

    try {
      const String = Java.use('java.lang.String');
      // 返回 Java String 对象会在 JSON 序列化时显示为 "<instance: java.lang.String>"
      // 通过与空字符串拼接将其转换为原生 JS 字符串
      const jstr = String.$new(byteArray, 'UTF-8');
      return jstr ? ('' + jstr) : '';
    } catch (e) {
      // 如果Java String不可用，使用JavaScript实现
      try {
        const bytes = new Uint8Array(byteArray.length);
        for (let i = 0; i < byteArray.length; i++) {
          bytes[i] = byteArray[i] & 0xFF;
        }
        return new TextDecoder('utf-8').decode(bytes);
      } catch (e2) {
        return '';
      }
    }
  }

  /**
   * 将字节数组转换为ASCII字符串
   * @param {Array} byteArray Java字节数组
   * @returns {string} ASCII字符串
   */
  static bytesToAscii(byteArray) {
    if (!byteArray || !byteArray.length) return '';

    try {
      const chars = [];
      for (let i = 0; i < byteArray.length; i++) {
        const byte = byteArray[i] & 0xFF;
        // 只处理可打印的ASCII字符（32-126）
        if (byte >= 32 && byte <= 126) {
          chars.push(String.fromCharCode(byte));
        } else {
          chars.push('.');
        }
      }
      return chars.join('');
    } catch (e) {
      return '';
    }
  }

  /**
   * 将字节数组转换为原始格式字符串
   * @param {Array} byteArray Java字节数组
   * @returns {string} 原始格式字符串
   */
  static bytesToRaw(byteArray) {
    if (!byteArray || !byteArray.length) return '';

    try {
      const rawBytes = [];
      for (let i = 0; i < byteArray.length; i++) {
        rawBytes.push(byteArray[i]);
      }
      return rawBytes.join(',');
    } catch (e) {
      return String(byteArray);
    }
  }

  /**
   * 将字节数组转换为PEM格式字符串
   * @param {Array} keyBytes 密钥字节数组
   * @param {string} keyType 密钥类型 ('PUBLIC KEY' 或 'PRIVATE KEY')
   * @returns {string} PEM格式字符串
   */
  static bytesToPem(keyBytes, keyType = 'KEY') {
    if (!keyBytes || !keyBytes.length) return null;

    try {
      // 将字节数组转换为 Base64
      const base64 = this.bytesToBase64(keyBytes);
      if (!base64) return null;

      // 将 Base64 字符串按64字符一行分割
      const lines = [];
      for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.substring(i, i + 64));
      }

      // 组装 PEM 格式
      const pemContent = [
        `-----BEGIN ${keyType}-----`,
        ...lines,
        `-----END ${keyType}-----`
      ].join('\n');

      return pemContent;
    } catch (e) {
      Logger.warn(`PEM转换失败: ${e.message}`);
      return null;
    }
  }

  /**
   * 提取并格式化密钥信息
   * @param {Object} key Java密钥对象
   * @param {string} keyType 密钥类型描述
   * @returns {Object} 格式化的密钥信息
   */
  static extractKeyInfo(key, keyType = 'Key') {
    if (!key) return null;

    try {
      const keyInfo = {
        algorithm: key.getAlgorithm ? ('' + key.getAlgorithm()) : 'Unknown',
        format: key.getFormat ? ('' + key.getFormat()) : 'Unknown',
        type: keyType
      };

      // 尝试获取密钥编码
      try {
        const encoded = key.getEncoded ? key.getEncoded() : null;
        if (encoded && encoded.length > 0) {
          keyInfo.encoded = {
            hex: HookUtils.bytesToHex(encoded),
            base64: this.bytesToBase64(encoded),
            string: this.bytesToUtf8(encoded),
            ascii: this.bytesToAscii(encoded),
            utf8: this.bytesToUtf8(encoded),
            raw: this.bytesToRaw(encoded),
            length: encoded.length
          };

          // 只为非对称密钥生成 PEM 格式
          const algorithm = keyInfo.algorithm.toLowerCase();
          if (algorithm.includes('rsa') || algorithm.includes('ec') || algorithm.includes('dsa') || algorithm.includes('dh')) {
            // 非对称密钥才生成PEM格式
            if (keyType.toLowerCase().includes('private')) {
              keyInfo.pem = this.bytesToPem(encoded, 'PRIVATE KEY');
            } else if (keyType.toLowerCase().includes('public')) {
              keyInfo.pem = this.bytesToPem(encoded, 'PUBLIC KEY');
            } else {
              keyInfo.pem = this.bytesToPem(encoded, 'KEY');
            }
          }
          // 对称密钥（如AES、DES等）不生成PEM格式
        } else {
          keyInfo.encoded = null;
          keyInfo.pem = null;
          keyInfo.note = '密钥不可导出（可能由硬件安全模块管理）';
        }
      } catch (encodeError) {
        keyInfo.encoded = null;
        keyInfo.pem = null;
        keyInfo.encodeError = encodeError.message;
      }

      return keyInfo;
    } catch (e) {
      Logger.warn(`密钥信息提取失败: ${e.message}`);
      return {
        type: keyType,
        error: e.message
      };
    }
  }

  /**
   * 根据配置格式化数据为多种编码格式
   * @param {Array|string} data 输入数据
   * @param {string} dataType 数据类型标识
   * @returns {Object} 格式化后的数据对象
   */
  static formatMultiEncoding(data, dataType = '') {
    // 如果数据为null、undefined，返回null
    if (data === null || data === undefined) return null;

    // 如果数据是字节数组并且长度为0，返回空对象
    if (FormatUtils.isByteArray(data) && data.length === 0) {
      return {};
    }

    const result = {};
    const config = CONFIG?.output?.enabledFormats || {};

    try {
      // 字节数组分支（兼容多种实现）
      if (FormatUtils.isByteArray(data)) {
        // 原始格式
        if (config.raw) {
          result.raw = this.bytesToRaw(data);
        }

        // 十六进制格式
        if (config.hex) {
          result.hex = HookUtils.bytesToHex(data);
        }

        // Base64格式
        if (config.base64) {
          result.base64 = this.bytesToBase64(data);
        }

        // 字符串格式（UTF-8）
        if (config.str || config.utf8) {
          const utf8Str = this.bytesToUtf8(data);
          if (utf8Str) {
            if (config.str) result.str = utf8Str;
            if (config.utf8) result.utf8 = utf8Str;
          }
        }

        // ASCII格式
        if (config.ascii) {
          result.ascii = this.bytesToAscii(data);
        }
      }
      // 字符串分支
      else if (typeof data === 'string') {
        if (config.str) {
          result.str = data;
        }
        if (config.utf8) {
          result.utf8 = data;
        }
        if (config.hex) {
          result.hex = HookUtils.stringToHex(data);
        }
        if (config.base64) {
          result.base64 = this.stringToBase64(data);
        }
        if (config.ascii) {
          result.ascii = data.replace(/[^\x20-\x7E]/g, '.');
        }
        if (config.raw) {
          const codes = [];
          for (let i = 0; i < data.length; i++) codes.push(data.charCodeAt(i));
          result.raw = codes.join(',');
        }
      }

      return result;
    } catch (e) {
      Logger.warn(`数据格式化失败: ${e.message}`, { tag: 'FormatUtils' });
      return { error: e.message };
    }
  }

  /**
   * 创建JSON格式的输出对象
   * @param {string} algorithm 算法名称
   * @param {Object} input 输入数据（已格式化）
   * @param {Object} result 结果数据（已格式化）
   * @param {Object} metadata 元数据
   * @returns {Object} JSON格式的输出对象
   */
  static createJsonOutput(algorithm, input = null, result = null, metadata = {}) {
    const output = {
      algorithm: algorithm
    };

    const fields = CONFIG?.output?.fields || {};

    // 添加输入数据（即使为null也显示）
    if (fields.input) {
      output.input = input || {};
    }

    // 添加结果数据（即使为null也显示）
    if (fields.result) {
      output.result = result || {};
    }

    // 添加时间戳
    if (fields.timestamp) {
      output.timestamp = new Date().toISOString();
    }

    // 添加元数据
    if (fields.metadata && Object.keys(metadata).length > 0) {
      output.metadata = metadata;
    }

    return output;
  }
}



/*
 * ██████╗  █████╗ ███████╗███████╗██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
 * ██╔══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
 * ██████╔╝███████║███████╗█████╗  ███████║██║   ██║██║   ██║█████╔╝
 * ██╔══██╗██╔══██║╚════██║██╔══╝  ██╔══██║██║   ██║██║   ██║██╔═██╗
 * ██████╔╝██║  ██║███████║███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
 * ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
 *
 * Hook 基础类 - 所有 Hook 类的抽象基类
 * 提供通用的 Hook 功能、配置检查、数据格式化等核心方法
 */
class BaseHook {
  /**
   * 构造函数
   * @param {string} className Java类名
   * @param {string} hookName Hook名称（用于日志标识）
   * @param {string} configKey 配置键名（在CONFIG.hook中的路径）
   */
  constructor(className, hookName, configKey) {
    this.className = className;
    this.hookName = hookName;
    this.configKey = configKey;
    this.javaClass = null;
    this.isEnabled = this.checkEnabled();
  }

  /**
   * 检查当前Hook是否启用
   * @returns {boolean} 是否启用
   */
  checkEnabled() {
    if (!this.configKey) return true;

    const keys = this.configKey.split('.');
    let config = CONFIG.hook;

    for (const key of keys) {
      if (config && typeof config === 'object' && key in config) {
        config = config[key];
      } else {
        return false;
      }
    }

    return !!config;
  }

  /**
   * 初始化Java类
   * @returns {boolean} 是否成功初始化
   */
  initJavaClass() {
    if (!this.isEnabled) {
      Logger.debug(`${this.hookName} Hook 已禁用，跳过初始化`, { tag: this.hookName });
      return false;
    }

    try {
      this.javaClass = Java.use(this.className);
      Logger.info(`${this.hookName} Hook 初始化成功`, { tag: this.hookName });
      return true;
    } catch (e) {
      Logger.error(`${this.hookName} Hook 初始化失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
      return false;
    }
  }

  /**
   * Hook 方法的通用包装器
   * @param {string} methodName 方法名
   * @param {string} signature 方法签名
   * @param {Function} hookHandler Hook处理函数
   */
  hookMethod(methodName, signature, hookHandler) {
    if (!this.javaClass) {
      Logger.error(`${this.hookName} Java类未初始化，无法Hook方法: ${methodName}`, { tag: this.hookName });
      return;
    }

    try {
      const method = signature ? this.javaClass[methodName].overload(...signature) : this.javaClass[methodName];
      const hookInstance = this; // 保存Hook实例的引用

      method.implementation = function(...args) {
        const methodTag = `${hookInstance.hookName}.${methodName}`;

        try {
          // 调用自定义的Hook处理函数，并将 Java 实例(this) 作为额外参数传入，便于回调中读取 getAlgorithm/getProvider 等信息
          return hookHandler.call(hookInstance, methodTag, args, () => {
            // 原始方法调用 - this指向Java对象实例
            return method.apply(this, args);
          }, this);
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return method.apply(this, args);
        }
      };

      Logger.info(`${this.hookName}.${methodName} Hook 设置成功`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.${methodName} Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }

  /**
   * 启动Hook - 子类需要重写此方法
   */
  start() {
    throw new Error(`${this.hookName} Hook 必须实现 start() 方法`);
  }

  /**
   * 格式化输入输出数据用于日志显示
   * @param {any} data 数据
   * @param {string} type 数据类型提示
   * @returns {string|Object|null} 格式化后的字符串或对象
   */
  formatData(data, type = '') {
    // 如果数据为 null 或 undefined，返回 null
    if (data === null || data === undefined) return null;

    try {
      // 如果数据是字节数组并且长度为 0，返回空对象，便于区分“确实有输入但为空”
      if (FormatUtils.isByteArray(data) && data.length === 0) {
        return {};
      }

      const result = {};
      const config = CONFIG?.output?.enabledFormats || {};

      // 字节数组分支（兼容多种实现）
      if (FormatUtils.isByteArray(data)) {
        // 原始格式
        if (config.raw) {
          result.raw = FormatUtils.bytesToRaw(data);
        }
        // 十六进制格式
        if (config.hex) {
          result.hex = HookUtils.bytesToHex(data);
        }
        // Base64 格式
        if (config.base64) {
          result.base64 = FormatUtils.bytesToBase64(data);
        }
        // 字符串格式（UTF-8）
        if (config.str || config.utf8) {
          const utf8Str = FormatUtils.bytesToUtf8(data);
          if (utf8Str) {
            if (config.str) result.str = utf8Str;
            if (config.utf8) result.utf8 = utf8Str;
          }
        }
        // ASCII 格式
        if (config.ascii) {
          result.ascii = FormatUtils.bytesToAscii(data);
        }
      }
      // 字符串分支
      else if (typeof data === 'string') {
        if (config.str) {
          result.str = data;
        }
        if (config.utf8) {
          result.utf8 = data;
        }
        if (config.hex) {
          result.hex = HookUtils.stringToHex(data);
        }
        if (config.base64) {
          result.base64 = FormatUtils.stringToBase64(data);
        }
        if (config.ascii) {
          result.ascii = data.replace(/[^\x20-\x7E]/g, '.');
        }
        if (config.raw) {
          const codes = [];
          for (let i = 0; i < data.length; i++) codes.push(data.charCodeAt(i));
          result.raw = codes.join(',');
        }
      }

      return result;
    } catch (e) {
      // 将异常信息落日志并返回可读的降级文本
      Logger.warn(`数据格式化失败: ${e.message}`, { tag: this.hookName });
      return `${type}: ${String(data)}`;
    }
  }

  /**
   * 创建格式化的JSON输出
   * @param {string} algorithm 算法名称
   * @param {*} inputData 输入数据
   * @param {*} resultData 结果数据
   * @param {Object} metadata 元数据
   * @returns {Object} 格式化的JSON对象
   */
  createFormattedOutput(algorithm, inputData = null, resultData = null, metadata = {}) {
    try {
      const enableJsonFormat = CONFIG?.output?.enableJsonFormat;

      if (!enableJsonFormat) {
        // 如果未启用JSON格式，返回简单对象
        return {
          algorithm: algorithm,
          input: inputData ? this.formatData(inputData, 'input') : null,
          result: resultData ? this.formatData(resultData, 'result') : null
        };
      }

      // 格式化输入和结果数据（即使为null也要处理）
      const formattedInput = this.formatData(inputData, 'input');
      const formattedResult = this.formatData(resultData, 'result');

      // 创建JSON输出
      return FormatUtils.createJsonOutput(algorithm, formattedInput, formattedResult, metadata);
    } catch (e) {
      Logger.error(`创建格式化输出失败: ${e.message}`, { tag: this.hookName, error: e });
      return {
        algorithm: algorithm,
        error: e.message
      };
    }
  }
}



class HashHook extends BaseHook {
  constructor() {
    super('java.security.MessageDigest', 'HashHook', 'hash');

    // 支持的算法映射表
    this.supportedAlgorithms = {
      'MD5': 'md5',
      'SHA-1': 'sha1',
      'SHA1': 'sha1',
      'SHA-256': 'sha256',
      'SHA256': 'sha256',
      'SHA-384': 'sha384',
      'SHA384': 'sha384',
      'SHA-512': 'sha512',
      'SHA512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3256': 'sha3-256',
      'SHA3-384': 'sha3-384',
      'SHA3384': 'sha3-384',
      'SHA3-512': 'sha3-512',
      'SHA3512': 'sha3-512'
    };
  }

  /**
   * 启动 Hash Hook
   */
  start() {
    if (!this.initJavaClass()) return;

    Logger.separator('Hash Hook 启动 (MD5/SHA系列)');

    // Hook getInstance 方法
    this.hookGetInstance();

    // Hook update 方法
    this.hookUpdate();

    // Hook digest 方法
    this.hookDigest();

    Logger.info('Hash Hook 启动完成 (支持 MD5, SHA-1, SHA-256, SHA-384, SHA-512)', { tag: this.hookName });
  }

  /**
   * 检查特定算法是否启用
   * @param {string} algorithm 算法名称
   * @returns {boolean} 是否启用
   */
  isAlgorithmEnabled(algorithm) {
    const normalizedAlg = algorithm.toUpperCase().replace(/[-_]/g, '');
    const configKey = this.supportedAlgorithms[normalizedAlg];
    if (!configKey) return false;

    return CONFIG.hook.hash[configKey] === true;
  }

  /**
   * Hook MessageDigest.getInstance() 方法
   */
  hookGetInstance() {
    try {
      const hookInstance = this;

      // Hook getInstance(String algorithm) 方法
      const getInstance1 = this.javaClass.getInstance.overload('java.lang.String');
      getInstance1.implementation = function(algorithm) {
        const methodTag = `${hookInstance.hookName}.getInstance(String)`;

        try {
          // 调用原始方法
          const result = getInstance1.call(this, algorithm);

          // 检查是否为支持的哈希算法且已启用
          if (algorithm && hookInstance.isAlgorithmEnabled(algorithm.toString())) {
            Logger.info(`${methodTag} 调用`, {
              tag: hookInstance.hookName,
              data: {
                algorithm: algorithm.toString(),
                result: result ? result.toString() : 'null'
              }
            });

            // 捕获调用堆栈
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return getInstance1.call(this, algorithm);
        }
      };

      // Hook getInstance(String algorithm, String provider) 方法
      const getInstance2 = this.javaClass.getInstance.overload('java.lang.String', 'java.lang.String');
      getInstance2.implementation = function(algorithm, provider) {
        const methodTag = `${hookInstance.hookName}.getInstance(String,String)`;

        try {
          // 调用原始方法
          const result = getInstance2.call(this, algorithm, provider);

          // 检查是否为支持的哈希算法且已启用
          if (algorithm && hookInstance.isAlgorithmEnabled(algorithm.toString())) {
            Logger.info(`${methodTag} 调用`, {
              tag: hookInstance.hookName,
              data: {
                algorithm: algorithm.toString(),
                provider: provider ? provider.toString() : 'null',
                result: result ? result.toString() : 'null'
              }
            });

            // 捕获调用堆栈
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return getInstance2.call(this, algorithm, provider);
        }
      };

      // Hook getInstance(String algorithm, Provider provider) 方法
      const getInstance3 = this.javaClass.getInstance.overload('java.lang.String', 'java.security.Provider');
      getInstance3.implementation = function(algorithm, provider) {
        const methodTag = `${hookInstance.hookName}.getInstance(String,Provider)`;

        try {
          // 调用原始方法
          const result = getInstance3.call(this, algorithm, provider);

          // 检查是否为支持的哈希算法且已启用
          if (algorithm && hookInstance.isAlgorithmEnabled(algorithm.toString())) {
            Logger.info(`${methodTag} 调用`, {
              tag: hookInstance.hookName,
              data: {
                algorithm: algorithm.toString(),
                provider: provider ? provider.toString() : 'null',
                result: result ? result.toString() : 'null'
              }
            });

            // 捕获调用堆栈
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return getInstance3.call(this, algorithm, provider);
        }
      };

      Logger.info(`${this.hookName}.getInstance Hook 设置成功 (3个重载版本)`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.getInstance Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }

  /**
   * Hook MessageDigest.update() 方法
   */
  hookUpdate() {
    // update(byte[])
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall) => {
      const inputBytes = args[0];
      let algorithm = 'Hash';
      try {
        // 在Hook回调中，this指向Java对象实例，直接调用其getAlgorithm方法
        algorithm = this.getAlgorithm().toString();
      } catch (e) {
        algorithm = 'Hash';
      }

      // 创建格式化输出
      const formattedOutput = this.createFormattedOutput(algorithm, inputBytes, null, {
        method: 'update',
        inputLength: inputBytes ? inputBytes.length : 0
      });

      Logger.info(`${methodTag} 调用`, {
        tag: this.hookName,
        data: formattedOutput
      });

      // 捕获调用堆栈
      HookUtils.captureStack(methodTag);

      return originalCall();
    });

    // update(byte[], int, int)
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall) => {
      const inputBytes = args[0];
      const offset = args[1];
      const len = args[2];
      let algorithm = 'Hash';
      try {
        // 在Hook回调中，this指向Java对象实例，直接调用其getAlgorithm方法
        algorithm = this.getAlgorithm().toString();
      } catch (e) {
        algorithm = 'Hash';
      }

      // 创建格式化输出
      const formattedOutput = this.createFormattedOutput(algorithm, inputBytes, null, {
        method: 'update',
        offset: offset,
        length: len,
        inputLength: inputBytes ? inputBytes.length : 0
      });

      Logger.info(`${methodTag} 调用`, {
        tag: this.hookName,
        data: formattedOutput
      });

      // 捕获调用堆栈
      HookUtils.captureStack(methodTag);

      return originalCall();
    });

    // update(byte)
    this.hookMethod('update', ['byte'], (methodTag, args, originalCall) => {
      const inputByte = args[0];

      Logger.info(`${methodTag} 调用`, {
        tag: this.hookName,
        data: {
          input: `byte: 0x${(inputByte & 0xFF).toString(16).padStart(2, '0')}`,
          algorithm: this.getAlgorithm.call(this)
        }
      });

      return originalCall();
    });
  }

  /**
   * Hook MessageDigest.digest() 方法
   */
  hookDigest() {
    // Hook digest() 方法
    this.hookMethod('digest', [], (methodTag, args, originalCall) => {
      const result = originalCall();
      let algorithm = 'Hash';
      try {
        // 在Hook回调中，this指向Java对象实例，直接调用其getAlgorithm方法
        algorithm = this.getAlgorithm().toString();
      } catch (e) {
        algorithm = 'Hash';
      }

      // digest() 没有输入参数，但有结果
      const formattedOutput = this.createFormattedOutput(algorithm, null, result, {
        method: 'digest',
        resultLength: result ? result.length : 0
      });

      Logger.info(`${methodTag} 调用`, {
        tag: this.hookName,
        data: formattedOutput
      });

      // 捕获调用堆栈
      HookUtils.captureStack(methodTag);

      return result;
    });

    // Hook digest(byte[]) 方法
    this.hookMethod('digest', ['[B'], (methodTag, args, originalCall) => {
      const inputBytes = args[0];
      const result = originalCall();
      let algorithm = 'Hash';
      try {
        // 在Hook回调中，this指向Java对象实例，直接调用其getAlgorithm方法
        algorithm = this.getAlgorithm().toString();
      } catch (e) {
        algorithm = 'Hash';
      }

      // digest(byte[]) 既有输入又有结果
      const formattedOutput = this.createFormattedOutput(algorithm, inputBytes, result, {
        method: 'digest',
        inputLength: inputBytes ? inputBytes.length : 0,
        resultLength: result ? result.length : 0
      });

      Logger.info(`${methodTag} 调用`, {
        tag: this.hookName,
        data: formattedOutput
      });

      // 捕获调用堆栈
      HookUtils.captureStack(methodTag);

      return result;
    });

    // Hook digest(byte[], int, int) 方法
    this.hookMethod('digest', ['[B', 'int', 'int'], (methodTag, args, originalCall) => {
      const input = args[0];
      const offset = args[1];
      const len = args[2];
      const result = originalCall();
      const algorithm = this.getAlgorithm.call(this);

      // digest(byte[], int, int) 既有输入又有结果
      const formattedOutput = this.createFormattedOutput(algorithm, input, result, {
        method: 'digest',
        offset: offset,
        length: len,
        inputLength: input ? input.length : 0,
        resultLength: result ? result.length : 0
      });

      Logger.info(`${methodTag} 调用`, {
        tag: this.hookName,
        data: formattedOutput
      });

      // 捕获调用堆栈
      HookUtils.captureStack(methodTag);

      return result;
    });
  }

  /**
   * 获取当前MessageDigest实例的算法名称
   * 注意：这个方法应该在Java对象的上下文中调用
   * @returns {string} 算法名称
   */
  getAlgorithm() {
    // 这个方法不应该被直接调用，而是在Hook回调中直接获取算法
    return 'Hash';
  }
}





class RSACipherHook extends BaseHook {
  constructor() {
    super('javax.crypto.Cipher', 'RSACipher', 'asymmetricCrypto.rsa');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('RSACipher Hook 启动');
    this.hookGetInstance();
    this.hookInit();
    this.hookUpdate();
    this.hookDoFinal();
    Logger.info('RSACipher Hook 启动完成', { tag: this.hookName });
  }

  hookGetInstance() {
    try {
      const hookInstance = this;
      // getInstance(String transformation)
      const getInstance1 = this.javaClass.getInstance.overload('java.lang.String');
      getInstance1.implementation = function(transformation) {
        const methodTag = `${hookInstance.hookName}.getInstance(String)`;
        try {
          const ret = getInstance1.call(this, transformation);
          if ((transformation + '').toUpperCase().includes('RSA')) {
            Logger.info(`${methodTag} 调用`, { tag: hookInstance.hookName, data: { transformation: transformation + '', result: ret + '' } });
            HookUtils.captureStack(methodTag);
          }
          return ret;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, { tag: hookInstance.hookName, error: e });
          return getInstance1.call(this, transformation);
        }
      };

      // getInstance(String transformation, String provider)
      if (this.javaClass.getInstance.overload('java.lang.String', 'java.lang.String')) {
        const getInstance2 = this.javaClass.getInstance.overload('java.lang.String', 'java.lang.String');
        getInstance2.implementation = function(transformation, provider) {
          const methodTag = `${hookInstance.hookName}.getInstance(String,String)`;
          try {
            const ret = getInstance2.call(this, transformation, provider);
            if ((transformation + '').toUpperCase().includes('RSA')) {
              Logger.info(`${methodTag} 调用`, { tag: hookInstance.hookName, data: { transformation: transformation + '', provider: provider + '', result: ret + '' } });
              HookUtils.captureStack(methodTag);
            }
            return ret;
          } catch (e) {
            Logger.error(`${methodTag} Hook执行异常: ${e.message}`, { tag: hookInstance.hookName, error: e });
            return getInstance2.call(this, transformation, provider);
          }
        };
      }

      // getInstance(String transformation, Provider provider)
      if (this.javaClass.getInstance.overload('java.lang.String', 'java.security.Provider')) {
        const getInstance3 = this.javaClass.getInstance.overload('java.lang.String', 'java.security.Provider');
        getInstance3.implementation = function(transformation, provider) {
          const methodTag = `${hookInstance.hookName}.getInstance(String,Provider)`;
          try {
            const ret = getInstance3.call(this, transformation, provider);
            if ((transformation + '').toUpperCase().includes('RSA')) {
              Logger.info(`${methodTag} 调用`, { tag: hookInstance.hookName, data: { transformation: transformation + '', provider: provider + '', result: ret + '' } });
              HookUtils.captureStack(methodTag);
            }
            return ret;
          } catch (e) {
            Logger.error(`${methodTag} Hook执行异常: ${e.message}`, { tag: hookInstance.hookName, error: e });
            return getInstance3.call(this, transformation, provider);
          }
        };
      }

      Logger.info(`${this.hookName}.getInstance Hook 设置完成`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.getInstance Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }

  hookInit() {
    // init(int opmode, Key key)
    this.hookMethod('init', ['int', 'java.security.Key'], (methodTag, args, originalCall) => {
      const opmode = args[0];
      const key = args[1];
      const algo = key ? (key.getAlgorithm ? ('' + key.getAlgorithm()) : 'Unknown') : 'null';
      const format = key ? (key.getFormat ? ('' + key.getFormat()) : 'Unknown') : 'null';

      // 根据 key.format/algorithm 粗略判断类型（仅用于展示标签）
      const lowerAlgo = (algo || '').toLowerCase();
      const isPublic = key && (lowerAlgo.includes('rsa') && format === 'X.509');
      const isPrivate = key && (lowerAlgo.includes('rsa') && format === 'PKCS#8');
      const keyInfo = key ? FormatUtils.extractKeyInfo(key, isPrivate ? 'PrivateKey' : (isPublic ? 'PublicKey' : 'Key')) : null;

      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { opmode, keyAlgorithm: algo, keyFormat: format, keyInfo } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // init(int opmode, Key key, AlgorithmParameterSpec params)
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall) => {
      const opmode = args[0];
      const key = args[1];
      const params = args[2];

      const algo = key ? (key.getAlgorithm ? ('' + key.getAlgorithm()) : 'Unknown') : 'null';
      const format = key ? (key.getFormat ? ('' + key.getFormat()) : 'Unknown') : 'null';
      const lowerAlgo = (algo || '').toLowerCase();
      const isPublic = key && (lowerAlgo.includes('rsa') && format === 'X.509');
      const isPrivate = key && (lowerAlgo.includes('rsa') && format === 'PKCS#8');
      const keyInfo = key ? FormatUtils.extractKeyInfo(key, isPrivate ? 'PrivateKey' : (isPublic ? 'PublicKey' : 'Key')) : null;

      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { opmode, keyAlgorithm: algo, keyFormat: format, params: params + '', keyInfo } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // 其它重载根据需要可继续添加
  }

  hookUpdate() {
    // update(byte[])
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall) => {
      const input = args[0];
      const formattedOutput = this.createFormattedOutput('RSA', input, null, { method: 'update', inputLength: input ? input.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // update(byte[], int, int)
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall) => {
      const input = args[0];
      const offset = args[1];
      const len = args[2];
      const formattedOutput = this.createFormattedOutput('RSA', input, null, {
        method: 'update',
        offset: offset,
        length: len,
        inputLength: input ? input.length : 0
      });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // update(byte[], int, int, byte[])
    this.hookMethod('update', ['[B', 'int', 'int', '[B'], (methodTag, args, originalCall) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const result = originalCall(); // 返回处理的字节数
      const formattedOutput = this.createFormattedOutput('RSA', input, null, {
        method: 'update(output)',
        inputOffset: inputOffset,
        inputLength: inputLen,
        outputBufferLength: output ? output.length : 0,
        processedBytes: result || 0
      });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });

    // update(byte[], int, int, byte[], int)
    this.hookMethod('update', ['[B', 'int', 'int', '[B', 'int'], (methodTag, args, originalCall) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const outputOffset = args[4];
      const result = originalCall(); // 返回处理的字节数
      const formattedOutput = this.createFormattedOutput('RSA', input, null, {
        method: 'update(output,offset)',
        inputOffset: inputOffset,
        inputLength: inputLen,
        outputBufferLength: output ? output.length : 0,
        outputOffset: outputOffset,
        processedBytes: result || 0
      });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });

    // update(java.nio.ByteBuffer, java.nio.ByteBuffer)
    this.hookMethod('update', ['java.nio.ByteBuffer', 'java.nio.ByteBuffer'], (methodTag, args, originalCall) => {
      const inputBB = args[0];
      const outputBB = args[1];
      const meta = { method: 'update(ByteBuffer,ByteBuffer)' };
      let input = null;
      try {
        if (inputBB) {
          if (inputBB.position) meta.inputPosition = inputBB.position();
          if (inputBB.limit) meta.inputLimit = inputBB.limit();
          if (inputBB.remaining) meta.inputRemaining = inputBB.remaining();
          if (inputBB.capacity) meta.inputCapacity = inputBB.capacity();
          try {
            if (inputBB.hasArray && inputBB.hasArray()) {
              input = inputBB.array();
              meta.inputBackingArray = true;
            } else {
              meta.inputBackingArray = false;
            }
          } catch (e) {
            meta.note = '无法直接获取输入ByteBuffer底层数组';
          }
        }
        if (outputBB) {
          if (outputBB.position) meta.outputPosition = outputBB.position();
          if (outputBB.limit) meta.outputLimit = outputBB.limit();
          if (outputBB.remaining) meta.outputRemaining = outputBB.remaining();
          if (outputBB.capacity) meta.outputCapacity = outputBB.capacity();
        }
      } catch (e) {
        Logger.warn(`${methodTag} 读取 ByteBuffer 元数据异常: ${e}`, { tag: this.hookName });
      }
      const result = originalCall(); // 返回处理的字节数
      meta.processedBytes = result || 0;
      const formattedOutput = this.createFormattedOutput('RSA', input, null, meta);
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });
  }

  hookDoFinal() {
    // doFinal()
    this.hookMethod('doFinal', [], (methodTag, args, originalCall) => {
      const result = originalCall();
      const formattedOutput = this.createFormattedOutput('RSA', null, result, { method: 'doFinal', resultLength: result ? result.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });

    // doFinal(byte[] input)
    this.hookMethod('doFinal', ['[B'], (methodTag, args, originalCall) => {
      const input = args[0];
      const result = originalCall();
      const formattedOutput = this.createFormattedOutput('RSA', input, result, { method: 'doFinal', inputLength: input ? input.length : 0, resultLength: result ? result.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });

    // doFinal(byte[] input, int offset, int len)
    this.hookMethod('doFinal', ['[B', 'int', 'int'], (methodTag, args, originalCall) => {
      const input = args[0];
      const offset = args[1];
      const len = args[2];
      const result = originalCall();
      const formattedOutput = this.createFormattedOutput('RSA', input, result, { method: 'doFinal', offset, length: len, inputLength: input ? input.length : 0, resultLength: result ? result.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });
  }
}

class RSASignatureHook extends BaseHook {
  constructor() {
    super('java.security.Signature', 'RSASignature', 'asymmetricCrypto.rsa');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('RSASignature Hook 启动');
    this.hookGetInstance();
    this.hookInitSignVerify();
    this.hookUpdate();
    this.hookSignVerify();
    Logger.info('RSASignature Hook 启动完成', { tag: this.hookName });
  }

  hookGetInstance() {
    try {
      const hookInstance = this;
      const getInstance1 = this.javaClass.getInstance.overload('java.lang.String');
      getInstance1.implementation = function(algorithm) {
        const methodTag = `${hookInstance.hookName}.getInstance(String)`;
        try {
          const ret = getInstance1.call(this, algorithm);
          if ((algorithm + '').toUpperCase().includes('RSA')) {
            // 尝试获取 Provider 信息，虽然此时 Signature 实例还未初始化，但也作为参考
            let provider = null;
            try {
              const p = ret && ret.getProvider ? ret.getProvider() : null;
              if (p) {
                provider = {
                  name: '' + p.getName(),
                  info: '' + p.getInfo(),
                  className: '' + p.getClass().getName()
                };
              }
            } catch (e) {}

            Logger.info(`${methodTag} 调用`, { tag: hookInstance.hookName, data: { algorithm: algorithm + '', provider, result: ret + '' } });
            HookUtils.captureStack(methodTag);
          }
          return ret;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, { tag: hookInstance.hookName, error: e });
          return getInstance1.call(this, algorithm);
        }
      };
    } catch (e) {
      Logger.error(`${this.hookName}.getInstance Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }

  hookInitSignVerify() {
    // initSign(PrivateKey)
    this.hookMethod('initSign', ['java.security.PrivateKey'], (methodTag, args, originalCall, javaThis) => {
      const key = args[0];
      const algo = key ? (key.getAlgorithm ? ('' + key.getAlgorithm()) : 'Unknown') : 'null';
      const format = key ? (key.getFormat ? ('' + key.getFormat()) : 'Unknown') : 'null';
      const keyInfo = key ? FormatUtils.extractKeyInfo(key, 'PrivateKey') : null;

      // 读取 Signature 对象的算法与提供者信息
      const signatureAlgorithm = (javaThis && javaThis.getAlgorithm) ? ('' + javaThis.getAlgorithm()) : null;
      let provider = null;
      try {
        const p = (javaThis && javaThis.getProvider) ? javaThis.getProvider() : null;
        if (p) {
          provider = {
            name: '' + p.getName(),
            info: '' + p.getInfo(),
            className: '' + p.getClass().getName()
          };
        }
      } catch (e) {}

      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { signatureAlgorithm, provider, keyAlgorithm: algo, keyFormat: format, keyInfo } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // initVerify(PublicKey)
    this.hookMethod('initVerify', ['java.security.PublicKey'], (methodTag, args, originalCall, javaThis) => {
      const key = args[0];
      const algo = key ? (key.getAlgorithm ? ('' + key.getAlgorithm()) : 'Unknown') : 'null';
      const format = key ? (key.getFormat ? ('' + key.getFormat()) : 'Unknown') : 'null';
      const keyInfo = key ? FormatUtils.extractKeyInfo(key, 'PublicKey') : null;

      // 读取 Signature 对象的算法与提供者信息
      const signatureAlgorithm = (javaThis && javaThis.getAlgorithm) ? ('' + javaThis.getAlgorithm()) : null;
      let provider = null;
      try {
        const p = (javaThis && javaThis.getProvider) ? javaThis.getProvider() : null;
        if (p) {
          provider = {
            name: '' + p.getName(),
            info: '' + p.getInfo(),
            className: '' + p.getClass().getName()
          };
        }
      } catch (e) {}

      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { signatureAlgorithm, provider, keyAlgorithm: algo, keyFormat: format, keyInfo } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });
  }

  hookUpdate() {
    // update(byte[])
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall) => {
      const input = args[0];
      const formattedOutput = this.createFormattedOutput('RSA', input, null, { method: 'update', inputLength: input ? input.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // update(byte[], int, int)
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall) => {
      const input = args[0];
      const offset = args[1];
      const len = args[2];
      const formattedOutput = this.createFormattedOutput('RSA', input, null, { method: 'update', offset, length: len, inputLength: input ? input.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // update(byte)
    this.hookMethod('update', ['byte'], (methodTag, args, originalCall) => {
      const oneByte = args[0];
      const metadata = { method: 'update(byte)', value: `0x${(oneByte & 0xFF).toString(16).padStart(2, '0')}` };
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { algorithm: 'RSA', input: metadata.value, metadata } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // update(java.nio.ByteBuffer)
    this.hookMethod('update', ['java.nio.ByteBuffer'], (methodTag, args, originalCall) => {
      const bb = args[0];
      const meta = { method: 'update(ByteBuffer)' };
      let input = null;
      try {
        if (bb) {
          if (bb.position) meta.position = bb.position();
          if (bb.limit) meta.limit = bb.limit();
          if (bb.remaining) meta.remaining = bb.remaining();
          if (bb.capacity) meta.capacity = bb.capacity();
          try {
            if (bb.hasArray && bb.hasArray()) {
              input = bb.array();
              meta.backingArray = true;
            } else {
              meta.backingArray = false;
            }
          } catch (e) {
            meta.note = '无法直接获取底层数组';
          }
        }
      } catch (e) {
        Logger.warn(`${methodTag} 读取 ByteBuffer 元数据异常: ${e}`, { tag: this.hookName });
      }
      const formattedOutput = this.createFormattedOutput('RSA', input, null, meta);
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });
  }

  hookSignVerify() {
    // sign()
    this.hookMethod('sign', [], (methodTag, args, originalCall) => {
      const result = originalCall();
      const formattedOutput = this.createFormattedOutput('RSA', null, result, { method: 'sign', resultLength: result ? result.length : 0 });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return result;
    });

    // sign(byte[] outbuf, int offset, int len)
    if (this.javaClass.sign.overload('[B', 'int', 'int')) {
      this.hookMethod('sign', ['[B', 'int', 'int'], (methodTag, args, originalCall) => {
        const outbuf = args[0];
        const result = originalCall();
        const formattedOutput = this.createFormattedOutput('RSA', null, outbuf, { method: 'sign(outbuf)', resultLength: outbuf ? outbuf.length : 0 });
        Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
        HookUtils.captureStack(methodTag);
        return result;
      });
    }

    // verify(byte[] sigBytes)
    this.hookMethod('verify', ['[B'], (methodTag, args, originalCall) => {
      const sig = args[0];
      const ret = originalCall();
      const formattedOutput = this.createFormattedOutput('RSA', sig, null, { method: 'verify', inputLength: sig ? sig.length : 0, verifyResult: !!ret });
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: formattedOutput });
      HookUtils.captureStack(methodTag);
      return ret;
    });
  }
}

class RSAKeyPairHook extends BaseHook {
  constructor() {
    super('java.security.KeyPairGenerator', 'RSAKeyPair', 'asymmetricCrypto.rsa');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('RSAKeyPair Hook 启动');
    this.hookGetInstance();
    this.hookInitAndGen();
    Logger.info('RSAKeyPair Hook 启动完成', { tag: this.hookName });
  }

  hookGetInstance() {
    try {
      const hookInstance = this;
      const getInstance1 = this.javaClass.getInstance.overload('java.lang.String');
      getInstance1.implementation = function(algorithm) {
        const methodTag = `${hookInstance.hookName}.getInstance(String)`;
        try {
          const ret = getInstance1.call(this, algorithm);
          if ((algorithm + '').toUpperCase().includes('RSA')) {
            Logger.info(`${methodTag} 调用`, { tag: hookInstance.hookName, data: { algorithm: algorithm + '', result: ret + '' } });
            HookUtils.captureStack(methodTag);
          }
          return ret;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, { tag: hookInstance.hookName, error: e });
          return getInstance1.call(this, algorithm);
        }
      };
    } catch (e) {
      Logger.error(`${this.hookName}.getInstance Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }

  hookInitAndGen() {
    // initialize(int keysize)
    this.hookMethod('initialize', ['int'], (methodTag, args, originalCall) => {
      const keysize = args[0];
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { keysize } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // initialize(int keysize, SecureRandom random)
    this.hookMethod('initialize', ['int', 'java.security.SecureRandom'], (methodTag, args, originalCall) => {
      const keysize = args[0];
      Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { keysize, withRandom: true } });
      HookUtils.captureStack(methodTag);
      return originalCall();
    });

    // generateKeyPair()
    this.hookMethod('generateKeyPair', [], (methodTag, args, originalCall) => {
      const ret = originalCall();
      try {
        // 反射/常规模式：KeyPair 提供 getPublic/getPrivate
        const pub = ret ? ret.getPublic && ret.getPublic() : null;
        const pri = ret ? ret.getPrivate && ret.getPrivate() : null;
        const pubInfo = pub ? FormatUtils.extractKeyInfo(pub, 'PublicKey') : null;
        const priInfo = pri ? FormatUtils.extractKeyInfo(pri, 'PrivateKey') : null;
        Logger.info(`${methodTag} 调用`, { tag: this.hookName, data: { keypair: ret + '', publicKey: pubInfo, privateKey: priInfo } });
        HookUtils.captureStack(methodTag);
      } catch (e) {
        Logger.warn(`${methodTag} 提取 KeyPair 信息失败: ${e.message}`, { tag: this.hookName });
      }
      return ret;
    });
  }
}

class RSAKeySpecHook extends BaseHook {
  constructor() {
    super('java.security.spec.PKCS8EncodedKeySpec', 'RSAKeySpec', 'asymmetricCrypto.rsa');
  }

  start() {
    if (!this.initJavaClass()) {
      // 如果 PKCS8EncodedKeySpec 不可用，尝试其他密钥规范类
      this.tryAlternativeKeySpecs();
      return;
    }
    Logger.separator('RSAKeySpec Hook 启动');
    this.hookPKCS8EncodedKeySpec();
    this.hookX509EncodedKeySpec();
    this.hookRSAKeySpecs();
    Logger.info('RSAKeySpec Hook 启动完成', { tag: this.hookName });
  }

  tryAlternativeKeySpecs() {
    // 尝试 Hook 其他可能的密钥规范类
    const keySpecClasses = [
      'java.security.spec.X509EncodedKeySpec',
      'java.security.spec.RSAPrivateKeySpec',
      'java.security.spec.RSAPublicKeySpec',
      'java.security.spec.RSAPrivateCrtKeySpec'
    ];

    for (const className of keySpecClasses) {
      try {
        this.className = className;
        this.hookName = `RSAKeySpec_${className.split('.').pop()}`;
        if (this.initJavaClass()) {
          Logger.info(`成功初始化 ${className}`, { tag: this.hookName });
          this.hookKeySpecConstructors();
          break;
        }
      } catch (e) {
        Logger.debug(`无法初始化 ${className}: ${e.message}`, { tag: 'RSAKeySpec' });
      }
    }
  }

  hookPKCS8EncodedKeySpec() {
    try {
      // Hook PKCS8EncodedKeySpec 构造函数
      const PKCS8EncodedKeySpec = Java.use('java.security.spec.PKCS8EncodedKeySpec');
      const constructor = PKCS8EncodedKeySpec.$init.overload('[B');
      const hookInstance = this;

      constructor.implementation = function(encoded) {
        const methodTag = `${hookInstance.hookName}.PKCS8EncodedKeySpec(byte[])`;
        try {
          const result = constructor.call(this, encoded);

          // 提取并记录密钥数据
          const keyData = {
            type: 'PKCS8EncodedKeySpec',
            encodedLength: encoded ? encoded.length : 0
          };

          if (encoded && encoded.length > 0) {
            keyData.encoded = {
              hex: HookUtils.bytesToHex(encoded),
              base64: FormatUtils.bytesToBase64(encoded),
              pem: FormatUtils.bytesToPem(encoded, 'PRIVATE KEY')
            };
          }

          Logger.info(`${methodTag} 调用 - 捕获到私钥数据`, {
            tag: hookInstance.hookName,
            data: keyData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor.call(this, encoded);
        }
      };

      Logger.info('PKCS8EncodedKeySpec Hook 设置完成', { tag: this.hookName });
    } catch (e) {
      Logger.warn(`PKCS8EncodedKeySpec Hook 设置失败: ${e.message}`, { tag: this.hookName });
    }
  }

  hookX509EncodedKeySpec() {
    try {
      // Hook X509EncodedKeySpec 构造函数
      const X509EncodedKeySpec = Java.use('java.security.spec.X509EncodedKeySpec');
      const constructor = X509EncodedKeySpec.$init.overload('[B');
      const hookInstance = this;

      constructor.implementation = function(encoded) {
        const methodTag = `${hookInstance.hookName}.X509EncodedKeySpec(byte[])`;
        try {
          const result = constructor.call(this, encoded);

          // 提取并记录密钥数据
          const keyData = {
            type: 'X509EncodedKeySpec',
            encodedLength: encoded ? encoded.length : 0
          };

          if (encoded && encoded.length > 0) {
            keyData.encoded = {
              hex: HookUtils.bytesToHex(encoded),
              base64: FormatUtils.bytesToBase64(encoded),
              pem: FormatUtils.bytesToPem(encoded, 'PUBLIC KEY')
            };
          }

          Logger.info(`${methodTag} 调用 - 捕获到公钥数据`, {
            tag: hookInstance.hookName,
            data: keyData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor.call(this, encoded);
        }
      };

      Logger.info('X509EncodedKeySpec Hook 设置完成', { tag: this.hookName });
    } catch (e) {
      Logger.warn(`X509EncodedKeySpec Hook 设置失败: ${e.message}`, { tag: this.hookName });
    }
  }

  hookRSAKeySpecs() {
    // Hook RSAPrivateKeySpec
    try {
      const RSAPrivateKeySpec = Java.use('java.security.spec.RSAPrivateKeySpec');
      const constructor = RSAPrivateKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger');
      const hookInstance = this;

      constructor.implementation = function(modulus, privateExponent) {
        const methodTag = `${hookInstance.hookName}.RSAPrivateKeySpec(BigInteger,BigInteger)`;
        try {
          const result = constructor.call(this, modulus, privateExponent);

          const keyData = {
            type: 'RSAPrivateKeySpec',
            modulus: modulus ? modulus.toString(16) : null,
            privateExponent: privateExponent ? privateExponent.toString(16) : null,
            modulusLength: modulus ? modulus.bitLength() : 0
          };

          Logger.info(`${methodTag} 调用 - 捕获到RSA私钥参数`, {
            tag: hookInstance.hookName,
            data: keyData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor.call(this, modulus, privateExponent);
        }
      };

      Logger.info('RSAPrivateKeySpec Hook 设置完成', { tag: this.hookName });
    } catch (e) {
      Logger.warn(`RSAPrivateKeySpec Hook 设置失败: ${e.message}`, { tag: this.hookName });
    }

    // Hook RSAPublicKeySpec
    try {
      const RSAPublicKeySpec = Java.use('java.security.spec.RSAPublicKeySpec');
      const constructor = RSAPublicKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger');
      const hookInstance = this;

      constructor.implementation = function(modulus, publicExponent) {
        const methodTag = `${hookInstance.hookName}.RSAPublicKeySpec(BigInteger,BigInteger)`;
        try {
          const result = constructor.call(this, modulus, publicExponent);

          const keyData = {
            type: 'RSAPublicKeySpec',
            modulus: modulus ? modulus.toString(16) : null,
            publicExponent: publicExponent ? publicExponent.toString(16) : null,
            modulusLength: modulus ? modulus.bitLength() : 0
          };

          Logger.info(`${methodTag} 调用 - 捕获到RSA公钥参数`, {
            tag: hookInstance.hookName,
            data: keyData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor.call(this, modulus, publicExponent);
        }
      };

      Logger.info('RSAPublicKeySpec Hook 设置完成', { tag: this.hookName });
    } catch (e) {
      Logger.warn(`RSAPublicKeySpec Hook 设置失败: ${e.message}`, { tag: this.hookName });
    }
  }

  hookKeySpecConstructors() {
    // 通用的密钥规范构造函数 Hook
    try {
      if (this.javaClass && this.javaClass.$init) {
        const constructors = this.javaClass.$init.overloads;
        const hookInstance = this;

        constructors.forEach((constructor, index) => {
          try {
            const originalImpl = constructor.implementation;
            constructor.implementation = function(...args) {
              const methodTag = `${hookInstance.hookName}.constructor[${index}]`;
              try {
                const result = originalImpl ? originalImpl.apply(this, args) : constructor.call(this, ...args);

                Logger.info(`${methodTag} 调用`, {
                  tag: hookInstance.hookName,
                  data: {
                    className: hookInstance.className,
                    argsCount: args.length,
                    args: args.map((arg, i) => `arg${i}: ${typeof arg}`)
                  }
                });
                HookUtils.captureStack(methodTag);

                return result;
              } catch (e) {
                Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
                  tag: hookInstance.hookName,
                  error: e
                });
                return originalImpl ? originalImpl.apply(this, args) : constructor.call(this, ...args);
              }
            };
          } catch (e) {
            Logger.debug(`构造函数[${index}] Hook设置失败: ${e.message}`, { tag: this.hookName });
          }
        });
      }
    } catch (e) {
      Logger.warn(`通用构造函数 Hook 设置失败: ${e.message}`, { tag: this.hookName });
    }
  }
}

class RSAKeyFactoryHook extends BaseHook {
  constructor() {
    super('java.security.KeyFactory', 'RSAKeyFactory', 'asymmetricCrypto.rsa');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('RSAKeyFactory Hook 启动');
    this.hookGetInstance();
    this.hookGeneratePrivate();
    this.hookGeneratePublic();
    this.hookGetKeySpec();
    Logger.info('RSAKeyFactory Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook KeyFactory.getInstance() 方法
   */
  hookGetInstance() {
    // Hook getInstance(String algorithm) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const result = originalCall();

      // 只记录RSA相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('RSA')) {
        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录RSA相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('RSA')) {
        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录RSA相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('RSA')) {
        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook generatePrivate() 方法
   */
  hookGeneratePrivate() {
    this.hookMethod('generatePrivate', ['java.security.spec.KeySpec'], (methodTag, args, originalCall) => {
      const keySpec = args[0];
      const result = originalCall();

      const keyInfo = FormatUtils.extractKeyInfo(result, 'RSA Private Key');
      const specInfo = {
        keySpecClass: keySpec ? keySpec.getClass().getName() : 'null',
        keySpecString: keySpec ? keySpec.toString() : 'null'
      };

      Logger.info(`${methodTag} 调用 - 生成RSA私钥`, {
        tag: this.hookName,
        data: {
          keySpec: specInfo,
          generatedKey: keyInfo
        }
      });
      HookUtils.captureStack(methodTag);

      return result;
    });
  }

  /**
   * Hook generatePublic() 方法
   */
  hookGeneratePublic() {
    this.hookMethod('generatePublic', ['java.security.spec.KeySpec'], (methodTag, args, originalCall) => {
      const keySpec = args[0];
      const result = originalCall();

      const keyInfo = FormatUtils.extractKeyInfo(result, 'RSA Public Key');
      const specInfo = {
        keySpecClass: keySpec ? keySpec.getClass().getName() : 'null',
        keySpecString: keySpec ? keySpec.toString() : 'null'
      };

      Logger.info(`${methodTag} 调用 - 生成RSA公钥`, {
        tag: this.hookName,
        data: {
          keySpec: specInfo,
          generatedKey: keyInfo
        }
      });
      HookUtils.captureStack(methodTag);

      return result;
    });
  }

  /**
   * Hook getKeySpec() 方法
   */
  hookGetKeySpec() {
    this.hookMethod('getKeySpec', ['java.security.Key', 'java.lang.Class'], (methodTag, args, originalCall) => {
      const key = args[0];
      const keySpecClass = args[1];
      const result = originalCall();

      const keyInfo = FormatUtils.extractKeyInfo(key, 'Key');

      Logger.info(`${methodTag} 调用 - 获取密钥规范`, {
        tag: this.hookName,
        data: {
          inputKey: keyInfo,
          targetSpecClass: keySpecClass ? keySpecClass.getName() : 'null',
          resultSpec: result ? result.toString() : 'null'
        }
      });
      HookUtils.captureStack(methodTag);

      return result;
    });
  }
}





class DESCipherHook extends BaseHook {
  constructor() {
    super('javax.crypto.Cipher', 'DESCipher', 'symmetricCrypto.des');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('DESCipher Hook 启动');
    this.hookGetInstance();
    this.hookInit();
    this.hookUpdate();
    this.hookDoFinal();
    Logger.info('DESCipher Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook Cipher.getInstance() 方法
   */
  hookGetInstance() {
    // Hook getInstance(String transformation) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const result = originalCall();

      // 只记录DES相关的调用
      if (transformation && this.isDESTransformation(transformation.toString())) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'DES',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String transformation, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录DES相关的调用
      if (transformation && this.isDESTransformation(transformation.toString())) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'DES',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String transformation, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录DES相关的调用
      if (transformation && this.isDESTransformation(transformation.toString())) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'DES',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.init() 方法
   */
  hookInit() {
    // Hook init(int opmode, Key key) 方法
    this.hookMethod('init', ['int', 'java.security.Key'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'DES Key');
        const modeStr = this.getOperationMode(opmode);

        const formattedOutput = this.createFormattedOutput('DES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES初始化`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, SecureRandom random) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const random = args[2];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'DES Key');
        const modeStr = this.getOperationMode(opmode);

        const formattedOutput = this.createFormattedOutput('DES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          secureRandom: random ? random.toString() : 'null',
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES初始化(带随机数)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, AlgorithmParameterSpec params) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const params = args[2];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'DES Key');
        const modeStr = this.getOperationMode(opmode);
        const paramInfo = this.extractAlgorithmParams(params);

        const formattedOutput = this.createFormattedOutput('DES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          algorithmParams: paramInfo,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES初始化(带参数)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const params = args[2];
      const random = args[3];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'DES Key');
        const modeStr = this.getOperationMode(opmode);
        const paramInfo = this.extractAlgorithmParams(params);

        const formattedOutput = this.createFormattedOutput('DES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          algorithmParams: paramInfo,
          secureRandom: random ? random.toString() : 'null',
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES初始化(完整参数)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.update() 方法
   */
  hookUpdate() {
    // Hook update(byte[] input) 方法
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, result, {
          method: 'update',
          inputLength: input ? input.length : 0,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES更新数据`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen) 方法
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, result, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES更新数据(带偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen, byte[] output) 方法
    this.hookMethod('update', ['[B', 'int', 'int', '[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, output, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES更新数据(输出缓冲区)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) 方法
    this.hookMethod('update', ['[B', 'int', 'int', '[B', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const outputOffset = args[4];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, output, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          outputOffset: outputOffset,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES更新数据(完整偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(ByteBuffer input, ByteBuffer output) 方法
    this.hookMethod('update', ['java.nio.ByteBuffer', 'java.nio.ByteBuffer'], (methodTag, args, originalCall, javaThis) => {
      const inputBB = args[0];
      const outputBB = args[1];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const inputInfo = this.extractByteBufferInfo(inputBB, 'Input');
        const outputInfo = this.extractByteBufferInfo(outputBB, 'Output');

        const formattedOutput = this.createFormattedOutput('DES', null, null, {
          method: 'update',
          inputBuffer: inputInfo,
          outputBuffer: outputInfo,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES更新数据(ByteBuffer)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.doFinal() 方法
   */
  hookDoFinal() {
    // Hook doFinal() 方法
    this.hookMethod('doFinal', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', null, result, {
          method: 'doFinal',
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input) 方法
    this.hookMethod('doFinal', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, result, {
          method: 'doFinal',
          inputLength: input ? input.length : 0,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密(带输入)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input, int inputOffset, int inputLen) 方法
    this.hookMethod('doFinal', ['[B', 'int', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, result, {
          method: 'doFinal',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密(带偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] output, int outputOffset) 方法
    this.hookMethod('doFinal', ['[B', 'int'], (methodTag, args, originalCall, javaThis) => {
      const output = args[0];
      const outputOffset = args[1];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', null, output, {
          method: 'doFinal',
          outputBufferLength: output ? output.length : 0,
          outputOffset: outputOffset,
          bytesWritten: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密(输出缓冲区)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) 方法
    this.hookMethod('doFinal', ['[B', 'int', 'int', '[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, output, {
          method: 'doFinal',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          bytesWritten: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密(完整缓冲区)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) 方法
    this.hookMethod('doFinal', ['[B', 'int', 'int', '[B', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const outputOffset = args[4];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('DES', input, output, {
          method: 'doFinal',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          outputOffset: outputOffset,
          bytesWritten: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密(完整偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(ByteBuffer input, ByteBuffer output) 方法
    this.hookMethod('doFinal', ['java.nio.ByteBuffer', 'java.nio.ByteBuffer'], (methodTag, args, originalCall, javaThis) => {
      const inputBB = args[0];
      const outputBB = args[1];
      const result = originalCall();

      // 检查是否为DES算法
      if (this.isDESCipher(javaThis)) {
        const inputInfo = this.extractByteBufferInfo(inputBB, 'Input');
        const outputInfo = this.extractByteBufferInfo(outputBB, 'Output');

        const formattedOutput = this.createFormattedOutput('DES', null, null, {
          method: 'doFinal',
          inputBuffer: inputInfo,
          outputBuffer: outputInfo,
          bytesWritten: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - DES完成加密/解密(ByteBuffer)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * 检查是否为DES算法的Cipher实例
   * @param {Object} cipherInstance Cipher实例
   * @returns {boolean} 是否为DES算法
   */
  isDESCipher(cipherInstance) {
    try {
      const transformation = this.getTransformation(cipherInstance);
      return this.isDESTransformation(transformation);
    } catch (e) {
      return false;
    }
  }

  /**
   * 检查是否为DES相关的transformation
   * @param {string} transformation 转换字符串
   * @returns {boolean} 是否为DES相关
   */
  isDESTransformation(transformation) {
    if (!transformation) return false;
    const upperTransformation = transformation.toUpperCase();
    return upperTransformation.includes('DES') && !upperTransformation.includes('3DES') && !upperTransformation.includes('TRIPLEDES');
  }

  /**
   * 获取Cipher实例的transformation
   * @param {Object} cipherInstance Cipher实例
   * @returns {string} transformation字符串
   */
  getTransformation(cipherInstance) {
    try {
      // 尝试获取算法信息
      const algorithm = cipherInstance.getAlgorithm();
      return algorithm ? algorithm.toString() : 'Unknown';
    } catch (e) {
      return 'Unknown';
    }
  }

  /**
   * 获取操作模式字符串
   * @param {number} opmode 操作模式
   * @returns {string} 操作模式字符串
   */
  getOperationMode(opmode) {
    const modes = {
      1: 'ENCRYPT_MODE',
      2: 'DECRYPT_MODE',
      3: 'WRAP_MODE',
      4: 'UNWRAP_MODE'
    };
    return modes[opmode] || `UNKNOWN_MODE(${opmode})`;
  }

  /**
   * 提取算法参数信息
   * @param {Object} params 算法参数
   * @returns {Object} 参数信息
   */
  extractAlgorithmParams(params) {
    if (!params) return { type: 'null', details: 'null' };

    try {
      const className = params.getClass().getName();
      const paramInfo = {
        type: className,
        details: params.toString()
      };

      // 如果是IvParameterSpec，尝试提取IV
      if (className.includes('IvParameterSpec')) {
        try {
          const iv = params.getIV();
          if (iv) {
            paramInfo.iv = {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv),
              length: iv.length
            };
          }
        } catch (e) {
          paramInfo.ivError = e.message;
        }
      }

      return paramInfo;
    } catch (e) {
      return {
        type: 'Unknown',
        details: 'Error extracting params: ' + e.message
      };
    }
  }

  /**
   * 提取ByteBuffer信息
   * @param {Object} byteBuffer ByteBuffer对象
   * @param {string} type 类型标识
   * @returns {Object} ByteBuffer信息
   */
  extractByteBufferInfo(byteBuffer, type = '') {
    if (!byteBuffer) return { type: type, status: 'null' };

    try {
      return {
        type: type,
        capacity: byteBuffer.capacity(),
        position: byteBuffer.position(),
        limit: byteBuffer.limit(),
        remaining: byteBuffer.remaining(),
        hasArray: byteBuffer.hasArray(),
        isDirect: byteBuffer.isDirect(),
        isReadOnly: byteBuffer.isReadOnly()
      };
    } catch (e) {
      return {
        type: type,
        error: e.message
      };
    }
  }
}

class AESCipherHook extends BaseHook {
  constructor() {
    super('javax.crypto.Cipher', 'AESCipher', 'symmetricCrypto.aes');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('AESCipher Hook 启动');
    this.hookGetInstance();
    this.hookInit();
    this.hookUpdate();
    this.hookDoFinal();
    Logger.info('AESCipher Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook Cipher.getInstance() 方法
   */
  hookGetInstance() {
    // Hook getInstance(String transformation) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const result = originalCall();

      // 只记录AES相关的调用
      if (transformation && transformation.toString().toUpperCase().includes('AES')) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'AES',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String transformation, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录AES相关的调用
      if (transformation && transformation.toString().toUpperCase().includes('AES')) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'AES',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String transformation, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录AES相关的调用
      if (transformation && transformation.toString().toUpperCase().includes('AES')) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'AES',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.init() 方法
   */
  hookInit() {
    // Hook init(int opmode, Key key) 方法
    this.hookMethod('init', ['int', 'java.security.Key'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'AES Key');
        const modeStr = this.getOperationMode(opmode);

        const formattedOutput = this.createFormattedOutput('AES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES初始化`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, SecureRandom random) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const random = args[2];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'AES Key');
        const modeStr = this.getOperationMode(opmode);

        const formattedOutput = this.createFormattedOutput('AES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          secureRandom: random ? random.toString() : 'null',
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES初始化(带随机数)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, AlgorithmParameterSpec params) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const params = args[2];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'AES Key');
        const modeStr = this.getOperationMode(opmode);
        const paramInfo = this.extractAlgorithmParams(params);

        const formattedOutput = this.createFormattedOutput('AES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          algorithmParams: paramInfo,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES初始化(带参数)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const params = args[2];
      const random = args[3];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'AES Key');
        const modeStr = this.getOperationMode(opmode);
        const paramInfo = this.extractAlgorithmParams(params);

        const formattedOutput = this.createFormattedOutput('AES', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          key: keyInfo,
          algorithmParams: paramInfo,
          secureRandom: random ? random.toString() : 'null',
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES初始化(完整参数)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.update() 方法
   */
  hookUpdate() {
    // Hook update(byte[] input) 方法
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, result, {
          method: 'update',
          inputLength: input ? input.length : 0,
          resultLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES更新数据`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen) 方法
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, result, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          resultLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES更新数据(带偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen, byte[] output) 方法
    this.hookMethod('update', ['[B', 'int', 'int', '[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, output, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES更新数据(输出缓冲区)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) 方法
    this.hookMethod('update', ['[B', 'int', 'int', '[B', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const outputOffset = args[4];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, output, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          outputOffset: outputOffset,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES更新数据(完整偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(ByteBuffer input, ByteBuffer output) 方法
    this.hookMethod('update', ['java.nio.ByteBuffer', 'java.nio.ByteBuffer'], (methodTag, args, originalCall, javaThis) => {
      const inputBB = args[0];
      const outputBB = args[1];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const inputMeta = this.extractByteBufferInfo(inputBB, 'input');
        const outputMeta = this.extractByteBufferInfo(outputBB, 'output');

        const formattedOutput = this.createFormattedOutput('AES', inputMeta.data, outputMeta.data, {
          method: 'update',
          inputBuffer: inputMeta.meta,
          outputBuffer: outputMeta.meta,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES更新数据(ByteBuffer)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.doFinal() 方法
   */
  hookDoFinal() {
    // Hook doFinal() 方法
    this.hookMethod('doFinal', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', null, result, {
          method: 'doFinal',
          resultLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES完成加密/解密`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input) 方法
    this.hookMethod('doFinal', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, result, {
          method: 'doFinal',
          inputLength: input ? input.length : 0,
          resultLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES完成加密/解密(带输入)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input, int inputOffset, int inputLen) 方法
    this.hookMethod('doFinal', ['[B', 'int', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, result, {
          method: 'doFinal',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          resultLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES完成加密/解密(带偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) 方法
    this.hookMethod('doFinal', ['[B', 'int', 'int', '[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, output, {
          method: 'doFinal',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES完成加密/解密(输出缓冲区)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) 方法
    this.hookMethod('doFinal', ['[B', 'int', 'int', '[B', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const output = args[3];
      const outputOffset = args[4];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('AES', input, output, {
          method: 'doFinal',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input ? input.length : 0,
          outputBufferLength: output ? output.length : 0,
          outputOffset: outputOffset,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES完成加密/解密(完整偏移)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(ByteBuffer input, ByteBuffer output) 方法
    this.hookMethod('doFinal', ['java.nio.ByteBuffer', 'java.nio.ByteBuffer'], (methodTag, args, originalCall, javaThis) => {
      const inputBB = args[0];
      const outputBB = args[1];
      const result = originalCall();

      // 检查是否为AES算法
      if (this.isAESCipher(javaThis)) {
        const inputMeta = this.extractByteBufferInfo(inputBB, 'input');
        const outputMeta = this.extractByteBufferInfo(outputBB, 'output');

        const formattedOutput = this.createFormattedOutput('AES', inputMeta.data, outputMeta.data, {
          method: 'doFinal',
          inputBuffer: inputMeta.meta,
          outputBuffer: outputMeta.meta,
          bytesProcessed: result,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用 - AES完成加密/解密(ByteBuffer)`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * 检查Cipher实例是否为AES算法
   * @param {Object} cipherInstance Java Cipher实例
   * @returns {boolean} 是否为AES算法
   */
  isAESCipher(cipherInstance) {
    try {
      if (!cipherInstance) return false;

      // 尝试获取算法名称
      const algorithm = cipherInstance.getAlgorithm ? cipherInstance.getAlgorithm() : null;
      if (algorithm) {
        const algStr = algorithm.toString().toUpperCase();
        return algStr.includes('AES');
      }

      // 如果无法获取算法名称，返回false
      return false;
    } catch (e) {
      return false;
    }
  }

  /**
   * 获取Cipher的transformation字符串
   * @param {Object} cipherInstance Java Cipher实例
   * @returns {string} transformation字符串
   */
  getTransformation(cipherInstance) {
    try {
      if (!cipherInstance) return 'Unknown';

      const algorithm = cipherInstance.getAlgorithm ? cipherInstance.getAlgorithm() : null;
      return algorithm ? algorithm.toString() : 'Unknown';
    } catch (e) {
      return 'Unknown';
    }
  }

  /**
   * 获取操作模式字符串
   * @param {number} opmode 操作模式数值
   * @returns {string} 操作模式字符串
   */
  getOperationMode(opmode) {
    const modes = {
      1: 'ENCRYPT_MODE',
      2: 'DECRYPT_MODE',
      3: 'WRAP_MODE',
      4: 'UNWRAP_MODE'
    };
    return modes[opmode] || `Unknown(${opmode})`;
  }

  /**
   * 提取算法参数信息
   * @param {Object} params AlgorithmParameterSpec对象
   * @returns {Object} 参数信息
   */
  extractAlgorithmParams(params) {
    if (!params) return null;

    try {
      const paramInfo = {
        class: params.getClass().getName(),
        toString: params.toString()
      };

      // 尝试提取IV参数（IvParameterSpec）
      try {
        if (params.getIV) {
          const iv = params.getIV();
          if (iv) {
            paramInfo.iv = {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv),
              length: iv.length
            };
          }
        }
      } catch (e) {
        // 忽略IV提取失败
      }

      // 尝试提取GCM参数（GCMParameterSpec）
      try {
        if (params.getTLen) {
          paramInfo.tagLength = params.getTLen();
        }
        if (params.getIV) {
          const iv = params.getIV();
          if (iv) {
            paramInfo.gcmIv = {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv),
              length: iv.length
            };
          }
        }
      } catch (e) {
        // 忽略GCM参数提取失败
      }

      return paramInfo;
    } catch (e) {
      return {
        error: e.message,
        toString: params.toString()
      };
    }
  }

  /**
   * 提取ByteBuffer信息
   * @param {Object} byteBuffer Java ByteBuffer对象
   * @param {string} type 类型标识
   * @returns {Object} ByteBuffer信息
   */
  extractByteBufferInfo(byteBuffer, type = '') {
    const result = {
      data: null,
      meta: {}
    };

    if (!byteBuffer) {
      result.meta.note = `${type} ByteBuffer is null`;
      return result;
    }

    try {
      // 提取ByteBuffer元数据
      if (byteBuffer.position) result.meta.position = byteBuffer.position();
      if (byteBuffer.limit) result.meta.limit = byteBuffer.limit();
      if (byteBuffer.remaining) result.meta.remaining = byteBuffer.remaining();
      if (byteBuffer.capacity) result.meta.capacity = byteBuffer.capacity();

      // 尝试获取底层数组
      try {
        if (byteBuffer.hasArray && byteBuffer.hasArray()) {
          result.data = byteBuffer.array();
          result.meta.backingArray = true;
        } else {
          result.meta.backingArray = false;
          result.meta.note = '无法直接获取底层数组';
        }
      } catch (e) {
        result.meta.note = '获取底层数组失败: ' + e.message;
      }
    } catch (e) {
      result.meta.error = e.message;
    }

    return result;
  }
}

class DESKeyGeneratorHook extends BaseHook {
  constructor() {
    super('javax.crypto.KeyGenerator', 'DESKeyGenerator', 'symmetricCrypto.des');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('DESKeyGenerator Hook 启动');
    this.hookGenerateKey();
    this.hookGetInstance();
    Logger.info('DESKeyGenerator Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook KeyGenerator.generateKey() 方法
   */
  hookGenerateKey() {
    this.hookMethod('generateKey', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      // 检查是否为DES密钥生成器
      if (this.isDESKeyGenerator(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(result, 'DES Generated Key');

        Logger.info(`${methodTag} 调用 - DES密钥生成`, {
          tag: this.hookName,
          data: {
            algorithm: 'DES',
            method: 'generateKey',
            keyInfo: keyInfo,
            generator: javaThis.toString()
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook KeyGenerator.getInstance() 静态方法
   */
  hookGetInstance() {
    // Hook getInstance(String algorithm) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const result = originalCall();

      // 只记录DES相关的调用
      if (algorithm && this.isDESAlgorithm(algorithm.toString())) {
        Logger.info(`${methodTag} 调用 - DES密钥生成器创建`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            method: 'getInstance',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录DES相关的调用
      if (algorithm && this.isDESAlgorithm(algorithm.toString())) {
        Logger.info(`${methodTag} 调用 - DES密钥生成器创建(带提供者)`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            method: 'getInstance',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录DES相关的调用
      if (algorithm && this.isDESAlgorithm(algorithm.toString())) {
        Logger.info(`${methodTag} 调用 - DES密钥生成器创建(带Provider对象)`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            method: 'getInstance',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * 检查是否为DES密钥生成器
   * @param {Object} keyGenerator KeyGenerator实例
   * @returns {boolean} 是否为DES密钥生成器
   */
  isDESKeyGenerator(keyGenerator) {
    try {
      const algorithm = keyGenerator.getAlgorithm();
      return this.isDESAlgorithm(algorithm ? algorithm.toString() : '');
    } catch (e) {
      return false;
    }
  }

  /**
   * 检查是否为DES算法
   * @param {string} algorithm 算法名称
   * @returns {boolean} 是否为DES算法
   */
  isDESAlgorithm(algorithm) {
    if (!algorithm) return false;
    const upperAlgorithm = algorithm.toUpperCase();
    return upperAlgorithm === 'DES' || upperAlgorithm.startsWith('DES/');
  }
}

class AESKeyGeneratorHook extends BaseHook {
  constructor() {
    super('javax.crypto.KeyGenerator', 'AESKeyGenerator', 'symmetricCrypto.aes');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('AESKeyGenerator Hook 启动');
    this.hookGetInstance();
    this.hookInit();
    this.hookGenerateKey();
    Logger.info('AESKeyGenerator Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook KeyGenerator.getInstance() 方法
   */
  hookGetInstance() {
    // Hook getInstance(String algorithm) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const result = originalCall();

      // 只记录AES相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('AES')) {
        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录AES相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('AES')) {
        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录AES相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('AES')) {
        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook KeyGenerator.init() 方法
   */
  hookInit() {
    // Hook init(int keysize) 方法
    this.hookMethod('init', ['int'], (methodTag, args, originalCall, javaThis) => {
      const keysize = args[0];
      const result = originalCall();

      // 检查是否为AES密钥生成器
      if (this.isAESKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - AES密钥生成器初始化`, {
          tag: this.hookName,
          data: {
            algorithm: 'AES',
            keySize: keysize,
            method: 'init(int)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int keysize, SecureRandom random) 方法
    this.hookMethod('init', ['int', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const keysize = args[0];
      const random = args[1];
      const result = originalCall();

      // 检查是否为AES密钥生成器
      if (this.isAESKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - AES密钥生成器初始化(带随机数)`, {
          tag: this.hookName,
          data: {
            algorithm: 'AES',
            keySize: keysize,
            secureRandom: random ? random.toString() : 'null',
            method: 'init(int, SecureRandom)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(AlgorithmParameterSpec params) 方法
    this.hookMethod('init', ['java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall, javaThis) => {
      const params = args[0];
      const result = originalCall();

      // 检查是否为AES密钥生成器
      if (this.isAESKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - AES密钥生成器初始化(带参数)`, {
          tag: this.hookName,
          data: {
            algorithm: 'AES',
            params: params ? params.toString() : 'null',
            paramsClass: params ? params.getClass().getName() : 'null',
            method: 'init(AlgorithmParameterSpec)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(AlgorithmParameterSpec params, SecureRandom random) 方法
    this.hookMethod('init', ['java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const params = args[0];
      const random = args[1];
      const result = originalCall();

      // 检查是否为AES密钥生成器
      if (this.isAESKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - AES密钥生成器初始化(完整参数)`, {
          tag: this.hookName,
          data: {
            algorithm: 'AES',
            params: params ? params.toString() : 'null',
            paramsClass: params ? params.getClass().getName() : 'null',
            secureRandom: random ? random.toString() : 'null',
            method: 'init(AlgorithmParameterSpec, SecureRandom)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook KeyGenerator.generateKey() 方法
   */
  hookGenerateKey() {
    this.hookMethod('generateKey', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      // 检查是否为AES密钥生成器
      if (this.isAESKeyGenerator(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(result, 'AES Generated Key');

        Logger.info(`${methodTag} 调用 - 生成AES密钥`, {
          tag: this.hookName,
          data: {
            algorithm: 'AES',
            generatedKey: keyInfo,
            method: 'generateKey()'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * 检查KeyGenerator实例是否为AES算法
   * @param {Object} keyGenInstance Java KeyGenerator实例
   * @returns {boolean} 是否为AES算法
   */
  isAESKeyGenerator(keyGenInstance) {
    try {
      if (!keyGenInstance) return false;

      // 尝试获取算法名称
      const algorithm = keyGenInstance.getAlgorithm ? keyGenInstance.getAlgorithm() : null;
      if (algorithm) {
        const algStr = algorithm.toString().toUpperCase();
        return algStr.includes('AES');
      }

      return false;
    } catch (e) {
      return false;
    }
  }
}

class AESKeySpecHook extends BaseHook {
  constructor() {
    super('javax.crypto.spec.SecretKeySpec', 'AESKeySpec', 'symmetricCrypto.aes');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('AESKeySpec Hook 启动');
    this.hookSecretKeySpec();
    this.hookIvParameterSpec();
    Logger.info('AESKeySpec Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook SecretKeySpec 构造函数
   */
  hookSecretKeySpec() {
    try {
      const SecretKeySpec = this.javaClass;
      const hookInstance = this;

      // Hook SecretKeySpec(byte[] key, String algorithm) 构造函数
      const constructor1 = SecretKeySpec.$init.overload('[B', 'java.lang.String');
      constructor1.implementation = function(key, algorithm) {
        const methodTag = `${hookInstance.hookName}.SecretKeySpec(byte[],String)`;

        try {
          const result = constructor1.call(this, key, algorithm);

          // 记录AES、HMAC和DES相关的密钥规范
          const algorithmStr = algorithm ? algorithm.toString().toUpperCase() : '';
          if (algorithmStr.includes('AES') || algorithmStr.includes('HMAC') || algorithmStr.includes('DES')) {
            const keyData = {
              algorithm: algorithm.toString(),
              keyLength: key ? key.length : 0,
              keyData: key ? {
                hex: HookUtils.bytesToHex(key),
                base64: FormatUtils.bytesToBase64(key),
                string: FormatUtils.bytesToUtf8(key),
                ascii: FormatUtils.bytesToAscii(key),
                utf8: FormatUtils.bytesToUtf8(key),
                raw: FormatUtils.bytesToRaw(key)
              } : null
            };

            const keyType = algorithmStr.includes('AES') ? 'AES' :
                           algorithmStr.includes('HMAC') ? 'HMAC' : 'DES';
            Logger.info(`${methodTag} 调用 - 创建${keyType}密钥规范`, {
              tag: hookInstance.hookName,
              data: keyData
            });
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor1.call(this, key, algorithm);
        }
      };

      // Hook SecretKeySpec(byte[] key, int offset, int len, String algorithm) 构造函数
      const constructor2 = SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String');
      constructor2.implementation = function(key, offset, len, algorithm) {
        const methodTag = `${hookInstance.hookName}.SecretKeySpec(byte[],int,int,String)`;

        try {
          const result = constructor2.call(this, key, offset, len, algorithm);

          // 记录AES和HMAC相关的密钥规范
          const algorithmStr = algorithm ? algorithm.toString().toUpperCase() : '';
          if (algorithmStr.includes('AES') || algorithmStr.includes('HMAC')) {
            const keyData = {
              algorithm: algorithm.toString(),
              totalKeyLength: key ? key.length : 0,
              keyOffset: offset,
              keyLength: len,
              keyData: key ? {
                hex: HookUtils.bytesToHex(key),
                base64: FormatUtils.bytesToBase64(key),
                string: FormatUtils.bytesToUtf8(key),
                ascii: FormatUtils.bytesToAscii(key),
                utf8: FormatUtils.bytesToUtf8(key),
                raw: FormatUtils.bytesToRaw(key),
                usedHex: key.length > offset + len ? HookUtils.bytesToHex(key.slice(offset, offset + len)) : 'Invalid range'
              } : null
            };

            const keyType = algorithmStr.includes('AES') ? 'AES' : 'HMAC';
            Logger.info(`${methodTag} 调用 - 创建${keyType}密钥规范(带偏移)`, {
              tag: hookInstance.hookName,
              data: keyData
            });
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor2.call(this, key, offset, len, algorithm);
        }
      };

      Logger.info('SecretKeySpec Hook 设置完成 (2个构造函数)', { tag: this.hookName });
    } catch (e) {
      Logger.error(`SecretKeySpec Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }

  /**
   * Hook IvParameterSpec 构造函数
   */
  hookIvParameterSpec() {
    try {
      const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
      const hookInstance = this;

      // Hook IvParameterSpec(byte[] iv) 构造函数
      const constructor1 = IvParameterSpec.$init.overload('[B');
      constructor1.implementation = function(iv) {
        const methodTag = `${hookInstance.hookName}.IvParameterSpec(byte[])`;

        try {
          const result = constructor1.call(this, iv);

          const ivData = {
            ivLength: iv ? iv.length : 0,
            iv: iv ? {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv)
            } : null
          };

          Logger.info(`${methodTag} 调用 - 创建IV参数规范`, {
            tag: hookInstance.hookName,
            data: ivData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor1.call(this, iv);
        }
      };

      // Hook IvParameterSpec(byte[] iv, int offset, int len) 构造函数
      const constructor2 = IvParameterSpec.$init.overload('[B', 'int', 'int');
      constructor2.implementation = function(iv, offset, len) {
        const methodTag = `${hookInstance.hookName}.IvParameterSpec(byte[],int,int)`;

        try {
          const result = constructor2.call(this, iv, offset, len);

          const ivData = {
            totalIvLength: iv ? iv.length : 0,
            ivOffset: offset,
            ivLength: len,
            iv: iv ? {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv),
              usedHex: iv.length > offset + len ? HookUtils.bytesToHex(iv.slice(offset, offset + len)) : 'Invalid range'
            } : null
          };

          Logger.info(`${methodTag} 调用 - 创建IV参数规范(带偏移)`, {
            tag: hookInstance.hookName,
            data: ivData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor2.call(this, iv, offset, len);
        }
      };

      Logger.info('IvParameterSpec Hook 设置成功', { tag: this.hookName });
    } catch (e) {
      Logger.error(`IvParameterSpec Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }
}

class AESIvParameterSpecHook extends BaseHook {
  constructor() {
    super('javax.crypto.spec.IvParameterSpec', 'AESIvParameterSpec', 'symmetricCrypto.aes');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('AESIvParameterSpec Hook 启动');
    this.hookIvParameterSpec();
    this.hookGCMParameterSpec();
    Logger.info('AESIvParameterSpec Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook IvParameterSpec 构造函数和方法
   */
  hookIvParameterSpec() {
    try {
      const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
      const hookInstance = this;

      // Hook IvParameterSpec(byte[] iv) 构造函数
      const constructor1 = IvParameterSpec.$init.overload('[B');
      constructor1.implementation = function(iv) {
        const methodTag = `${hookInstance.hookName}.IvParameterSpec(byte[])`;

        try {
          const result = constructor1.call(this, iv);

          const ivData = {
            ivLength: iv ? iv.length : 0,
            iv: iv ? {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv)
            } : null
          };

          Logger.info(`${methodTag} 调用 - 创建IV参数规范`, {
            tag: hookInstance.hookName,
            data: ivData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor1.call(this, iv);
        }
      };

      // Hook IvParameterSpec(byte[] iv, int offset, int len) 构造函数
      const constructor2 = IvParameterSpec.$init.overload('[B', 'int', 'int');
      constructor2.implementation = function(iv, offset, len) {
        const methodTag = `${hookInstance.hookName}.IvParameterSpec(byte[],int,int)`;

        try {
          const result = constructor2.call(this, iv, offset, len);

          const ivData = {
            totalIvLength: iv ? iv.length : 0,
            ivOffset: offset,
            ivLength: len,
            iv: iv ? {
              hex: HookUtils.bytesToHex(iv),
              base64: FormatUtils.bytesToBase64(iv),
              usedHex: iv.length > offset + len ? HookUtils.bytesToHex(iv.slice(offset, offset + len)) : 'Invalid range'
            } : null
          };

          Logger.info(`${methodTag} 调用 - 创建IV参数规范(带偏移)`, {
            tag: hookInstance.hookName,
            data: ivData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor2.call(this, iv, offset, len);
        }
      };

      // Hook getIV() 方法
      this.hookMethod('getIV', [], (methodTag, args, originalCall, javaThis) => {
        const result = originalCall();

        const ivData = {
          ivLength: result ? result.length : 0,
          iv: result ? {
            hex: HookUtils.bytesToHex(result),
            base64: FormatUtils.bytesToBase64(result)
          } : null
        };

        Logger.info(`${methodTag} 调用 - 获取IV`, {
          tag: this.hookName,
          data: ivData
        });
        HookUtils.captureStack(methodTag);

        return result;
      });

      Logger.info('IvParameterSpec Hook 设置成功', { tag: this.hookName });
    } catch (e) {
      Logger.error(`IvParameterSpec Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }

  /**
   * Hook GCMParameterSpec 构造函数和方法
   */
  hookGCMParameterSpec() {
    try {
      const GCMParameterSpec = Java.use('javax.crypto.spec.GCMParameterSpec');
      const hookInstance = this;

      // Hook GCMParameterSpec(int tLen, byte[] src) 构造函数
      const constructor1 = GCMParameterSpec.$init.overload('int', '[B');
      constructor1.implementation = function(tLen, src) {
        const methodTag = `${hookInstance.hookName}.GCMParameterSpec(int,byte[])`;

        try {
          const result = constructor1.call(this, tLen, src);

          const gcmData = {
            tagLength: tLen,
            ivLength: src ? src.length : 0,
            iv: src ? {
              hex: HookUtils.bytesToHex(src),
              base64: FormatUtils.bytesToBase64(src)
            } : null
          };

          Logger.info(`${methodTag} 调用 - 创建GCM参数规范`, {
            tag: hookInstance.hookName,
            data: gcmData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor1.call(this, tLen, src);
        }
      };

      // Hook GCMParameterSpec(int tLen, byte[] src, int offset, int len) 构造函数
      const constructor2 = GCMParameterSpec.$init.overload('int', '[B', 'int', 'int');
      constructor2.implementation = function(tLen, src, offset, len) {
        const methodTag = `${hookInstance.hookName}.GCMParameterSpec(int,byte[],int,int)`;

        try {
          const result = constructor2.call(this, tLen, src, offset, len);

          const gcmData = {
            tagLength: tLen,
            totalIvLength: src ? src.length : 0,
            ivOffset: offset,
            ivLength: len,
            iv: src ? {
              hex: HookUtils.bytesToHex(src),
              base64: FormatUtils.bytesToBase64(src),
              usedHex: src.length > offset + len ? HookUtils.bytesToHex(src.slice(offset, offset + len)) : 'Invalid range'
            } : null
          };

          Logger.info(`${methodTag} 调用 - 创建GCM参数规范(带偏移)`, {
            tag: hookInstance.hookName,
            data: gcmData
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor2.call(this, tLen, src, offset, len);
        }
      };

      // Hook getTLen() 方法 - 直接检查方法是否存在
      try {
        if (GCMParameterSpec.getTLen && GCMParameterSpec.getTLen.overload) {
          const getTLenMethod = GCMParameterSpec.getTLen.overload();
          getTLenMethod.implementation = function() {
            const methodTag = `${hookInstance.hookName}.getTLen`;

            try {
              const result = getTLenMethod.call(this);

              Logger.info(`${methodTag} 调用 - 获取GCM标签长度`, {
                tag: hookInstance.hookName,
                data: { tagLength: result }
              });
              HookUtils.captureStack(methodTag);

              return result;
            } catch (e) {
              Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
                tag: hookInstance.hookName,
                error: e
              });
              return getTLenMethod.call(this);
            }
          };
          Logger.info('GCMParameterSpec.getTLen Hook 设置成功', { tag: this.hookName });
        } else {
          Logger.warn('GCMParameterSpec.getTLen 方法不存在，跳过Hook', { tag: this.hookName });
        }
      } catch (e) {
        Logger.warn(`GCMParameterSpec.getTLen Hook跳过: ${e.message}`, { tag: this.hookName });
      }

      // Hook getIV() 方法 - 直接检查方法是否存在
      try {
        if (GCMParameterSpec.getIV && GCMParameterSpec.getIV.overload) {
          const getIVMethod = GCMParameterSpec.getIV.overload();
          getIVMethod.implementation = function() {
            const methodTag = `${hookInstance.hookName}.getIV`;

            try {
              const result = getIVMethod.call(this);

              const ivData = {
                ivLength: result ? result.length : 0,
                iv: result ? {
                  hex: HookUtils.bytesToHex(result),
                  base64: FormatUtils.bytesToBase64(result)
                } : null
              };

              Logger.info(`${methodTag} 调用 - 获取GCM IV`, {
                tag: hookInstance.hookName,
                data: ivData
              });
              HookUtils.captureStack(methodTag);

              return result;
            } catch (e) {
              Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
                tag: hookInstance.hookName,
                error: e
              });
              return getIVMethod.call(this);
            }
          };
          Logger.info('GCMParameterSpec.getIV Hook 设置成功', { tag: this.hookName });
        } else {
          Logger.warn('GCMParameterSpec.getIV 方法不存在，跳过Hook', { tag: this.hookName });
        }
      } catch (e) {
        Logger.warn(`GCMParameterSpec.getIV Hook跳过: ${e.message}`, { tag: this.hookName });
      }

      Logger.info('GCMParameterSpec Hook 设置成功', { tag: this.hookName });
    } catch (e) {
      Logger.error(`GCMParameterSpec Hook 设置失败: ${e.message}`, { tag: this.hookName, error: e });
    }
  }
}







class HMACKeyGeneratorHook extends BaseHook {
  constructor() {
    super('javax.crypto.KeyGenerator', 'HMACKeyGenerator', 'hash.hmac');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('HMAC KeyGenerator Hook 启动');
    this.hookGetInstance();
    this.hookInit();
    this.hookGenerateKey();
    Logger.info('HMAC KeyGenerator Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook KeyGenerator.getInstance() 方法
   */
  hookGetInstance() {
    // Hook getInstance(String algorithm) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const result = originalCall();

      // 只记录HMAC相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('HMAC')) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器获取`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录HMAC相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('HMAC')) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器获取(带提供者)`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String algorithm, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const algorithm = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录HMAC相关的调用
      if (algorithm && algorithm.toString().toUpperCase().includes('HMAC')) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器获取(带Provider对象)`, {
          tag: this.hookName,
          data: {
            algorithm: algorithm.toString(),
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook KeyGenerator.init() 方法
   */
  hookInit() {
    // Hook init(int keysize) 方法
    this.hookMethod('init', ['int'], (methodTag, args, originalCall, javaThis) => {
      const keysize = args[0];
      const result = originalCall();

      // 检查是否为HMAC密钥生成器
      if (this.isHMACKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器初始化`, {
          tag: this.hookName,
          data: {
            algorithm: this.getAlgorithmName(javaThis),
            keySize: keysize,
            method: 'init(int)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int keysize, SecureRandom random) 方法
    this.hookMethod('init', ['int', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const keysize = args[0];
      const random = args[1];
      const result = originalCall();

      // 检查是否为HMAC密钥生成器
      if (this.isHMACKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器初始化(带随机数)`, {
          tag: this.hookName,
          data: {
            algorithm: this.getAlgorithmName(javaThis),
            keySize: keysize,
            secureRandom: random ? random.toString() : 'null',
            method: 'init(int, SecureRandom)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(AlgorithmParameterSpec params) 方法
    this.hookMethod('init', ['java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall, javaThis) => {
      const params = args[0];
      const result = originalCall();

      // 检查是否为HMAC密钥生成器
      if (this.isHMACKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器初始化(带参数)`, {
          tag: this.hookName,
          data: {
            algorithm: this.getAlgorithmName(javaThis),
            params: params ? params.toString() : 'null',
            paramsClass: params ? params.getClass().getName() : 'null',
            method: 'init(AlgorithmParameterSpec)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(AlgorithmParameterSpec params, SecureRandom random) 方法
    this.hookMethod('init', ['java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom'], (methodTag, args, originalCall, javaThis) => {
      const params = args[0];
      const random = args[1];
      const result = originalCall();

      // 检查是否为HMAC密钥生成器
      if (this.isHMACKeyGenerator(javaThis)) {
        Logger.info(`${methodTag} 调用 - HMAC密钥生成器初始化(完整参数)`, {
          tag: this.hookName,
          data: {
            algorithm: this.getAlgorithmName(javaThis),
            params: params ? params.toString() : 'null',
            paramsClass: params ? params.getClass().getName() : 'null',
            secureRandom: random ? random.toString() : 'null',
            method: 'init(AlgorithmParameterSpec, SecureRandom)'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook KeyGenerator.generateKey() 方法
   */
  hookGenerateKey() {
    this.hookMethod('generateKey', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      // 检查是否为HMAC密钥生成器
      if (this.isHMACKeyGenerator(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(result, 'HMAC Generated Key');

        Logger.info(`${methodTag} 调用 - 生成HMAC密钥`, {
          tag: this.hookName,
          data: {
            algorithm: this.getAlgorithmName(javaThis),
            generatedKey: keyInfo,
            method: 'generateKey()'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * 检查KeyGenerator实例是否为HMAC算法
   * @param {Object} keyGenInstance Java KeyGenerator实例
   * @returns {boolean} 是否为HMAC算法
   */
  isHMACKeyGenerator(keyGenInstance) {
    try {
      if (!keyGenInstance) return false;

      // 尝试获取算法名称
      const algorithm = keyGenInstance.getAlgorithm ? keyGenInstance.getAlgorithm() : null;
      if (algorithm) {
        const algStr = algorithm.toString().toUpperCase();
        return algStr.includes('HMAC');
      }

      return false;
    } catch (e) {
      return false;
    }
  }

  /**
   * 获取算法名称
   * @param {Object} keyGenInstance Java KeyGenerator实例
   * @returns {string} 算法名称
   */
  getAlgorithmName(keyGenInstance) {
    try {
      if (!keyGenInstance) return 'HMAC';

      const algorithm = keyGenInstance.getAlgorithm ? keyGenInstance.getAlgorithm() : null;
      return algorithm ? algorithm.toString() : 'HMAC';
    } catch (e) {
      return 'HMAC';
    }
  }
}

class HMACHook extends BaseHook {
  constructor() {
    super('javax.crypto.Mac', 'HMACHook', 'hash.hmac');

    // 支持的HMAC算法映射表
    this.supportedAlgorithms = {
      'HMACMD5': 'hmac',
      'HMAC-MD5': 'hmac',
      'HMACSHA1': 'hmac',
      'HMAC-SHA1': 'hmac',
      'HMACSHA256': 'hmac',
      'HMAC-SHA256': 'hmac',
      'HMACSHA384': 'hmac',
      'HMAC-SHA384': 'hmac',
      'HMACSHA512': 'hmac',
      'HMAC-SHA512': 'hmac'
    };
  }

  /**
   * 启动 HMAC Hook
   */
  start() {
    if (!this.initJavaClass()) return;

    Logger.separator('HMAC Hook 启动');

    // Hook getInstance 方法
    this.hookGetInstance();

    // Hook init 方法
    this.hookInit();

    // Hook update 方法
    this.hookUpdate();

    // Hook doFinal 方法
    this.hookDoFinal();

    Logger.info('HMAC Hook 启动完成 (支持 HMAC-MD5, HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)', { tag: this.hookName });
  }

  /**
   * 检查特定算法是否启用
   * @param {string} algorithm 算法名称
   * @returns {boolean} 是否启用
   */
  isAlgorithmEnabled(algorithm) {
    const normalizedAlg = algorithm.toUpperCase().replace(/[-_]/g, '');
    const configKey = this.supportedAlgorithms[normalizedAlg];
    if (!configKey) return false;

    return CONFIG.hook.hash.hmac === true;
  }

  /**
   * Hook Mac.getInstance() 方法
   */
  hookGetInstance() {
    try {
      const hookInstance = this;

      // Hook getInstance(String algorithm) 方法
      const getInstance1 = this.javaClass.getInstance.overload('java.lang.String');
      getInstance1.implementation = function(algorithm) {
        const methodTag = `${hookInstance.hookName}.getInstance(String)`;

        try {
          // 调用原始方法
          const result = getInstance1.call(this, algorithm);

          // 检查是否为支持的HMAC算法且已启用
          if (algorithm && hookInstance.isAlgorithmEnabled(algorithm.toString())) {
            Logger.info(`${methodTag} 调用`, {
              tag: hookInstance.hookName,
              data: {
                algorithm: algorithm.toString(),
                result: result ? result.toString() : 'null'
              }
            });

            // 捕获调用堆栈
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return getInstance1.call(this, algorithm);
        }
      };

      // Hook getInstance(String algorithm, String provider) 方法
      const getInstance2 = this.javaClass.getInstance.overload('java.lang.String', 'java.lang.String');
      getInstance2.implementation = function(algorithm, provider) {
        const methodTag = `${hookInstance.hookName}.getInstance(String,String)`;

        try {
          // 调用原始方法
          const result = getInstance2.call(this, algorithm, provider);

          // 检查是否为支持的HMAC算法且已启用
          if (algorithm && hookInstance.isAlgorithmEnabled(algorithm.toString())) {
            Logger.info(`${methodTag} 调用`, {
              tag: hookInstance.hookName,
              data: {
                algorithm: algorithm.toString(),
                provider: provider ? provider.toString() : 'null',
                result: result ? result.toString() : 'null'
              }
            });

            // 捕获调用堆栈
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return getInstance2.call(this, algorithm, provider);
        }
      };

      // Hook getInstance(String algorithm, Provider provider) 方法
      const getInstance3 = this.javaClass.getInstance.overload('java.lang.String', 'java.security.Provider');
      getInstance3.implementation = function(algorithm, provider) {
        const methodTag = `${hookInstance.hookName}.getInstance(String,Provider)`;

        try {
          // 调用原始方法
          const result = getInstance3.call(this, algorithm, provider);

          // 检查是否为支持的HMAC算法且已启用
          if (algorithm && hookInstance.isAlgorithmEnabled(algorithm.toString())) {
            Logger.info(`${methodTag} 调用`, {
              tag: hookInstance.hookName,
              data: {
                algorithm: algorithm.toString(),
                provider: provider ? provider.toString() : 'null',
                result: result ? result.toString() : 'null'
              }
            });

            // 捕获调用堆栈
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          // 发生异常时仍调用原始方法
          return getInstance3.call(this, algorithm, provider);
        }
      };

      Logger.info(`${this.hookName}.getInstance Hook 设置成功 (3个重载版本)`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.getInstance Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }

  /**
   * Hook Mac.init() 方法
   */
  hookInit() {
    // Hook init(Key key) 方法
    this.hookMethod('init', ['java.security.Key'], (methodTag, args, originalCall, javaThis) => {
      const key = args[0];
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          const keyInfo = FormatUtils.extractKeyInfo(key, 'HMAC Key');

          const formattedOutput = this.createFormattedOutput(algorithm, null, null, {
            method: 'init',
            key: keyInfo
          });

          Logger.info(`${methodTag} 调用 - HMAC初始化`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });

    // Hook init(Key key, AlgorithmParameterSpec params) 方法
    this.hookMethod('init', ['java.security.Key', 'java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall, javaThis) => {
      const key = args[0];
      const params = args[1];
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          const keyInfo = FormatUtils.extractKeyInfo(key, 'HMAC Key');

          const formattedOutput = this.createFormattedOutput(algorithm, null, null, {
            method: 'init',
            key: keyInfo,
            params: params ? params.toString() : 'null',
            paramsClass: params ? params.getClass().getName() : 'null'
          });

          Logger.info(`${methodTag} 调用 - HMAC初始化(带参数)`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });
  }

  /**
   * Hook Mac.update() 方法
   */
  hookUpdate() {
    // Hook update(byte[] input) 方法
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          const formattedOutput = this.createFormattedOutput(algorithm, input, null, {
            method: 'update',
            inputLength: input ? input.length : 0
          });

          Logger.info(`${methodTag} 调用 - HMAC更新数据`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });

    // Hook update(byte[] input, int offset, int len) 方法
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const offset = args[1];
      const len = args[2];
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          const formattedOutput = this.createFormattedOutput(algorithm, input, null, {
            method: 'update',
            inputLength: input ? input.length : 0,
            offset: offset,
            length: len
          });

          Logger.info(`${methodTag} 调用 - HMAC更新数据(带偏移)`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });

    // Hook update(ByteBuffer input) 方法
    this.hookMethod('update', ['java.nio.ByteBuffer'], (methodTag, args, originalCall, javaThis) => {
      const inputBB = args[0];
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          let inputData = null;
          let inputLength = 0;

          if (inputBB) {
            try {
              inputLength = inputBB.remaining();
              // 尝试读取ByteBuffer中的数据
              const position = inputBB.position();
              const bytes = Java.array('byte', inputLength);
              inputBB.get(bytes);
              inputBB.position(position); // 恢复位置
              inputData = bytes;
            } catch (e) {
              Logger.warn(`无法读取ByteBuffer数据: ${e.message}`, { tag: this.hookName });
            }
          }

          const formattedOutput = this.createFormattedOutput(algorithm, inputData, null, {
            method: 'update',
            inputType: 'ByteBuffer',
            inputLength: inputLength
          });

          Logger.info(`${methodTag} 调用 - HMAC更新数据(ByteBuffer)`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });
  }

  /**
   * Hook Mac.doFinal() 方法
   */
  hookDoFinal() {
    // Hook doFinal() 方法
    this.hookMethod('doFinal', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          const formattedOutput = this.createFormattedOutput(algorithm, null, result, {
            method: 'doFinal',
            resultLength: result ? result.length : 0
          });

          Logger.info(`${methodTag} 调用 - HMAC计算完成`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });

    // Hook doFinal(byte[] input) 方法
    this.hookMethod('doFinal', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      try {
        // 获取算法名称
        let algorithm = 'HMAC';
        try {
          algorithm = javaThis.getAlgorithm().toString();
        } catch (e) {
          algorithm = 'HMAC';
        }

        // 检查是否为支持的HMAC算法且已启用
        if (this.isAlgorithmEnabled(algorithm)) {
          const formattedOutput = this.createFormattedOutput(algorithm, input, result, {
            method: 'doFinal',
            inputLength: input ? input.length : 0,
            resultLength: result ? result.length : 0
          });

          Logger.info(`${methodTag} 调用 - HMAC计算完成(带输入)`, {
            tag: this.hookName,
            data: formattedOutput
          });
          HookUtils.captureStack(methodTag);
        }
      } catch (e) {
        Logger.error(`${methodTag} Hook处理异常: ${e.message}`, {
          tag: this.hookName,
          error: e
        });
      }

      return result;
    });
  }
}












class DESKeySpecHook extends BaseHook {
  constructor() {
    super('javax.crypto.spec.DESKeySpec', 'DESKeySpec', 'symmetricCrypto.des');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('DESKeySpec Hook 启动');
    this.hookConstructors();
    this.hookMethods();
    Logger.info('DESKeySpec Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook DESKeySpec 构造函数
   */
  hookConstructors() {
    // Hook DESKeySpec(byte[] key) 构造函数
    this.hookMethod('$init', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const keyBytes = args[0];
      const result = originalCall();

      if (keyBytes) {
        const keyData = {
          algorithm: 'DES',
          keyLength: keyBytes.length,
          encoded: {
            hex: HookUtils.bytesToHex(keyBytes),
            base64: FormatUtils.bytesToBase64(keyBytes),
            string: FormatUtils.bytesToString(keyBytes),
            ascii: FormatUtils.bytesToAscii(keyBytes),
            utf8: FormatUtils.bytesToUtf8(keyBytes),
            raw: keyBytes
          }
        };

        Logger.info(`${methodTag} 调用 - DES密钥规范创建`, {
          tag: this.hookName,
          data: {
            method: 'constructor',
            keyData: keyData,
            instance: javaThis ? javaThis.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook DESKeySpec(byte[] key, int offset) 构造函数
    this.hookMethod('$init', ['[B', 'int'], (methodTag, args, originalCall, javaThis) => {
      const keyBytes = args[0];
      const offset = args[1];
      const result = originalCall();

      if (keyBytes) {
        // 提取从offset开始的8字节作为DES密钥
        const actualKeyBytes = keyBytes.slice(offset, offset + 8);

        const keyData = {
          algorithm: 'DES',
          keyLength: actualKeyBytes.length,
          offset: offset,
          totalLength: keyBytes.length,
          encoded: {
            hex: HookUtils.bytesToHex(actualKeyBytes),
            base64: FormatUtils.bytesToBase64(actualKeyBytes),
            string: FormatUtils.bytesToString(actualKeyBytes),
            ascii: FormatUtils.bytesToAscii(actualKeyBytes),
            utf8: FormatUtils.bytesToUtf8(actualKeyBytes),
            raw: actualKeyBytes
          }
        };

        Logger.info(`${methodTag} 调用 - DES密钥规范创建(带偏移)`, {
          tag: this.hookName,
          data: {
            method: 'constructor',
            keyData: keyData,
            instance: javaThis ? javaThis.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook DESKeySpec 方法
   */
  hookMethods() {
    // Hook getKey() 方法
    this.hookMethod('getKey', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      if (result) {
        const keyData = {
          algorithm: 'DES',
          keyLength: result.length,
          encoded: {
            hex: HookUtils.bytesToHex(result),
            base64: FormatUtils.bytesToBase64(result),
            string: FormatUtils.bytesToString(result),
            ascii: FormatUtils.bytesToAscii(result),
            utf8: FormatUtils.bytesToUtf8(result),
            raw: result
          }
        };

        Logger.info(`${methodTag} 调用 - 获取DES密钥`, {
          tag: this.hookName,
          data: {
            method: 'getKey',
            keyData: keyData,
            instance: javaThis ? javaThis.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook isWeak(byte[] key, int offset) 静态方法
    this.hookMethod('isWeak', ['[B', 'int'], (methodTag, args, originalCall) => {
      const keyBytes = args[0];
      const offset = args[1];
      const result = originalCall();

      if (keyBytes) {
        const actualKeyBytes = keyBytes.slice(offset, offset + 8);

        Logger.info(`${methodTag} 调用 - 检查DES弱密钥`, {
          tag: this.hookName,
          data: {
            method: 'isWeak',
            keyLength: actualKeyBytes.length,
            offset: offset,
            isWeak: result,
            keyHex: HookUtils.bytesToHex(actualKeyBytes)
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }
}


class CRC32Hook extends BaseHook {
  constructor() {
    super('java.util.zip.CRC32', 'CRC32Hook', 'hash.crc32');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('CRC32 Hook 启动');
    this.hookConstructor();
    this.hookUpdate();
    this.hookGetValue();
    this.hookReset();
    Logger.info('CRC32 Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook CRC32 构造函数
   */
  hookConstructor() {
    try {
      const hookInstance = this;

      // Hook CRC32() 无参构造函数
      const constructor1 = this.javaClass.$init.overload();
      constructor1.implementation = function() {
        const methodTag = `${hookInstance.hookName}.CRC32()`;

        try {
          const result = constructor1.call(this);

          Logger.info(`${methodTag} 调用 - CRC32实例创建`, {
            tag: hookInstance.hookName,
            data: {
              method: 'constructor',
              instance: this ? this.toString() : 'null'
            }
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return constructor1.call(this);
        }
      };

      Logger.info(`${this.hookName}.constructor Hook 设置成功`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.constructor Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }

  /**
   * Hook CRC32 update 方法
   */
  hookUpdate() {
    try {
      const hookInstance = this;

      // Hook update(int b) 方法
      const update1 = this.javaClass.update.overload('int');
      update1.implementation = function(b) {
        const methodTag = `${hookInstance.hookName}.update(int)`;

        try {
          const result = update1.call(this, b);

          Logger.info(`${methodTag} 调用 - 更新单字节`, {
            tag: hookInstance.hookName,
            data: {
              method: 'update',
              input: {
                byte: b,
                hex: '0x' + b.toString(16).padStart(2, '0')
              },
              instance: this ? this.toString() : 'null'
            }
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return update1.call(this, b);
        }
      };

      // Hook update(byte[] b) 方法
      const update2 = this.javaClass.update.overload('[B');
      update2.implementation = function(b) {
        const methodTag = `${hookInstance.hookName}.update(byte[])`;

        try {
          const result = update2.call(this, b);

          if (b) {
            const inputData = {
              length: b.length,
              hex: HookUtils.bytesToHex(b),
              base64: FormatUtils.bytesToBase64(b),
              string: FormatUtils.bytesToUtf8(b),
              ascii: FormatUtils.bytesToAscii(b),
              utf8: FormatUtils.bytesToUtf8(b),
              raw: FormatUtils.bytesToRaw(b)
            };

            Logger.info(`${methodTag} 调用 - 更新字节数组`, {
              tag: hookInstance.hookName,
              data: {
                method: 'update',
                input: inputData,
                instance: this ? this.toString() : 'null'
              }
            });
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return update2.call(this, b);
        }
      };

      // Hook update(byte[] b, int off, int len) 方法
      const update3 = this.javaClass.update.overload('[B', 'int', 'int');
      update3.implementation = function(b, off, len) {
        const methodTag = `${hookInstance.hookName}.update(byte[],int,int)`;

        try {
          const result = update3.call(this, b, off, len);

          if (b && len > 0) {
            // 从 Java 字节数组中提取指定范围的字节
            const actualBytes = [];
            for (let i = 0; i < len; i++) {
              actualBytes.push(b[off + i]);
            }

            const inputData = {
              totalLength: b.length,
              offset: off,
              length: len,
              hex: HookUtils.bytesToHex(actualBytes),
              base64: FormatUtils.bytesToBase64(actualBytes),
              string: FormatUtils.bytesToUtf8(actualBytes),
              ascii: FormatUtils.bytesToAscii(actualBytes),
              utf8: FormatUtils.bytesToUtf8(actualBytes),
              raw: FormatUtils.bytesToRaw(actualBytes)
            };

            Logger.info(`${methodTag} 调用 - 更新字节数组片段`, {
              tag: hookInstance.hookName,
              data: {
                method: 'update',
                input: inputData,
                instance: this ? this.toString() : 'null'
              }
            });
            HookUtils.captureStack(methodTag);
          }

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return update3.call(this, b, off, len);
        }
      };

      Logger.info(`${this.hookName}.update Hook 设置成功 (3个重载版本)`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.update Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }

  /**
   * Hook CRC32 getValue 方法
   */
  hookGetValue() {
    try {
      const hookInstance = this;

      const getValue = this.javaClass.getValue;
      getValue.implementation = function() {
        const methodTag = `${hookInstance.hookName}.getValue()`;

        try {
          const result = getValue.call(this);

          // 安全地转换CRC32值为不同格式
          const crc32Value = result.longValue ? result.longValue() : result;
          const resultData = {
            crc32Value: crc32Value,
            hex: '0x' + (crc32Value >>> 0).toString(16).toUpperCase().padStart(8, '0'),
            decimal: crc32Value.toString(),
            binary: (crc32Value >>> 0).toString(2).padStart(32, '0')
          };

          Logger.info(`${methodTag} 调用 - 获取CRC32值`, {
            tag: hookInstance.hookName,
            data: {
              method: 'getValue',
              result: resultData,
              instance: this ? this.toString() : 'null'
            }
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return getValue.call(this);
        }
      };

      Logger.info(`${this.hookName}.getValue Hook 设置成功`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.getValue Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }

  /**
   * Hook CRC32 reset 方法
   */
  hookReset() {
    try {
      const hookInstance = this;

      const reset = this.javaClass.reset;
      reset.implementation = function() {
        const methodTag = `${hookInstance.hookName}.reset()`;

        try {
          const result = reset.call(this);

          Logger.info(`${methodTag} 调用 - 重置CRC32`, {
            tag: hookInstance.hookName,
            data: {
              method: 'reset',
              instance: this ? this.toString() : 'null'
            }
          });
          HookUtils.captureStack(methodTag);

          return result;
        } catch (e) {
          Logger.error(`${methodTag} Hook执行异常: ${e.message}`, {
            tag: hookInstance.hookName,
            error: e
          });
          return reset.call(this);
        }
      };

      Logger.info(`${this.hookName}.reset Hook 设置成功`, { tag: this.hookName });
    } catch (e) {
      Logger.error(`${this.hookName}.reset Hook 设置失败: ${e.message}`, {
        tag: this.hookName,
        error: e
      });
    }
  }
}


class ChaCha20Hook extends BaseHook {
  constructor() {
    super('javax.crypto.Cipher', 'ChaCha20', 'symmetricCrypto.chacha');
  }

  start() {
    if (!this.initJavaClass()) return;
    Logger.separator('ChaCha20 Hook 启动');
    this.hookGetInstance();
    this.hookInit();
    this.hookUpdate();
    this.hookDoFinal();
    Logger.info('ChaCha20 Hook 启动完成', { tag: this.hookName });
  }

  /**
   * Hook Cipher.getInstance() 方法
   */
  hookGetInstance() {
    // Hook getInstance(String transformation) 方法
    this.hookMethod('getInstance', ['java.lang.String'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const result = originalCall();

      // 只记录ChaCha20相关的调用
      if (transformation && this.isChaChaTransformation(transformation.toString())) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'ChaCha20',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String transformation, String provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.lang.String'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录ChaCha20相关的调用
      if (transformation && this.isChaChaTransformation(transformation.toString())) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'ChaCha20',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook getInstance(String transformation, Provider provider) 方法
    this.hookMethod('getInstance', ['java.lang.String', 'java.security.Provider'], (methodTag, args, originalCall) => {
      const transformation = args[0];
      const provider = args[1];
      const result = originalCall();

      // 只记录ChaCha20相关的调用
      if (transformation && this.isChaChaTransformation(transformation.toString())) {
        const transformationStr = transformation.toString();
        const parts = transformationStr.split('/');

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: {
            transformation: transformationStr,
            algorithm: parts[0] || 'ChaCha20',
            mode: parts[1] || 'Unknown',
            padding: parts[2] || 'Unknown',
            provider: provider ? provider.toString() : 'null',
            result: result ? result.toString() : 'null'
          }
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.init() 方法
   */
  hookInit() {
    // Hook init(int opmode, Key key) 方法
    this.hookMethod('init', ['int', 'java.security.Key'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const result = originalCall();

      // 检查是否为ChaCha20算法
      if (this.isChaCha20Cipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'ChaCha20 Key');
        const modeStr = this.getOperationMode(opmode);

        const formattedOutput = this.createFormattedOutput('ChaCha20', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          transformation: this.getTransformation(javaThis),
          keyInfo: keyInfo
        });

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook init(int opmode, Key key, AlgorithmParameterSpec params) 方法
    this.hookMethod('init', ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'], (methodTag, args, originalCall, javaThis) => {
      const opmode = args[0];
      const key = args[1];
      const params = args[2];
      const result = originalCall();

      // 检查是否为ChaCha20算法
      if (this.isChaCha20Cipher(javaThis)) {
        const keyInfo = FormatUtils.extractKeyInfo(key, 'ChaCha20 Key');
        const modeStr = this.getOperationMode(opmode);
        const paramInfo = this.extractAlgorithmParams(params);

        const formattedOutput = this.createFormattedOutput('ChaCha20', null, null, {
          method: 'init',
          operationMode: modeStr,
          operationModeValue: opmode,
          transformation: this.getTransformation(javaThis),
          keyInfo: keyInfo,
          algorithmParams: paramInfo
        });

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.update() 方法
   */
  hookUpdate() {
    // Hook update(byte[] input) 方法
    this.hookMethod('update', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      // 检查是否为ChaCha20算法
      if (this.isChaCha20Cipher(javaThis) && input) {
        const inputData = this.formatData(input, 'ChaCha20 输入数据');
        const outputData = result ? this.formatData(result, 'ChaCha20 输出数据') : null;

        const formattedOutput = this.createFormattedOutput('ChaCha20', inputData, outputData, {
          method: 'update',
          inputLength: input.length,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook update(byte[] input, int inputOffset, int inputLen) 方法
    this.hookMethod('update', ['[B', 'int', 'int'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const inputOffset = args[1];
      const inputLen = args[2];
      const result = originalCall();

      // 检查是否为ChaCha20算法
      if (this.isChaCha20Cipher(javaThis) && input) {
        // 提取实际处理的数据
        const actualInput = Java.array('byte', inputLen);
        for (let i = 0; i < inputLen; i++) {
          actualInput[i] = input[inputOffset + i];
        }

        const inputData = this.formatData(actualInput, 'ChaCha20 输入数据');
        const outputData = result ? this.formatData(result, 'ChaCha20 输出数据') : null;

        const formattedOutput = this.createFormattedOutput('ChaCha20', inputData, outputData, {
          method: 'update',
          inputOffset: inputOffset,
          inputLength: inputLen,
          totalInputLength: input.length,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * Hook Cipher.doFinal() 方法
   */
  hookDoFinal() {
    // Hook doFinal() 方法
    this.hookMethod('doFinal', [], (methodTag, args, originalCall, javaThis) => {
      const result = originalCall();

      // 检查是否为ChaCha20算法
      if (this.isChaCha20Cipher(javaThis)) {
        const outputData = result ? this.formatData(result, 'ChaCha20 最终输出') : null;

        const formattedOutput = this.createFormattedOutput('ChaCha20', null, outputData, {
          method: 'doFinal',
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });

    // Hook doFinal(byte[] input) 方法
    this.hookMethod('doFinal', ['[B'], (methodTag, args, originalCall, javaThis) => {
      const input = args[0];
      const result = originalCall();

      // 检查是否为ChaCha20算法
      if (this.isChaCha20Cipher(javaThis)) {
        const formattedOutput = this.createFormattedOutput('ChaCha20', input, result, {
          method: 'doFinal',
          inputLength: input ? input.length : 0,
          outputLength: result ? result.length : 0,
          transformation: this.getTransformation(javaThis)
        });

        Logger.info(`${methodTag} 调用`, {
          tag: this.hookName,
          data: formattedOutput
        });
        HookUtils.captureStack(methodTag);
      }

      return result;
    });
  }

  /**
   * 检查是否为ChaCha20算法的Cipher实例
   */
  isChaCha20Cipher(cipherInstance) {
    if (!cipherInstance) return false;

    try {
      const transformation = this.getTransformation(cipherInstance);
      return this.isChaChaTransformation(transformation);
    } catch (e) {
      return false;
    }
  }

  /**
   * 检查transformation字符串是否与ChaCha20相关
   */
  isChaChaTransformation(transformation) {
    if (!transformation) return false;

    const upperTransformation = transformation.toUpperCase();
    return upperTransformation.includes('CHACHA20') ||
           upperTransformation.includes('CHACHA') ||
           upperTransformation.includes('CHACHA20-POLY1305');
  }

  /**
   * 获取Cipher实例的transformation信息
   */
  getTransformation(cipherInstance) {
    try {
      if (cipherInstance && cipherInstance.getAlgorithm) {
        return cipherInstance.getAlgorithm().toString();
      }
      return 'Unknown';
    } catch (e) {
      return 'Unknown';
    }
  }

  /**
   * 获取操作模式字符串
   */
  getOperationMode(opmode) {
    const modes = {
      1: 'ENCRYPT_MODE',
      2: 'DECRYPT_MODE',
      3: 'WRAP_MODE',
      4: 'UNWRAP_MODE'
    };
    return modes[opmode] || `Unknown(${opmode})`;
  }

  /**
   * 提取算法参数信息
   */
  extractAlgorithmParams(params) {
    if (!params) return null;

    try {
      const paramInfo = {
        type: params.getClass().getName(),
        toString: params.toString()
      };

      // 尝试提取ChaCha20ParameterSpec的特定信息
      if (params.getClass().getName().includes('ChaCha20ParameterSpec')) {
        try {
          if (params.getNonce) {
            const nonce = params.getNonce();
            paramInfo.nonce = {
              length: nonce.length,
              hex: HookUtils.bytesToHex(nonce),
              base64: FormatUtils.bytesToBase64(nonce)
            };
          }
          if (params.getCounter) {
            paramInfo.counter = params.getCounter();
          }
        } catch (e) {
          paramInfo.extractError = e.toString();
        }
      }

      return paramInfo;
    } catch (e) {
      return { error: e.toString() };
    }
  }
}


Java.perform(function() {
  Logger.separator('Frida Hook 启动', '═', 100);
  Logger.info('开始初始化 Hook 模块...', { tag: 'Main' });

  try {

    // 创建并启动 Hash Hook (支持 MD5/SHA 系列)
    const hashHook = new HashHook();
    hashHook.start();

    // 创建并启动 HMAC Hook (支持 HMAC 系列)
    const hmacHook = new HMACHook();
    hmacHook.start();

    // 创建并启动 HMAC 密钥生成器 Hook
    const hmacKeyGeneratorHook = new HMACKeyGeneratorHook();
    hmacKeyGeneratorHook.start();

    // 创建并启动 RSA Hooks
    const rsaCipherHook = new RSACipherHook();
    rsaCipherHook.start();

    const rsaSignatureHook = new RSASignatureHook();
    rsaSignatureHook.start();

    const rsaKeyPairHook = new RSAKeyPairHook();
    rsaKeyPairHook.start();

    // 创建并启动 RSA 密钥规范 Hooks
    const rsaKeySpecHook = new RSAKeySpecHook();
    rsaKeySpecHook.start();

    const rsaKeyFactoryHook = new RSAKeyFactoryHook();
    rsaKeyFactoryHook.start();

    // 创建并启动 AES Hooks
    const aesCipherHook = new AESCipherHook();
    aesCipherHook.start();

    const aesKeyGeneratorHook = new AESKeyGeneratorHook();
    aesKeyGeneratorHook.start();

    const aesKeySpecHook = new AESKeySpecHook();
    aesKeySpecHook.start();

    const aesIvParameterSpecHook = new AESIvParameterSpecHook();
    aesIvParameterSpecHook.start();

    // 创建并启动 DES Hooks
    const desCipherHook = new DESCipherHook();
    desCipherHook.start();

    const desKeyGeneratorHook = new DESKeyGeneratorHook();
    desKeyGeneratorHook.start();

    const desKeySpecHook = new DESKeySpecHook();
    desKeySpecHook.start();

    // 创建并启动 ChaCha20 Hook
    const chachaHook = new ChaCha20Hook();
    chachaHook.start();

    // 创建并启动 CRC32 Hook
    const crc32Hook = new CRC32Hook();
    crc32Hook.start();

    Logger.separator('Hook 初始化完成', '═', 100);
    Logger.info('所有 Hook 模块已成功启动 (包含 Hash(MD5/SHA系列)、HMAC、RSA、AES、DES、ChaCha20、CRC32 算法)', { tag: 'Main' });
    Logger.info('配置信息:', {
      tag: 'Main',
      data: {
        enableJsonFormat: CONFIG.output.enableJsonFormat,
        showRawFormat: CONFIG.output.showRawFormat,
        enabledFormats: CONFIG.output.enabledFormats,
        outputFields: CONFIG.output.fields
      }
    });
  } catch (e) {
    Logger.error('Hook 初始化失败', { tag: 'Main', error: e });
  }
});