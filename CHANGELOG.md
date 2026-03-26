# Changelog

All notable changes to this project will be documented in this file.

## [v1.1.0] - 2026-03-26

### ✨ New Features

#### 🔍 SSTI 模块集成
- **Fenjing**: Flask/Jinja2 SSTI漏洞利用工具，CTF专用
  - 支持 scan、crack、crack-path、crack-json、crack-request 模式
  - 支持多种模板环境：flask、jinja2、tornado、django
  - 支持自定义命令执行和编码绕过
  - 支持 GET/POST 请求方法
  - 支持 accurate/fast 检测模式

- **SSTImap**: 服务端模板注入(SSTI)检测与利用工具
  - 支持多种模板引擎自动检测
  - 支持 OS Shell、交互模式、命令执行
  - 支持多种注入技术：渲染(R)、错误(E)、布尔盲注(B)、时间盲注(T)
  - 支持 1-5 级检测深度
  - 支持随机 User-Agent 和 SSL 验证

### 🔧 Tool Manager Enhancement
- 新增 `python_module` 工具类型支持
- 支持以模块方式运行的 Python 工具 (如 `python -m fenjing`)
- 添加 `_get_tool_info()` 方法获取完整工具信息
- 优化工具配置加载逻辑

### 📝 UI Improvements
- 更新 SSTI 模块 UI，支持工具选择标签页
- 添加 SSTImap 选项配置面板
- 添加 Fenjing 选项配置面板
- 添加高级选项配置（代理、超时、自定义头部、Cookies）
- 优化结果表格显示

### 📦 Tool Files
- 添加 Fenjing 工具完整源码
- 添加 SSTImap 工具完整源码
- 更新工具下载链接配置

---

## [v1.0.1] - 2026-03-07

### 🐛 Bug Fixes

#### 扫描功能修复
- **修复扫描停止功能** 
  - 问题描述：点击停止按钮后无法正常停止扫描，开始按钮没有恢复亮起，设置也无法修改
  - 修复方案：
    - 在基类 `BaseModuleWidget` 中添加 `stop_scan()` 方法
    - 为所有使用 `_worker` (QThread) 的模块添加 `stop_scan()` 方法以正确取消线程
    - 修复 `_on_stop_scan()` 方法，停止后调用 `_scan_finished()` 恢复UI状态
    - 添加 `@pyqtSlot()` 装饰器确保 Qt 信号槽正确工作

- **修复进度条显示问题**
  - 问题描述：进度条一直显示 0%，扫描完成后没有变化
  - 修复方案：
    - 开始扫描时设置进度条为 0%
    - 扫描完成时设置进度条为 100%
    - 最后才隐藏进度条

- **修复结果表格显示问题**
  - 问题描述：扫描完成后结果栏什么都没有显示
  - 修复方案：
    - 修复 `_add_result()` 方法传递正确的结果索引参数
    - 使用 `@pyqtSlot(int)` 装饰器确保线程安全
    - 修复结果表格列数与数据匹配

- **修复工具执行问题**
  - 问题描述：工具管理器无法找到模块对应的工具
  - 修复方案：
    - 修复 `_execute_tool()` 方法中传递 `self.module_id` 而非 `self.module_name`
    - 为所有工具执行添加进程检查，确保进程启动成功

#### UI 显示修复
- **修复通知弹窗文字被遮挡**
  - 问题描述：扫描完成通知弹窗下面那行字被遮挡看不清
  - 修复方案：
    - 宽度从 320px 增加到 380px
    - 最小高度从 80px 增加到 100px
    - 内边距从 10px 增加到 12px
    - 字体大小适当增大

- **修复日志文字太小**
  - 问题描述：日志窗口文字太小看不清
  - 修复方案：
    - 日志字体从默认大小增加到 12pt

### ✨ New Features

#### 🤖 AI 助手模块
- **多模型支持**
  - OpenAI (GPT-4, GPT-3.5)
  - Anthropic Claude
  - DeepSeek
  - 阿里通义千问 (Qwen)
  - 本地模型支持 (Ollama)

- **功能特性**
  - 安全分析：AI驱动的漏洞分析
  - 代码审计：安全代码审查辅助
  - 报告生成：AI辅助报告撰写
  - 对话界面：交互式安全咨询
  - 操作记录：自动记录模块操作历史

#### 🔍 信息收集模块增强
- **端口扫描**
  - 新增 RustScan 支持
  - 新增 Masscan 支持
  - 优化 Nmap 扫描结果解析

- **子域名枚举**
  - 新增 Subdominator 支持
  - 新增 Chaos 支持

- **目录扫描**
  - 新增 Feroxbuster 支持

- **SSL/TLS 分析**
  - 新增 TLSX 工具集成

- **邮箱收集**
  - 新增邮箱枚举和验证模块

#### 🌐 Web 安全模块增强
- **新增漏洞检测模块**
  - SSTI (服务端模板注入)
  - CSRF (跨站请求伪造)
  - API 安全测试
  - 框架漏洞检测
  - 认证漏洞测试
  - 文件漏洞检测
  - 缓存投毒检测
  - HTTP 走私检测
  - 开放重定向检测
  - 点击劫持测试
  - 业务逻辑漏洞检测
  - JWT 安全分析
  - 供应链漏洞扫描
  - 原型污染检测
  - 云安全测试
  - WebSocket 安全测试
  - AI/LLM 应用安全测试

#### 🔒 内网渗透模块增强
- **新增功能**
  - 横向移动工具
  - 域攻击模块 (Active Directory)
  - ADCS 攻击模块
  - 免杀模块
  - Exchange 漏洞利用
  - SharePoint 漏洞测试
  - 权限维持管理
  - 权限提升模块

#### 🛠️ 实用工具
- **新增工具**
  - IP 工具：IP地址分析和计算
  - HTTP 工具：HTTP请求构建和测试
  - JSON 工具：JSON格式化和分析
  - 正则工具：正则表达式测试
  - 时间工具：时间戳转换
  - 对比工具：文本比较

#### 🔧 编码与加密
- **新增功能**
  - Base 编码：Base64、Base32、Base58、Base85
  - URL 编码：URL编码/解码
  - 哈希计算：多种哈希算法
  - JWT 工具：JWT编码/解码/伪造
  - 加密解密：加密/解密工具
  - 古典密码：凯撒、维吉尼亚等

#### 📦 Payload 生成
- **新增功能**
  - Payload 生成器：自定义Payload创建
  - 编码器：Payload编码和混淆
  - 漏洞库：漏洞数据库搜索
  - 反弹Shell：反弹Shell生成器
  - Webshell：Webshell管理
  - MSF Payload：Metasploit Payload生成

#### 📊 报告与项目管理
- **新增功能**
  - 密码生成：自定义字典生成
  - 用户名生成：用户名枚举列表
  - 目录生成：路径字典创建
  - 子域名生成：子域名字典创建
  - 字典管理：字典文件管理
  - 项目管理：项目跟踪管理
  - 数据导出：多种导出格式
  - 漏洞统计：发现结果分析
  - 历史记录：操作历史追踪

### 🔄 Other Changes

#### 性能优化
- 优化线程池管理，扫描停止时正确关闭线程池
- 优化结果处理，使用信号槽机制确保线程安全
- 优化内存使用，及时清理不需要的资源

#### 代码质量
- 添加 `@pyqtSlot()` 装饰器确保 Qt 信号槽正确工作
- 统一异常处理，添加完整的错误日志
- 改进代码结构，提高可维护性

#### 兼容性
- 更新 Python 依赖版本要求
- 优化 Windows 平台兼容性
- 改进工具路径检测逻辑

#### 文档更新
- 更新 README.md 文档，添加所有新功能说明
- 更新版本号为 v1.0.1
- 添加 AI 模块配置说明

---

## [v1.0.0] - 2026-03-01

### Initial Release
- 初始版本发布
- 基础安全工具集成
- GUI 界面实现
- 报告生成功能
