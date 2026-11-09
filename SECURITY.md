# Security Policy

## Reporting a Vulnerability

flock-protocol 是加密协议库，安全报告优先于一切普通 issue。

**请勿通过公开 issue、PR、讨论区或任何公开渠道报告安全漏洞。**

请使用 GitHub 私有漏洞报告渠道：

1. 打开本仓库页面，进入 **Security** 标签页；
2. 选择 **Report a vulnerability**（私有漏洞报告）；
3. 按模板描述：受影响版本、攻击前提、影响面、复现步骤（如有 PoV 请附在报告内，
   报告本身非公开）。

GitHub 私有漏洞报告通道说明：<https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability>

如该渠道不可用（例如仓库尚未启用），可联系维护者邮箱（见仓库 About 或 README），
邮件主题前缀 `[security]`。

### 期望的响应节奏

- **确认收到**：3 个工作日内；
- **初步评估**（是否接受、影响面定级）：7 个工作日内；
- **修复与公告**：按严重度排期，修复随常规版本发布，同步发布
  GitHub Security Advisory（CVE 编号按需申请）。

请给予我们合理的修复窗口后再公开细节；我们承诺对善意报告者不追究
（不诉诸法律手段）。

## 报告范围

- 本 crate（src/、tests/、benches/）中的密码学构造、协议逻辑与实现缺陷；
- 依赖项的已知漏洞波及本 crate 的部分（请同时报告，我们通过常规渠道跟进升级）。

不在范围内：需要物理接触或已控制操作系统的攻击面、理论性无现实前提的攻击、
DoS 类资源耗尽（除非可远程以极小成本触发且影响隧道可用性）。

## 公告渠道

安全修复公告通过 GitHub **Security Advisories** 发布（仓库 Security 标签页），
并同步到对应 release notes。
