# WHITEHAT 04 REPORT - Bug Bountyレポート生成

Ethereum Foundation向けのBug Bountyレポートを生成します。

Usage: `/04_report <vuln_name> <ut_path> <it_path>`
Example: `/04_report keccak1600_init test/crypto/keccak1600/poc_keccak1600_init.cpp test/crypto/keccak1600_init.cpp`

Arguments:
- vuln_name: 脆弱性名 (keccak1600_init)
- ut_path: Unit TestのPoCファイルパス (test/crypto/keccak1600/poc_keccak1600_init.cpp)
- it_path: Integration TestのPoCファイルパス (test/crypto/keccak1600_init.cpp)

---

<% 
// Parse arguments with support for quoted strings
const args = input.trim().match(/(?:[^\s"]+|"[^"]*")+/g);
const vulnName = args[0];
const pocTestFile = args[1];

// Read the original prompt content
const fs = require('fs');
const promptContent = fs.readFileSync('prompts/whitehat/04_REPORT.md', 'utf8');

// Replace template variables
const processedContent = promptContent
  .replace(/\{\{VULN_NAME\}\}/g, vulnName)
  .replace(/\{\{POC_TEST_FILE\}\}/g, pocTestFile)

%>

<%= processedContent %>
