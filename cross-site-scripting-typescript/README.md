# Cross-Site Scripting TypeScript Vulnerable Files - 20 Files

This directory contains 20 TypeScript files with XSS vulnerabilities identified by the `typescript-cross-site-scripting-ide` Semgrep rule.

**Analysis Results:**
- **Total Files:** 20 TypeScript files
- **Total Findings:** 54 XSS vulnerabilities  
- **Unique Files with Vulnerabilities:** 11
- **Severity:** WARNING
- **Detection Rate:** 55% (11 out of 20 files have vulnerabilities)

## Directory Structure

Each subdirectory contains files from a specific GitHub repository:

### 1. ERNICommunity_at11/
- **File:** app.ts
- **Repository:** ERNICommunity/at11
- **Vulnerable Lines:** 70, 72
- **GitHub Link:** https://github.com/ERNICommunity/at11/blob/38d1b8667dbd170c76585959bb69fa7a988c1504/app.ts

### 2. screeny05_letterboxd-list-radarr/
- **File:** index.ts
- **Repository:** screeny05/letterboxd-list-radarr
- **GitHub Link:** https://github.com/screeny05/letterboxd-list-radarr/blob/8c2755289ac756a4ab2a359447d4de19750fbf0b/index.ts

### 3. Treeki_BirdBridge/
- **File:** main.ts
- **Repository:** Treeki/BirdBridge
- **Vulnerable Lines:** 161, 320, 323, 329, 342, 360, 363
- **GitHub Link:** https://github.com/Treeki/BirdBridge/blob/16e96cb0fafec81e331c2b077a35483cfe1b3c4f/main.ts

### 4. csuermann_virtual-smart-home/
- **File:** admin.ts
- **Repository:** csuermann/virtual-smart-home
- **GitHub Link:** https://github.com/csuermann/virtual-smart-home/blob/d0a49bb99b43cee90bcc78560d6ce3053150e196/admin.ts

### 5. benjajaja_qdice/
- **File:** games.ts
- **Repository:** benjajaja/qdice
- **GitHub Link:** https://github.com/benjajaja/qdice/blob/6dcf5c2f4c290f7a61855a4c76faf33b9af01741/games.ts

### 6. DIYgod_RSSHub/
- **File:** lib_routes_cw_utils.ts (original: lib/routes/cw/utils.ts)
- **Repository:** DIYgod/RSSHub
- **GitHub Link:** https://github.com/DIYgod/RSSHub/blob/a7469fe8a0078c48c62964fa5ae07a6c203e4c35/lib/routes/cw/utils.ts

### 7. github_docs/
- **File:** src_frame_middleware_context_generic-toc.ts (original: src/frame/middleware/context/generic-toc.ts)
- **Repository:** github/docs
- **GitHub Link:** https://github.com/github/docs/blob/2f76b6d41ce3647a223e459a6438bc35ffd46dc5/src/frame/middleware/context/generic-toc.ts

### 8. pancakeswap_pancake-frontend/
- **File:** apps_web_src_pages_api_auth_discord-callback.ts (original: apps/web/src/pages/api/auth/discord-callback.ts)
- **Repository:** pancakeswap/pancake-frontend
- **GitHub Link:** https://github.com/pancakeswap/pancake-frontend/blob/b1168532c0d109615d79a4da646e0bf3663d375a/apps/web/src/pages/api/auth/discord-callback.ts

### 9. linfaxin_MBBS/
- **File:** server_routes_index.ts (original: server/routes/index.ts)
- **Repository:** linfaxin/MBBS
- **GitHub Link:** https://github.com/linfaxin/MBBS/blob/e6248c9ee53e479f3c419fcb10e52fc115f91aca/server/routes/index.ts

### 10. thedaviddias_llms-txt-hub/
- **File:** packages_validators_src_validate-security.ts (original: packages/validators/src/validate-security.ts)
- **Repository:** thedaviddias/llms-txt-hub
- **GitHub Link:** https://github.com/thedaviddias/llms-txt-hub/blob/289089562e0d09135690d0da52463e0c98ccdb22/packages/validators/src/validate-security.ts

### 11. kowasp_kowasp/
- **File:** kowasp-core_src_analyzer_ASTAnalyzer.ts (original: kowasp-core/src/analyzer/ASTAnalyzer.ts)
- **Repository:** kowasp/kowasp
- **GitHub Link:** https://github.com/kowasp/kowasp/blob/413f38ddfef0c873ec49937ec236f38fc69a9ae6/kowasp-core/src/analyzer/ASTAnalyzer.ts

### 12. nisalgunawardhana_security-checker-agent/
- **File:** src_security_knowledgeBase.ts (original: src/security/knowledgeBase.ts)
- **Repository:** nisalgunawardhana/security-checker-agent
- **GitHub Link:** https://github.com/nisalgunawardhana/security-checker-agent/blob/cc7e003ab7547b8d43d92848b255e4fc3be494eb/src/security/knowledgeBase.ts

### 13. yuwen-lu_learn-design-w-claude/
- **File:** src_pages_api_render-component.ts (original: src/pages/api/render-component.ts)
- **Repository:** yuwen-lu/learn-design-w-claude
- **GitHub Link:** https://github.com/yuwen-lu/learn-design-w-claude/blob/ccb10f519ce96de4931e63595659c7677eeef91e/src/pages/api/render-component.ts

### 14. Rop89_findmetime/
- **File:** src_pages_api_analyse.ts (original: src/pages/api/analyse.ts)
- **Repository:** Rop89/findmetime
- **Vulnerable Lines:** 115
- **GitHub Link:** https://github.com/Rop89/findmetime/blob/8a094827e96500de0a03fd623b6e44075a5ca15c/src/pages/api/analyse.ts

### 15. microsoft_content-processing-solution-accelerator/
- **File:** src_ContentProcessorWeb_src_Hooks_useSwaggerPreview.ts (original: src/ContentProcessorWeb/src/Hooks/useSwaggerPreview.ts)
- **Repository:** microsoft/content-processing-solution-accelerator
- **GitHub Link:** https://github.com/microsoft/content-processing-solution-accelerator/blob/049af6f3aae40744298171bd94c8296f0640d8f8/src/ContentProcessorWeb/src/Hooks/useSwaggerPreview.ts

### 16. bluelovers_novel-opds-now/
- **File:** server_index.ts (original: server/index.ts)
- **Repository:** bluelovers/novel-opds-now
- **GitHub Link:** https://github.com/bluelovers/novel-opds-now/blob/4710dbb4d2440939568b944c0aeb7d7207fae4fd/server/index.ts

### 17. tpack_tpack/
- **File:** src_server_liveReload.ts (original: src/server/liveReload.ts)
- **Repository:** tpack/tpack
- **GitHub Link:** https://github.com/tpack/tpack/blob/427a51cb9b28664d5bb22e91e38c11390047f5c0/src/server/liveReload.ts

### 18. olcan_mind.page/
- **File:** src_server.ts (original: src/server.ts)
- **Repository:** olcan/mind.page
- **GitHub Link:** https://github.com/olcan/mind.page/blob/7dcde437b46c919682c8ee59bd2fabdab5046f68/src/server.ts

### 19. carlosbtor_atm-front/
- **File:** src_utils_global.ts (original: src/utils/global.ts)
- **Repository:** carlosbtor/atm-front
- **GitHub Link:** https://github.com/carlosbtor/atm-front/blob/411f1d23888240d62df96f9b80f354a9235136ba/src/utils/global.ts

## Vulnerability Details

All files contain Cross-Site Scripting (XSS) vulnerabilities where:
- **CWE:** CWE-79
- **Severity:** WARNING
- **Issue:** User-controlled data output without proper sanitization

## Source Data

Generated from Darwin analysis CSV: `/Users/sanjuera/MCP_DARWIN/mcp/src/typescript_darwin_findings.csv`

## File Count Summary
- **Total TypeScript Files:** 19 unique files (20 downloads, 1 duplicate)
- **Total XSS Vulnerabilities:** 54
- **Repositories Analyzed:** 19
- **Files with Vulnerabilities:** 11 (58% detection rate)
- **Most Vulnerable File:** Treeki/BirdBridge main.ts (7 vulnerabilities)
