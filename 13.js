(function() {
    console.log("==================================================");
    console.log("[*] Starting Ultimate SSL Scanner (Full Scan)");
    console.log("==================================================");

    // [1] 안전한 Export 조회 헬퍼 (not a function 에러 해결)
    function getExportsSafe(moduleName) {
        try {
            // 방법 1: Module.enumerateExports (표준)
            if (Module.enumerateExports) {
                return Module.enumerateExports(moduleName);
            }
        } catch(e) {}

        try {
            // 방법 2: 모듈 객체에서 직접 호출 (구버전/특이환경 호환)
            var mod = Process.findModuleByName(moduleName);
            if (mod && mod.enumerateExports) {
                return mod.enumerateExports();
            }
        } catch(e) {}

        return []; // 실패하면 빈 배열 반환
    }

    var totalFound = 0;
    var modules = Process.enumerateModules();

    console.log("[*] Scanning " + modules.length + " loaded modules...");

    // [2] 모든 모듈 전수 조사
    for (var i = 0; i < modules.length; i++) {
        var m = modules[i];
        var mName = m.name.toLowerCase();
        
        // 시스템 기본 DLL 등 너무 뻔한 건 스킵해서 속도 향상 (원하면 주석 처리)
        // if (mName.includes("font") || mName.includes("gdi") || mName.includes("user32")) continue;

        var exports = getExportsSafe(m.name);
        
        for (var j = 0; j < exports.length; j++) {
            var funcName = exports[j].name;
            var lowerName = funcName.toLowerCase();

            // [3] 핵심 키워드 검색
            // - SSL_read/write: OpenSSL
            // - DecryptMessage: Windows Native SSL (SChannel)
            // - wolfSSL / mbedtls: 기타 SSL 라이브러리
            if (lowerName.indexOf("ssl_read") !== -1 || 
                lowerName.indexOf("ssl_write") !== -1 || 
                lowerName.indexOf("decryptmessage") !== -1) {
                
                console.log("[HIT] Found: " + funcName);
                console.log("      -> Module: " + m.name);
                console.log("      -> Address: " + exports[j].address);
                totalFound++;
            }
        }
    }

    console.log("==================================================");
    if (totalFound === 0) {
        console.log("[!] RESULT: No Exported SSL functions found.");
        console.log("    Possibility 1: Static Linking (함수 이름이 삭제됨)");
        console.log("    Possibility 2: Obfuscation (이름이 암호화됨)");
    } else {
        console.log("[*] RESULT: Found " + totalFound + " candidates.");
        console.log("    -> Use these function names in your hooking script.");
    }
    console.log("==================================================");

})();
