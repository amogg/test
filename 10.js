(function() {
    console.log("==========================================");
    console.log("[*] Starting Diagnostic Hooking Script");
    console.log("==========================================");

    // 1. 현재 로드된 모든 모듈(DLL) 출력
    console.log("\n[1] Enumerating Loaded Modules:");
    var modules = Process.enumerateModules();
    var targetModules = ["kernel32.dll", "advapi32.dll", "ws2_32.dll", "ntdll.dll"];
    
    modules.forEach(function(m) {
        // 너무 많으니까 주요 시스템 DLL만 필터링해서 확인
        if (targetModules.indexOf(m.name.toLowerCase()) !== -1 || m.name.indexOf("aaa_") !== -1) {
            console.log("    -> Found: " + m.name + " (" + m.base + ")");
        }
    });

    // 2. 핵심 함수 주소 확인 (존재 여부 체크)
    console.log("\n[2] Checking Symbol Resolution:");
    
    function checkAndHook(dll, name) {
        var ptr = Module.findExportByName(dll, name);
        if (!ptr) {
            console.log("    [X] " + dll + "!" + name + " -> NOT FOUND (NULL)");
            return;
        }
        console.log("    [O] " + dll + "!" + name + " -> Found at " + ptr);
        
        // 테스트용으로 딱 하나만 후킹 시도
        try {
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    console.log("\n    [!!!] HOOK SUCCESS: " + name + " called!");
                }
            });
            console.log("        -> Attach Success");
        } catch(e) {
            console.log("        -> Attach FAILED: " + e.message);
        }
    }

    // 자주 쓰는 함수들이 진짜 주소가 따지는지 확인
    checkAndHook("kernel32.dll", "CreateFileW");
    checkAndHook("kernel32.dll", "CreateProcessW");
    checkAndHook("ws2_32.dll", "connect");
    
    // 혹시 kernel32가 아니라 ntdll 레벨에서 호출하는지 확인 (Lower Level)
    checkAndHook("ntdll.dll", "NtCreateFile");

    console.log("\n==========================================");
    console.log("[*] Diagnostics Done. Waiting for triggers...");
    console.log("==========================================");
})();
