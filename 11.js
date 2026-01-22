(function() {
    console.log("[*] Starting Robust Hooking Script...");

    // ============================================================
    // 1. [호환성 해결] 문자열 읽기 함수 (Safe Reader)
    // ============================================================
    // 최신/구버전 프리다 모두 동작하도록 try-catch로 감쌉니다.
    function readStdString(ptr) {
        if (ptr.isNull()) return "(null)";
        try {
            // Modern Frida (v12+)
            if (typeof ptr.readUtf16String === 'function') {
                return ptr.readUtf16String();
            }
        } catch(e) {}

        try {
            // Legacy Frida
            if (typeof Memory.readUtf16String === 'function') {
                return Memory.readUtf16String(ptr);
            }
        } catch(e) {}

        return "(unknown string)";
    }

    // ============================================================
    // 2. [호환성 해결] 주소 찾기 및 후킹 (Safe Resolver)
    // ============================================================
    var hookedMap = {};

    function safeHook(dllName, funcName, callbacks) {
        var fullName = dllName + "!" + funcName;
        if (hookedMap[fullName]) return;

        var ptr = null;
        
        try {
            // 1차 시도: 일반적인 Export 찾기
            ptr = Module.findExportByName(dllName, funcName);
            
            // 2차 시도: DLL 이름이 대소문자 문제일 수 있으니 null이면 모듈부터 찾기
            if (!ptr) {
                var mod = Process.findModuleByName(dllName);
                if (mod) {
                    ptr = Module.findExportByName(mod.name, funcName);
                }
            }
        } catch (e) {
            // 여기서 에러나면 그냥 패스
            return;
        }

        // 주소를 못 찾았으면 종료
        if (!ptr) return;

        try {
            Interceptor.attach(ptr, callbacks);
            hookedMap[fullName] = true;
            console.log("[+] Hooked: " + fullName + " -> " + ptr);
        } catch (e) {
            console.log("[-] Failed to attach " + fullName + ": " + e.message);
        }
    }

    // ============================================================
    // 3. 메인 후킹 로직
    // ============================================================
    function applyHooks() {
        
        // [FILE] CreateFileW
        safeHook("kernel32.dll", "CreateFileW", {
            onEnter: function(args) {
                this.path = readStdString(args[0]);
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf("Windows") === -1) {
                    console.log("[FILE] Create: " + this.path);
                }
            }
        });

        // [EXEC] CreateProcessW
        safeHook("kernel32.dll", "CreateProcessW", {
            onEnter: function(args) {
                var app = readStdString(args[0]);
                var cmd = readStdString(args[1]);
                console.log("[EXEC] Process: " + app + " " + cmd);
            }
        });

        // [NET] Connect
        safeHook("ws2_32.dll", "connect", {
            onEnter: function(args) { console.log("[NET] Connect called"); }
        });
    }

    // ============================================================
    // 4. [수정됨] OpenSSL 찾기 (에러 원인 제거)
    // ============================================================
    function findOpenSSL() {
        try {
            var modules = Process.enumerateModules();
            
            for (var i = 0; i < modules.length; i++) {
                var m = modules[i];
                var mName = m.name.toLowerCase();

                if (mName.indexOf("ssl") !== -1 || mName.indexOf("crypto") !== -1) {
                    console.log("[*] Scanning SSL Module: " + m.name);

                    // [핵심 수정] m.enumerateExports() 대신 Module.enumerateExports 사용
                    // m 객체에 메서드가 없는 경우가 많아 여기서 'not a function'이 뜸
                    var exports = [];
                    try {
                        exports = m.enumerateExports(); // 1차 시도
                    } catch(e) {
                        try {
                            exports = Module.enumerateExports(m.name); // 2차 시도 (정석)
                        } catch(ex) {
                            continue; // 이것도 안되면 다음 모듈로
                        }
                    }

                    for (var j = 0; j < exports.length; j++) {
                        var exp = exports[j];
                        if (exp.name === "SSL_read" || exp.name === "SSL_write") {
                            safeHook(m.name, exp.name, {
                                onEnter: function(args) {
                                    console.log("[SSL] " + this.name + " called");
                                }
                            });
                        }
                    }
                }
            }
        } catch (e) {
            console.log("[-] OpenSSL Scan Error: " + e.message);
        }
    }

    // 실행
    console.log("[*] Initializing Hooks...");
    applyHooks();
    findOpenSSL();
    
    // Lazy Loading 대응 (1초 뒤 한 번 더 스캔 - 간단하고 확실한 방법)
    setTimeout(function() {
        console.log("[*] Re-scanning for late loaded modules...");
        applyHooks();
        findOpenSSL();
    }, 1000);

})();
