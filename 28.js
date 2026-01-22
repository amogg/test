import frida
import sys
import time

# 감시할 프로세스 접두사
TARGET_PREFIX = "aaa_"
attached_pids = set()

JS_CODE = """
(function() {
    function log(msg) { send(msg); }
    var hookedFunctions = {}; // 중복 후킹 방지

    log("========================================");
    log("[*] SSL Hooking Check (Step 2 & 3)");
    log("[*] Waiting for SSL/Crypto modules...");
    log("========================================");

    // [Step 3] 실제 후킹을 수행하는 함수
    function installHook(address, funcName, modName) {
        try {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    // 호출되면 즉시 알림
                    send("[HIT] " + funcName + " called! (in " + modName + ")");
                }
            });
            log("    -> [Step 3] Hook SUCCESS: " + funcName);
        } catch(e) {
            log("    -> [Step 3] Hook FAILED: " + e.message);
        }
    }

    // 주기적 스캔 함수
    function scanSSL() {
        // 현재 로드된 모든 모듈 가져오기
        var modules = Process.enumerateModules();
        
        for (var i = 0; i < modules.length; i++) {
            var m = modules[i];
            var mName = m.name;
            var lowName = mName.toLowerCase();

            // SSL 관련 모듈만 필터링 (sspi, secur32, libssl, openssl, crypto)
            if (lowName.indexOf("sspi") !== -1 || 
                lowName.indexOf("secur") !== -1 || 
                lowName.indexOf("ssl") !== -1 || 
                lowName.indexOf("crypt") !== -1) {

                // Export된 함수 목록 검색
                try {
                    var exports = Module.enumerateExports(mName);
                    
                    for (var j = 0; j < exports.length; j++) {
                        var exp = exports[j];
                        var fName = exp.name;
                        var lowFName = fName.toLowerCase();
                        
                        // 우리가 찾는 핵심 함수 패턴
                        // 1. Windows Native: DecryptMessage
                        // 2. OpenSSL: SSL_read, SSL_write
                        if (lowFName.indexOf("decryptmessage") !== -1 || 
                           (lowFName.indexOf("ssl_") !== -1 && (lowFName.indexOf("read") !== -1 || lowFName.indexOf("write") !== -1))) {
                            
                            var uniqueKey = mName + "::" + fName;
                            
                            // 이미 처리한 함수는 패스
                            if (hookedFunctions[uniqueKey]) continue;

                            // [Step 2] 함수 발견 보고
                            log("[Step 2] Found Target: " + fName + " @ " + exp.address + " (Module: " + mName + ")");
                            
                            // [Step 3] 후킹 시도
                            installHook(exp.address, fName, mName);
                            
                            hookedFunctions[uniqueKey] = true;
                        }
                    }
                } catch(e) {
                    // 권한 문제 등으로 Export를 못 읽는 경우 무시
                }
            }
        }
    }

    // 1초마다 새로운 모듈이 로드되었는지 확인 (Lazy Loading 대응)
    setInterval(scanSSL, 1000);
    scanSSL(); // 즉시 1회 실행

})();
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"{message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[JS Error] {message['stack']}\x1b[0m")

def main():
    print(f"[*] Waiting for processes starting with '{TARGET_PREFIX}'...")
    device = frida.get_local_device()

    while True:
        try:
            procs = device.enumerate_processes()
            for p in procs:
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    print(f"\n[+] Found {p.name} ({p.pid}). Attaching...")
                    try:
                        session = device.attach(p.pid)
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load()
                        attached_pids.add(p.pid)
                        print("[+] Script Loaded. Monitoring SSL functions...")
                    except Exception as e:
                        print(f"[!] Attach Error: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == "__main__":
    main()
