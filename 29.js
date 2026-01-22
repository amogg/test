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
    log("[*] Network & SSL Hooking Check");
    log("[*] Targets: ws2_32.dll + SSL Modules");
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

    // 모듈 스캔 및 타겟 함수 찾기
    function scanModules() {
        var modules = Process.enumerateModules();
        
        for (var i = 0; i < modules.length; i++) {
            var m = modules[i];
            var mName = m.name;
            var lowName = mName.toLowerCase();

            // 1. ws2_32.dll (소켓 기본)
            if (lowName === "ws2_32.dll") {
                checkAndHook(mName, ["socket", "connect", "send", "recv", "WSASend", "WSARecv"]);
            }
            
            // 2. SSL/Crypto 모듈 (sspi, secur32, libssl, openssl, crypto)
            else if (lowName.indexOf("sspi") !== -1 || 
                     lowName.indexOf("secur") !== -1 || 
                     lowName.indexOf("ssl") !== -1 || 
                     lowName.indexOf("crypt") !== -1) {
                
                checkAndHook(mName, ["DecryptMessage", "SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"]);
            }
        }
    }

    // 모듈 내부의 특정 함수들만 찾아서 후킹
    function checkAndHook(modName, targetFuncs) {
        try {
            var exports = Module.enumerateExports(modName);
            
            for (var j = 0; j < exports.length; j++) {
                var exp = exports[j];
                var fName = exp.name;
                var lowFName = fName.toLowerCase();
                var addr = exp.address;

                // 타겟 함수 목록에 포함되는지 확인 (부분 일치 검색)
                // 예: "SSL_read"는 "SSL_read_ex"도 포함할 수 있도록 처리하거나, 정확한 매칭 사용
                
                for (var k = 0; k < targetFuncs.length; k++) {
                    var target = targetFuncs[k].toLowerCase();
                    
                    // 정확한 이름 매칭 또는 _ex 같은 확장 함수 포함
                    // ws2_32의 경우 짧은 이름(send)이 다른 긴 이름에 포함될 수 있어 주의 필요
                    // 여기서는 단순히 포함 여부로 검색하되, 로그를 확인하여 필터링
                    
                    if (lowFName.indexOf(target) !== -1) {
                        
                        // ws2_32.dll의 경우 잡다한 함수 제외 (예: WSASendMsg 등)하고 핵심만 보기 위해
                        // 정확히 일치하거나, _ex 등이 붙은 경우만 허용하는 식으로 로직 강화 가능
                        // 여기서는 발견된 모든 관련 함수를 보여줍니다.

                        var uniqueKey = modName + "::" + fName;
                        if (hookedFunctions[uniqueKey]) continue;

                        // [Step 2] 함수 발견 보고
                        log("[Step 2] Found Target: " + fName + " @ " + addr + " (Module: " + modName + ")");
                        
                        // [Step 3] 후킹 시도
                        installHook(addr, fName, modName);
                        
                        hookedFunctions[uniqueKey] = true;
                        break; // 한 함수에 대해 한 번만 매칭
                    }
                }
            }
        } catch(e) {
            // log("Error scanning exports for " + modName + ": " + e.message);
        }
    }

    // 1초마다 새로운 모듈이 로드되었는지 확인 (Lazy Loading 대응)
    setInterval(scanModules, 1000);
    scanModules(); // 즉시 1회 실행

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
                        print("[+] Script Loaded. Monitoring Network & SSL functions...")
                    except Exception as e:
                        print(f"[!] Attach Error: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == "__main__":
    main()
