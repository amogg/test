(function() {
    console.log("[*] Starting SSL Inspector...");

    // 안전한 문자열 읽기 (호환성)
    function readStdString(ptr) {
        if (ptr.isNull()) return "(null)";
        try {
            if (typeof ptr.readUtf16String === 'function') return ptr.readUtf16String();
            if (typeof Memory.readUtf16String === 'function') return Memory.readUtf16String(ptr);
        } catch(e) {}
        return "(string)";
    }

    function inspectModule(mName) {
        console.log("---------------------------------------------");
        console.log("[*] Inspecting Module: " + mName);
        
        try {
            // 해당 모듈의 모든 함수(Export) 가져오기
            var exports = Module.enumerateExports(mName);
            console.log("    -> Total Exports found: " + exports.length);

            if (exports.length === 0) {
                console.log("    [!] Warning: No exports found. (Static Linked or Stripped?)");
                return;
            }

            // 상위 20개만 출력해서 이름 패턴 확인
            console.log("    -> Printing first 20 exports:");
            for (var i = 0; i < Math.min(exports.length, 20); i++) {
                console.log("       [" + i + "] " + exports[i].name + " (@" + exports[i].address + ")");
            }

            // 'SSL' 이나 'read' 가 들어가는 함수가 있는지 검색
            console.log("    -> Searching for 'SSL' related functions...");
            var found = 0;
            for (var i = 0; i < exports.length; i++) {
                var name = exports[i].name;
                // 대소문자 무시하고 검색
                if (name.toLowerCase().indexOf("ssl") !== -1 && name.toLowerCase().indexOf("read") !== -1) {
                    console.log("       [HIT] Found candidate: " + name);
                    found++;
                }
            }
            
            if (found === 0) console.log("       [X] No function names containing 'ssl' and 'read' were found.");

        } catch (e) {
            console.log("    [!] Error inspecting module: " + e.message);
        }
    }

    // SSL 모듈 찾기 로직
    var modules = Process.enumerateModules();
    var targetFound = false;

    for (var i = 0; i < modules.length; i++) {
        var m = modules[i];
        var name = m.name.toLowerCase();

        // ssl, crypto, 혹은 wolf, mbed 같은 다른 라이브러리 이름도 체크
        if (name.indexOf("ssl") !== -1 || name.indexOf("crypto") !== -1) {
            targetFound = true;
            inspectModule(m.name);
        }
    }

    if (!targetFound) {
        console.log("[!] No SSL-related modules loaded yet.");
        console.log("    (Wait for the application to make a connection...)");
    }

})();
