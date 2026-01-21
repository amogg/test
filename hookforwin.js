/*
 * Windows General Behavior Monitor (WinAPI Hooking)
 * 타겟: 파일, 프로세스, 레지스트리, 네트워크, 라이브러리 로드
 */

// 로그 출력을 위한 헬퍼 함수
function log(type, message) {
    var color = "";
    var reset = "\x1b[0m";
    
    // 터미널 색상 설정
    switch(type) {
        case "FILE": color = "\x1b[36m"; break; // Cyan
        case "NET":  color = "\x1b[32m"; break; // Green
        case "EXEC": color = "\x1b[31m"; break; // Red
        case "REG":  color = "\x1b[33m"; break; // Yellow
        case "LIB":  color = "\x1b[35m"; break; // Magenta
        default:     color = "\x1b[37m"; break; // White
    }
    console.log(color + "[" + type + "] " + message + reset);
}

// 1. [FILE] 파일 생성 및 열기 (CreateFileW)
var pCreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
if (pCreateFileW) {
    Interceptor.attach(pCreateFileW, {
        onEnter: function (args) {
            var path = args[0].readUtf16String();
            // 시스템 노이즈(Windows 폴더 등)를 줄이려면 아래 주석 해제
            // if (path.indexOf("C:\\Windows") === -1) {
                log("FILE", "Open/Create: " + path);
            // }
        }
    });
}

// 2. [FILE] 파일 삭제 (DeleteFileW)
var pDeleteFileW = Module.findExportByName("kernel32.dll", "DeleteFileW");
if (pDeleteFileW) {
    Interceptor.attach(pDeleteFileW, {
        onEnter: function (args) {
            log("FILE", "DELETE: " + args[0].readUtf16String());
        }
    });
}

// 3. [EXEC] 프로세스 실행 (CreateProcessW)
// 악성코드가 자가복제하거나 다른 프로그램을 실행할 때 사용
var pCreateProcessW = Module.findExportByName("kernel32.dll", "CreateProcessW");
if (pCreateProcessW) {
    Interceptor.attach(pCreateProcessW, {
        onEnter: function (args) {
            var app = args[0].isNull() ? "" : args[0].readUtf16String();
            var cmd = args[1].isNull() ? "" : args[1].readUtf16String();
            log("EXEC", "CreateProcess: " + app + " (Args: " + cmd + ")");
        }
    });
}

// 4. [EXEC] 쉘 실행 (ShellExecuteW)
// 특정 URL을 브라우저로 열거나 파일을 실행할 때 사용
var pShellExecuteW = Module.findExportByName("shell32.dll", "ShellExecuteW");
if (pShellExecuteW) {
    Interceptor.attach(pShellExecuteW, {
        onEnter: function (args) {
            var op = args[1].isNull() ? "" : args[1].readUtf16String();
            var file = args[2].isNull() ? "" : args[2].readUtf16String();
            var param = args[3].isNull() ? "" : args[3].readUtf16String();
            log("EXEC", "ShellExecute: [" + op + "] " + file + " " + param);
        }
    });
}

// 5. [REG] 레지스트리 쓰기 (RegSetValueExW)
// 시작프로그램 등록(Persistence) 확인용
var pRegSetValueExW = Module.findExportByName("advapi32.dll", "RegSetValueExW");
if (pRegSetValueExW) {
    Interceptor.attach(pRegSetValueExW, {
        onEnter: function (args) {
            var valName = args[1].isNull() ? "(default)" : args[1].readUtf16String();
            log("REG", "Set Value: " + valName);
            // 데이터 내용도 보고 싶다면 args[4] (Data)와 args[5] (Size)를 덤프해야 함
        }
    });
}

// 6. [LIB] DLL 로드 (LoadLibraryW)
// 런타임에 어떤 기능을 가져와 쓰는지 파악
var pLoadLibraryW = Module.findExportByName("kernel32.dll", "LoadLibraryW");
if (pLoadLibraryW) {
    Interceptor.attach(pLoadLibraryW, {
        onEnter: function (args) {
            log("LIB", "Loading DLL: " + args[0].readUtf16String());
        }
    });
}

// 7. [NET] 인터넷 연결 시도 (InternetOpenUrlW - WinInet)
// 하이레벨 HTTP 요청 감지
var pInternetOpenUrlW = Module.findExportByName("wininet.dll", "InternetOpenUrlW");
if (pInternetOpenUrlW) {
    Interceptor.attach(pInternetOpenUrlW, {
        onEnter: function (args) {
            log("NET", "HTTP Request: " + args[1].readUtf16String());
        }
    });
}

// 8. [NET] 소켓 연결 (connect - Winsock)
// 로우레벨 TCP 연결 감지
var pConnect = Module.findExportByName("ws2_32.dll", "connect");
if (pConnect) {
    Interceptor.attach(pConnect, {
        onEnter: function (args) {
            // 소켓 구조체 파싱은 복잡하므로 일단 호출 여부만 확인
            log("NET", "Socket Connect detected (Winsock)");
        }
    });
}

console.log("\n[*] WinAPI Monitor Script Loaded...");
console.log("[*] Waiting for File, Network, Process, Registry activities...\n");
