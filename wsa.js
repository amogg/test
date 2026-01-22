(function() {
    console.log("==================================================");
    console.log("[*] Starting Winsock (Ws2_32.dll) Hooking");
    console.log("[*] Watching: connect, send, recv, WSA APIs");
    console.log("==================================================");

    // [1] 유틸리티: 헥사 덤프 (안전 버전)
    function safeDump(ptr, len) {
        if (!ptr || ptr.isNull() || len <= 0) return "";
        try {
            var buf = Memory.readByteArray(ptr, Math.min(len, 256));
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: Math.min(len, 256), header: false, ansi: false });
            }
            return " [Hexdump missing]";
        } catch(e) { return " [Dump Error]"; }
    }

    // [2] 유틸리티: sockaddr 구조체에서 IP:Port 파싱 (IPv4)
    function parseSockAddr(ptr) {
        if (!ptr || ptr.isNull()) return "unknown";
        try {
            // struct sockaddr_in {
            //     short   sin_family; (2 bytes)
            //     u_short sin_port;   (2 bytes) - Big Endian
            //     struct  in_addr sin_addr; (4 bytes)
            //     char    sin_zero[8];
            // };
            var family = ptr.readU16();
            if (family !== 2) return "Family:" + family; // AF_INET = 2

            var port = ptr.add(2).readU16();
            // Big Endian -> Little Endian 변환 (Port)
            port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);

            var ip = ptr.add(4).readU32();
            // IP 주소 변환
            var ipStr = ((ip & 0xFF) + "." + 
                         ((ip >> 8) & 0xFF) + "." + 
                         ((ip >> 16) & 0xFF) + "." + 
                         ((ip >> 24) & 0xFF));
            
            return ipStr + ":" + port;
        } catch(e) { return "Parse Error"; }
    }

    // [3] 함수 주소 찾기 헬퍼
    function hookFunc(funcName, callbacks) {
        var ptr = Module.findExportByName("ws2_32.dll", funcName);
        if (ptr) {
            try {
                Interceptor.attach(ptr, callbacks);
                console.log("[+] Hooked: " + funcName);
            } catch(e) { console.log("[-] Failed to hook " + funcName + ": " + e.message); }
        } else {
            console.log("[-] Export not found: " + funcName);
        }
    }

    // =========================================================================
    // [A] 연결 감시 (connect, WSAConnect)
    // =========================================================================
    
    // connect(SOCKET s, const struct sockaddr *name, int namelen);
    hookFunc("connect", {
        onEnter: function(args) {
            this.sock = args[0];
            var dest = parseSockAddr(args[1]);
            console.log("\x1b[36m[NET] Connecting to " + dest + "\x1b[0m");
        }
    });

    // WSAConnect(SOCKET s, const struct sockaddr *name, ...);
    hookFunc("WSAConnect", {
        onEnter: function(args) {
            var dest = parseSockAddr(args[1]);
            console.log("\x1b[36m[NET] WSAConnect to " + dest + "\x1b[0m");
        }
    });

    // =========================================================================
    // [B] 데이터 전송 (send, WSASend)
    // =========================================================================

    // send(SOCKET s, const char *buf, int len, int flags);
    hookFunc("send", {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0) {
                console.log("\x1b[32m[NET] send (" + len + " bytes):\x1b[0m" + safeDump(args[1], len));
            }
        }
    });

    // WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, ...);
    // WSABUF 구조체: { ULONG len; CHAR *buf; }
    hookFunc("WSASend", {
        onEnter: function(args) {
            try {
                var lpBuffers = args[1];
                var dwBufferCount = args[2].toInt32();
                
                // 버퍼 개수만큼 반복
                for (var i = 0; i < dwBufferCount; i++) {
                    // x64: WSABUF size = 4(len) + 4(padding) + 8(ptr) = 16 bytes ?? 
                    // 구조체: ULONG len (4), char* buf (8) -> 보통 16바이트 정렬됨
                    var pWSABuf = lpBuffers.add(i * 16); 
                    
                    var len = pWSABuf.readU32();
                    var buf = pWSABuf.add(8).readPointer(); // 64비트 기준 포인터 오프셋

                    if (len > 0) {
                        console.log("\x1b[32m[NET] WSASend Buf[" + i + "] (" + len + " bytes):\x1b[0m" + safeDump(buf, len));
                    }
                }
            } catch(e) {}
        }
    });

    // =========================================================================
    // [C] 데이터 수신 (recv, WSARecv)
    // =========================================================================

    // recv(SOCKET s, char *buf, int len, int flags);
    hookFunc("recv", {
        onEnter: function(args) {
            this.buf = args[1];
        },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (len > 0) {
                console.log("\x1b[35m[NET] recv (" + len + " bytes):\x1b[0m" + safeDump(this.buf, len));
            }
        }
    });

    // WSARecv는 비동기(Overlapped) 방식일 수 있어 복잡하지만, 동기 호출의 경우 처리
    // WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, ...);
    hookFunc("WSARecv", {
        onEnter: function(args) {
            this.lpBuffers = args[1];
            this.dwBufferCount = args[2].toInt32();
            this.lpNumberOfBytesRecvd = args[3]; // 수신된 크기가 담길 포인터
        },
        onLeave: function(retval) {
            // retval이 0(성공)이고, 수신 크기 포인터가 유효하면
            try {
                if (retval.toInt32() === 0 && !this.lpNumberOfBytesRecvd.isNull()) {
                    var totalRecv = this.lpNumberOfBytesRecvd.readU32();
                    if (totalRecv > 0) {
                        // 첫 번째 버퍼만 덤프 (단순화)
                        var pWSABuf = this.lpBuffers;
                        var buf = pWSABuf.add(8).readPointer(); // x64 offset
                        console.log("\x1b[35m[NET] WSARecv (" + totalRecv + " bytes):\x1b[0m" + safeDump(buf, totalRecv));
                    }
                }
            } catch(e) {}
        }
    });

})();
