/*
 * Windows Crypto "Dragnet" Hooker
 * Targets: Legacy CAPI (Handle-based), CNG, Schannel
 */

const COLORS = {
    SEND: "\x1b[36m", // Cyan
    RECV: "\x1b[32m", // Green
    ERR:  "\x1b[31m", // Red
    RESET: "\x1b[0m"
};

function hookAllCrypto() {
    console.log("[*] Setting up Dragnet for Crypto APIs...");

    // =================================================================
    // 1. [Advapi32] 저수준 CAPI (가장 유력한 후보)
    // CryptEncrypt / CryptDecrypt (핸들 hKey를 사용하는 방식)
    // =================================================================
    const advapi = "advapi32.dll";
    const cEncrypt = Module.findExportByName(advapi, "CryptEncrypt");
    const cDecrypt = Module.findExportByName(advapi, "CryptDecrypt");

    if (cEncrypt) {
        Interceptor.attach(cEncrypt, {
            onEnter(args) {
                // BOOL CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
                // pbData(args[4])에 평문이 들어가고 -> 암호문으로 바뀜
                this.pbData = ptr(args[4]);
                this.pLen = ptr(args[5]);
                this.len = this.pLen.readU32();

                if (this.len > 0) {
                    console.log(`${COLORS.SEND}[CAPI] CryptEncrypt (Input Plaintext: ${this.len} bytes)${COLORS.RESET}`);
                    try {
                        console.log(hexdump(this.pbData, { length: this.len, header: false, ansi: true }));
                    } catch (e) {}
                }
            }
        });
    }

    if (cDecrypt) {
        Interceptor.attach(cDecrypt, {
            onEnter(args) {
                // BOOL CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
                this.pbData = ptr(args[4]);
                this.pLen = ptr(args[5]);
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0) { // Success
                    const len = this.pLen.readU32();
                    if (len > 0) {
                        console.log(`${COLORS.RECV}[CAPI] CryptDecrypt (Output Plaintext: ${len} bytes)${COLORS.RESET}`);
                        try {
                            console.log(hexdump(this.pbData, { length: len, header: false, ansi: true }));
                        } catch (e) {}
                    }
                }
            }
        });
    }

    // =================================================================
    // 2. [NCrypt] CNG & Schannel (I_CryptDetachTls와 연관)
    // I_CryptDetachTls가 보였다면, ncrypt.dll 내부의 Ssl함수를 쓸 확률이 높음
    // =================================================================
    const ncrypt = "ncrypt.dll";
    const sslEnc = Module.findExportByName(ncrypt, "SslEncryptPacket");
    const sslDec = Module.findExportByName(ncrypt, "SslDecryptPacket");

    if (sslEnc) {
        Interceptor.attach(sslEnc, {
            onEnter(args) {
                // SslEncryptPacket(Context, pPlaintext, PlaintextLen, ...)
                const pPlain = ptr(args[1]);
                const len = ptr(args[2]).toInt32();
                if (len > 0) {
                    console.log(`${COLORS.SEND}[Schannel] SslEncryptPacket (Send: ${len} bytes)${COLORS.RESET}`);
                    console.log(hexdump(pPlain, { length: len, header: false, ansi: true }));
                }
            }
        });
    }

    if (sslDec) {
        Interceptor.attach(sslDec, {
            onEnter(args) {
                this.pPlain = ptr(args[3]); // 복호화된 데이터 버퍼
                this.pLen = ptr(args[4]);   // 길이
            },
            onLeave(retval) {
                if (retval.toInt32() === 0) { // Success
                    const len = this.pLen.readU32();
                    if (len > 0) {
                        console.log(`${COLORS.RECV}[Schannel] SslDecryptPacket (Recv: ${len} bytes)${COLORS.RESET}`);
                        console.log(hexdump(this.pPlain, { length: len, header: false, ansi: true }));
                    }
                }
            }
        });
    }

    // =================================================================
    // 3. [Crypt32] 인증서 관련 (노이즈 확인용)
    // 혹시 데이터 통신이 아니라 인증서 검증만 하고 있는지 확인
    // =================================================================
    const certFunc = Module.findExportByName("crypt32.dll", "CertVerifyCertificateChainPolicy");
    if (certFunc) {
        Interceptor.attach(certFunc, {
            onEnter(args) {
                // 이 로그가 너무 많이 뜨면, 프로그램이 통신보다는 인증서 확인에 바쁜 상태임
                // console.log("[*] CertVerifyCertificateChainPolicy called (Certificate Check)");
            }
        });
    }
}

setTimeout(hookAllCrypto, 1000);
