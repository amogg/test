var SSL_CTX_use_PrivateKey_file = Module.findExportByName(null, "SSL_CTX_use_PrivateKey_file");

if (SSL_CTX_use_PrivateKey_file) {
    Interceptor.attach(SSL_CTX_use_PrivateKey_file, {
        onEnter: function (args) {
            var keyFilePath = Memory.readCString(args[1]);
            console.log("[SSL_CTX_use_PrivateKey_file] Key file path: " + keyFilePath);

            // Here you could add additional code to read and print the key file contents if needed
            try {
                var keyFile = new File(keyFilePath, 'r');
                var keyContent = keyFile.read();
                keyFile.close();

                console.log("[SSL_CTX_use_PrivateKey_file] Key file content:\n" + keyContent);
            } catch (e) {
                console.log("[SSL_CTX_use_PrivateKey_file] Failed to read key file: " + e.message);
            }
        }
    });
} else {
    console.log("Failed to find SSL_CTX_use_PrivateKey_file symbol");
}
