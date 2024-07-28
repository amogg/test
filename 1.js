// Load the SSL module
var SSL_write = Module.findExportByName(null, "SSL_write");
var SSL_read = Module.findExportByName(null, "SSL_read");

if (SSL_write && SSL_read) {
    // Hook SSL_write
    Interceptor.attach(SSL_write, {
        onEnter: function (args) {
            var ssl = args[0];
            var buffer = args[1];
            var len = args[2].toInt32();

            var data = Memory.readByteArray(buffer, len);
            var hexData = hexdump(data, {
                offset: 0,
                length: len,
                header: false,
                ansi: false
            });

            console.log("[SSL_write] Data length: " + len);
            console.log("[SSL_write] Data (hex):\n" + hexData);
            console.log("[SSL_write] Data (string):\n" + Memory.readCString(buffer, len));
        }
    });

    // Hook SSL_read
    Interceptor.attach(SSL_read, {
        onEnter: function (args) {
            this.ssl = args[0];
            this.buffer = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function (retval) {
            if (retval.toInt32() > 0) {
                var len = retval.toInt32();
                var data = Memory.readByteArray(this.buffer, len);
                var hexData = hexdump(data, {
                    offset: 0,
                    length: len,
                    header: false,
                    ansi: false
                });

                console.log("[SSL_read] Data length: " + len);
                console.log("[SSL_read] Data (hex):\n" + hexData);
                console.log("[SSL_read] Data (string):\n" + Memory.readCString(this.buffer, len));
            }
        }
    });
} else {
    console.log("Failed to find SSL_write or SSL_read symbols");
}
