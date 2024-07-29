// Find the SSL_write function in the current process
var SSL_write = Module.findExportByName(null, "SSL_write");

if (SSL_write) {
    Interceptor.attach(SSL_write, {
        onEnter: function (args) {
            var ssl = args[0];
            var buffer = args[1];
            var len = args[2].toInt32();

            // Read the original data
            var data = Memory.readByteArray(buffer, len);
            var hexData = hexdump(data, {
                offset: 0,
                length: len,
                header: false,
                ansi: false
            });

            console.log("[SSL_write] Original Data length: " + len);
            console.log("[SSL_write] Original Data (hex):\n" + hexData);
            console.log("[SSL_write] Original Data (string):\n" + Memory.readCString(buffer, len));

            // Modify the data at the desired position
            var position = 0;  // Change this to the position you want to modify
            var newValue = 0x41;  // Change this to the new byte value (0x41 = 'A')

            Memory.writeU8(buffer.add(position), newValue);

            // Read the modified data
            var modifiedData = Memory.readByteArray(buffer, len);
            var modifiedHexData = hexdump(modifiedData, {
                offset: 0,
                length: len,
                header: false,
                ansi: false
            });

            console.log("[SSL_write] Modified Data length: " + len);
            console.log("[SSL_write] Modified Data (hex):\n" + modifiedHexData);
            console.log("[SSL_write] Modified Data (string):\n" + Memory.readCString(buffer, len));
        }
    });
} else {
    console.log("Failed to find SSL_write symbol");
}
