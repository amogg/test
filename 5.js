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

            // Define the new string to insert
            var newString = "ABCDE"; // Example string
            var newHexString = stringToHex(newString);

            // Convert hex string to byte array
            var newBytes = hexStringToByteArray(newHexString);

            // Modify the data at the desired position
            var position = 0;  // Change this to the position you want to start modifying

            // Write the byte array to the buffer
            Memory.writeByteArray(buffer.add(position), newBytes);

            // Update the length argument
            var newLen = newBytes.length;
            args[2] = ptr(newLen);

            // Read the modified data
            var modifiedData = Memory.readByteArray(buffer, newLen);
            var modifiedHexData = hexdump(modifiedData, {
                offset: 0,
                length: newLen,
                header: false,
                ansi: false
            });

            console.log("[SSL_write] Modified Data length: " + newLen);
            console.log("[SSL_write] Modified Data (hex):\n" + modifiedHexData);
            console.log("[SSL_write] Modified Data (string):\n" + Memory.readCString(buffer, newLen));
        }
    });
} else {
    console.log("Failed to find SSL_write symbol");
}

// Function to convert string to hex string
function stringToHex(str) {
    var hex = '';
    for (var i = 0; i < str.length; i++) {
        hex += str.charCodeAt(i).toString(16);
    }
    return hex;
}

// Function to convert hex string to byte array
function hexStringToByteArray(hexString) {
    var result = [];
    for (var i = 0; i < hexString.length; i += 2) {
        result.push(parseInt(hexString.substr(i, 2), 16));
    }
    return result;
}
