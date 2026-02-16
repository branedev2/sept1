import java.security.MessageDigest
import java.util.UUID
import java.io.File
import java.nio.charset.StandardCharsets

// True Positive Examples (Vulnerable Code)

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_1() {
    val data = "Hello, World!"
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(data.toByteArray())
    
    val hexString = StringBuilder()
    for (b in digest) {
        // ruleid: kotlin-bad-hexa-conversion
        hexString.append(Integer.toHexString(0xFF and b.toInt()))
    }
    
    println("SHA-256 Hash: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_2() {
    val inputText = "Security Test"
    val md = MessageDigest.getInstance("MD5")
    val bytes = md.digest(inputText.toByteArray())
    val result = StringBuilder()
    
    for (byte in bytes) {
        // ruleid: kotlin-bad-hexa-conversion
        result.append(Integer.toHexString(0xFF and byte.toInt()))
    }
    
    println("MD5 Hash: $result")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_3() {
    val fileContent = File("config.txt").readBytes()
    val md = MessageDigest.getInstance("SHA-1")
    val hashBytes = md.digest(fileContent)
    
    val sb = StringBuilder()
    for (b in hashBytes) {
        // ruleid: kotlin-bad-hexa-conversion
        val hex = Integer.toHexString(b.toInt() & 0xFF)
        sb.append(hex)
    }
    
    println("File hash: $sb")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_4() {
    val userId = UUID.randomUUID().toString()
    val bytes = userId.toByteArray()
    val result = StringBuilder()
    
    for (i in bytes.indices) {
        // ruleid: kotlin-bad-hexa-conversion
        val hexValue = Integer.toHexString(bytes[i].toInt() and 0xFF)
        result.append(hexValue)
    }
    
    println("Hex representation: $result")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_5() {
    val password = "SecurePassword123"
    val md = MessageDigest.getInstance("SHA-512")
    val hash = md.digest(password.toByteArray())
    
    val hexString = StringBuilder()
    for (b in hash) {
        // ruleid: kotlin-bad-hexa-conversion
        val hex = Integer.toHexString(b.toInt() and 0xFF)
        hexString.append(hex)
    }
    
    println("Password hash: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_6() {
    val ipAddress = "192.168.1.1"
    val bytes = ipAddress.toByteArray()
    val hexRepresentation = StringBuilder()
    
    for (byte in bytes) {
        // ruleid: kotlin-bad-hexa-conversion
        hexRepresentation.append(Integer.toHexString(byte.toInt() and 0xFF))
    }
    
    println("IP in hex: $hexRepresentation")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_7() {
    val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
    val hexOutput = StringBuilder()
    
    for (b in data) {
        // ruleid: kotlin-bad-hexa-conversion
        val hexValue = Integer.toHexString(b.toInt() and 0xFF)
        hexOutput.append(hexValue)
    }
    
    println("Hex data: $hexOutput")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_8() {
    val text = "Convert this to octal"
    val bytes = text.toByteArray()
    val octalResult = StringBuilder()
    
    for (byte in bytes) {
        // ruleid: kotlin-bad-hexa-conversion
        octalResult.append(Integer.toOctalString(byte.toInt() and 0xFF))
        octalResult.append(" ")
    }
    
    println("Octal representation: $octalResult")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_9() {
    val randomBytes = ByteArray(16).apply { 
        java.security.SecureRandom().nextBytes(this) 
    }
    
    val hexString = StringBuilder()
    for (i in randomBytes.indices) {
        // ruleid: kotlin-bad-hexa-conversion
        val hex = Integer.toHexString(randomBytes[i].toInt() and 0xFF)
        hexString.append(hex)
    }
    
    println("Random hex: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_10() {
    val message = "This is a secret message"
    val md = MessageDigest.getInstance("SHA-384")
    val digest = md.digest(message.toByteArray())
    
    val sb = StringBuilder()
    for (b in digest) {
        // ruleid: kotlin-bad-hexa-conversion
        val hexValue = Integer.toHexString(0xFF and b.toInt())
        if (hexValue.length == 1) sb.append('0')
        sb.append(hexValue)
    }
    
    println("Message digest: $sb")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_11() {
    val binaryData = byteArrayOf(0x10, 0x20, 0x30, 0x40, 0x50)
    val hexBuilder = StringBuilder()
    
    for (b in binaryData) {
        // ruleid: kotlin-bad-hexa-conversion
        hexBuilder.append(Integer.toHexString(b.toInt() and 0xFF))
    }
    
    println("Binary data in hex: $hexBuilder")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_12() {
    val colorValue = 0x00FF00
    val r = (colorValue shr 16) and 0xFF
    val g = (colorValue shr 8) and 0xFF
    val b = colorValue and 0xFF
    
    val hexColor = StringBuilder("#")
    // ruleid: kotlin-bad-hexa-conversion
    hexColor.append(Integer.toHexString(r))
    // ruleid: kotlin-bad-hexa-conversion
    hexColor.append(Integer.toHexString(g))
    // ruleid: kotlin-bad-hexa-conversion
    hexColor.append(Integer.toHexString(b))
    
    println("Color: $hexColor")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_13() {
    val macAddress = byteArrayOf(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)
    val formattedMac = StringBuilder()
    
    for (i in macAddress.indices) {
        // ruleid: kotlin-bad-hexa-conversion
        formattedMac.append(Integer.toHexString(macAddress[i].toInt() and 0xFF))
        if (i < macAddress.size - 1) {
            formattedMac.append(":")
        }
    }
    
    println("MAC Address: $formattedMac")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_14() {
    val timestamp = System.currentTimeMillis()
    val bytes = ByteArray(8)
    
    for (i in 0..7) {
        bytes[i] = ((timestamp shr (i * 8)) and 0xFF).toByte()
    }
    
    val hexTimestamp = StringBuilder()
    for (b in bytes) {
        // ruleid: kotlin-bad-hexa-conversion
        hexTimestamp.append(Integer.toHexString(b.toInt() and 0xFF))
    }
    
    println("Timestamp in hex: $hexTimestamp")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=1}
fun bad_case_15() {
    val input = "Convert to binary representation"
    val bytes = input.toByteArray(StandardCharsets.UTF_8)
    
    val hexOutput = StringBuilder()
    val binaryOutput = StringBuilder()
    
    for (b in bytes) {
        // ruleid: kotlin-bad-hexa-conversion
        val hex = Integer.toHexString(b.toInt() and 0xFF)
        hexOutput.append(hex)
        
        val binary = Integer.toBinaryString(b.toInt() and 0xFF)
        binaryOutput.append(binary.padStart(8, '0'))
        binaryOutput.append(" ")
    }
    
    println("Hex: $hexOutput")
    println("Binary: $binaryOutput")
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_1() {
    val data = "Hello, World!"
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(data.toByteArray())
    
    val hexString = StringBuilder()
    for (b in digest) {
        // ok: kotlin-bad-hexa-conversion
        hexString.append(String.format("%02X", b))
    }
    
    println("SHA-256 Hash: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_2() {
    val inputText = "Security Test"
    val md = MessageDigest.getInstance("MD5")
    val bytes = md.digest(inputText.toByteArray())
    val result = StringBuilder()
    
    for (byte in bytes) {
        // ok: kotlin-bad-hexa-conversion
        result.append(String.format("%02x", byte))
    }
    
    println("MD5 Hash: $result")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_3() {
    val fileContent = File("config.txt").readBytes()
    val md = MessageDigest.getInstance("SHA-1")
    val hashBytes = md.digest(fileContent)
    
    val sb = StringBuilder()
    for (b in hashBytes) {
        // ok: kotlin-bad-hexa-conversion
        sb.append(String.format("%02x", b))
    }
    
    println("File hash: $sb")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_4() {
    val userId = UUID.randomUUID().toString()
    val bytes = userId.toByteArray()
    val result = StringBuilder()
    
    for (i in bytes.indices) {
        // ok: kotlin-bad-hexa-conversion
        val hexValue = String.format("%02X", bytes[i])
        result.append(hexValue)
    }
    
    println("Hex representation: $result")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_5() {
    val password = "SecurePassword123"
    val md = MessageDigest.getInstance("SHA-512")
    val hash = md.digest(password.toByteArray())
    
    // ok: kotlin-bad-hexa-conversion
    val hexString = hash.joinToString("") { "%02x".format(it) }
    
    println("Password hash: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_6() {
    val ipAddress = "192.168.1.1"
    val bytes = ipAddress.toByteArray()
    
    // ok: kotlin-bad-hexa-conversion
    val hexRepresentation = bytes.joinToString("") { "%02X".format(it) }
    
    println("IP in hex: $hexRepresentation")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_7() {
    val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
    
    // ok: kotlin-bad-hexa-conversion
    val hexOutput = data.joinToString("") { byte -> 
        String.format("%02X", byte) 
    }
    
    println("Hex data: $hexOutput")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_8() {
    val text = "Convert this to hex"
    val bytes = text.toByteArray()
    
    // ok: kotlin-bad-hexa-conversion
    val hexResult = bytes.map { String.format("%02X", it) }.joinToString("")
    
    println("Hex representation: $hexResult")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_9() {
    val randomBytes = ByteArray(16).apply { 
        java.security.SecureRandom().nextBytes(this) 
    }
    
    val hexString = StringBuilder()
    for (i in randomBytes.indices) {
        // ok: kotlin-bad-hexa-conversion
        val hex = String.format("%02X", randomBytes[i])
        hexString.append(hex)
    }
    
    println("Random hex: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_10() {
    val message = "This is a secret message"
    val md = MessageDigest.getInstance("SHA-384")
    val digest = md.digest(message.toByteArray())
    
    // ok: kotlin-bad-hexa-conversion
    val hexString = digest.fold("") { str, byte -> str + "%02x".format(byte) }
    
    println("Message digest: $hexString")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_11() {
    val binaryData = byteArrayOf(0x10, 0x20, 0x30, 0x40, 0x50)
    
    // ok: kotlin-bad-hexa-conversion
    val hexBuilder = binaryData.joinToString("") { "%02X".format(it) }
    
    println("Binary data in hex: $hexBuilder")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_12() {
    val colorValue = 0x00FF00
    val r = (colorValue shr 16) and 0xFF
    val g = (colorValue shr 8) and 0xFF
    val b = colorValue and 0xFF
    
    // ok: kotlin-bad-hexa-conversion
    val hexColor = String.format("#%02X%02X%02X", r, g, b)
    
    println("Color: $hexColor")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_13() {
    val macAddress = byteArrayOf(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)
    
    // ok: kotlin-bad-hexa-conversion
    val formattedMac = macAddress.joinToString(":") { "%02X".format(it) }
    
    println("MAC Address: $formattedMac")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_14() {
    val timestamp = System.currentTimeMillis()
    val bytes = ByteArray(8)
    
    for (i in 0..7) {
        bytes[i] = ((timestamp shr (i * 8)) and 0xFF).toByte()
    }
    
    // ok: kotlin-bad-hexa-conversion
    val hexTimestamp = bytes.joinToString("") { "%02X".format(it) }
    
    println("Timestamp in hex: $hexTimestamp")
}
// {/fact}

// {fact rule=nan-injection@v1.0 defects=0}
fun good_case_15() {
    val input = "Convert to binary representation"
    val bytes = input.toByteArray(StandardCharsets.UTF_8)
    
    // ok: kotlin-bad-hexa-conversion
    val hexOutput = bytes.joinToString("") { "%02X".format(it) }
    
    val binaryOutput = bytes.joinToString(" ") { 
        Integer.toBinaryString(it.toInt() and 0xFF).padStart(8, '0') 
    }
    
    println("Hex: $hexOutput")
    println("Binary: $binaryOutput")
}
// {/fact}