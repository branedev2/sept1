import java.io.*
import java.net.*
import javax.net.ssl.*
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_1() {
    val socket = Socket("example.com", 80)
    val outputStream = socket.getOutputStream()
    val writer = PrintWriter(outputStream, true)
    
    val username = "admin"
    val password = "secret123"
    
    // ruleid: kotlin-unencrypted-socket
    writer.println("LOGIN $username $password")
    
    val inputStream = socket.getInputStream()
    val reader = BufferedReader(InputStreamReader(inputStream))
    val response = reader.readLine()
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_2() {
    val serverAddress = InetAddress.getByName("api.example.com")
    val port = 8080
    
    // ruleid: kotlin-unencrypted-socket
    val socket = Socket(serverAddress, port)
    
    val outputStream = DataOutputStream(socket.getOutputStream())
    val creditCardNumber = "4111-1111-1111-1111"
    val cvv = "123"
    
    outputStream.writeBytes("PAYMENT $creditCardNumber $cvv\n")
    
    val inputStream = DataInputStream(socket.getInputStream())
    val response = inputStream.readUTF()
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_3() {
    val serverSocket = ServerSocket(9000)
    println("Server listening on port 9000")
    
    // ruleid: kotlin-unencrypted-socket
    val clientSocket = serverSocket.accept()
    
    val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
    val writer = PrintWriter(clientSocket.getOutputStream(), true)
    
    val request = reader.readLine()
    if (request.startsWith("GET_USER_DATA")) {
        val userData = "SSN: 123-45-6789, DOB: 01/01/1980"
        writer.println(userData)
    }
    
    clientSocket.close()
    serverSocket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_4() {
    thread {
        try {
            // ruleid: kotlin-unencrypted-socket
            val socket = Socket("database.example.com", 5432)
            val out = PrintWriter(socket.getOutputStream(), true)
            val in = BufferedReader(InputStreamReader(socket.getInputStream()))
            
            out.println("SELECT * FROM users WHERE username='admin' AND password='adminpass'")
            val response = in.readLine()
            println("Database response: $response")
            
            socket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_5() {
    val host = "payment-gateway.example.com"
    val port = 7777
    
    try {
        // ruleid: kotlin-unencrypted-socket
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), 5000) // 5 second timeout
        
        val out = PrintWriter(socket.getOutputStream(), true)
        val paymentInfo = "card_type=VISA&card_number=4111111111111111&expiry=12/25&cvv=123"
        out.println("POST /process_payment HTTP/1.1")
        out.println("Content-Type: application/x-www-form-urlencoded")
        out.println("Content-Length: ${paymentInfo.length}")
        out.println()
        out.println(paymentInfo)
        
        val in = BufferedReader(InputStreamReader(socket.getInputStream()))
        var line: String?
        while (in.readLine().also { line = it } != null) {
            println(line)
        }
        
        socket.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_6() {
    val socket = Socket()
    val address = InetSocketAddress("auth.example.com", 8888)
    
    // ruleid: kotlin-unencrypted-socket
    socket.connect(address)
    
    val outputStream = socket.getOutputStream()
    val writer = OutputStreamWriter(outputStream)
    
    val authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    writer.write("Authorization: Bearer $authToken\n")
    writer.flush()
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_7() {
    val host = "api.example.org"
    val port = 1234
    
    try {
        // ruleid: kotlin-unencrypted-socket
        val socket = Socket(host, port)
        val out = DataOutputStream(socket.getOutputStream())
        
        val healthData = """
            {
                "patient_id": "12345",
                "blood_type": "O+",
                "allergies": ["penicillin", "peanuts"],
                "medical_history": "Appendectomy in 2018, chronic asthma"
            }
        """.trimIndent()
        
        out.writeBytes(healthData)
        out.flush()
        
        val in = DataInputStream(socket.getInputStream())
        val buffer = ByteArray(1024)
        val bytesRead = in.read(buffer)
        val response = String(buffer, 0, bytesRead)
        
        socket.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_8() {
    val serverSocket = ServerSocket(6543)
    println("Chat server started on port 6543")
    
    while (true) {
        try {
            // ruleid: kotlin-unencrypted-socket
            val clientSocket = serverSocket.accept()
            println("Client connected: ${clientSocket.inetAddress.hostAddress}")
            
            thread {
                val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                val writer = PrintWriter(clientSocket.getOutputStream(), true)
                
                var message: String?
                while (reader.readLine().also { message = it } != null) {
                    println("Received: $message")
                    writer.println("Server received: $message")
                }
                
                clientSocket.close()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            break
        }
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_9() {
    val addresses = InetAddress.getAllByName("mail.example.com")
    
    // ruleid: kotlin-unencrypted-socket
    val socket = Socket(addresses[0], 25) // SMTP port
    
    val writer = PrintWriter(socket.getOutputStream(), true)
    val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
    
    // Read greeting
    reader.readLine()
    
    // SMTP commands
    writer.println("HELO example.com")
    reader.readLine()
    
    writer.println("MAIL FROM: <sender@example.com>")
    reader.readLine()
    
    writer.println("RCPT TO: <recipient@example.com>")
    reader.readLine()
    
    writer.println("DATA")
    reader.readLine()
    
    writer.println("Subject: Confidential Information")
    writer.println("From: sender@example.com")
    writer.println("To: recipient@example.com")
    writer.println()
    writer.println("This email contains sensitive company financial data.")
    writer.println("Revenue: $10,000,000")
    writer.println("Profit: $2,500,000")
    writer.println(".")
    
    reader.readLine()
    writer.println("QUIT")
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_10() {
    // ruleid: kotlin-unencrypted-socket
    val socket = Socket("fileserver.example.com", 21) // FTP port
    
    val writer = PrintWriter(socket.getOutputStream(), true)
    val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
    
    // Read welcome message
    reader.readLine()
    
    // Login
    writer.println("USER admin")
    reader.readLine()
    
    writer.println("PASS secretpassword")
    reader.readLine()
    
    // Request file with sensitive data
    writer.println("RETR /confidential/employee_salaries.csv")
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_11() {
    val serverName = "internal-api.example.com"
    val serverPort = 4321
    
    try {
        // ruleid: kotlin-unencrypted-socket
        val clientSocket = Socket(serverName, serverPort)
        val out = PrintWriter(clientSocket.getOutputStream(), true)
        val in = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
        
        // Send API key in plaintext
        out.println("X-API-Key: a1b2c3d4e5f6g7h8i9j0")
        
        // Send request
        out.println("GET /api/v1/users/sensitive-data HTTP/1.1")
        out.println("Host: $serverName")
        out.println()
        
        // Read response
        var inputLine: String?
        val response = StringBuilder()
        while (in.readLine().also { inputLine = it } != null) {
            response.append(inputLine)
        }
        
        clientSocket.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_12() {
    val serverSocket = ServerSocket(3333)
    
    try {
        while (true) {
            // ruleid: kotlin-unencrypted-socket
            val socket = serverSocket.accept()
            
            thread {
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                
                // Receive login credentials
                val username = input.readUTF()
                val password = input.readUTF()
                
                // Authenticate (simplified)
                val authenticated = (username == "admin" && password == "admin123")
                
                if (authenticated) {
                    // Send back sensitive user data
                    output.writeUTF("User ID: 12345, Access Level: Admin, Security Clearance: Top Secret")
                } else {
                    output.writeUTF("Authentication failed")
                }
                
                socket.close()
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        serverSocket.close()
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_13() {
    val host = "config-server.example.com"
    val port = 5555
    
    // ruleid: kotlin-unencrypted-socket
    val socket = Socket(host, port)
    
    val out = PrintWriter(socket.getOutputStream(), true)
    val in = BufferedReader(InputStreamReader(socket.getInputStream()))
    
    // Request database configuration with credentials
    out.println("GET_CONFIG database")
    
    val response = in.readLine()
    // Parse response to extract database credentials
    val dbConfig = response.split(",")
    val dbHost = dbConfig[0]
    val dbUser = dbConfig[1]
    val dbPass = dbConfig[2]
    
    println("Database configured with host=$dbHost, user=$dbUser, pass=$dbPass")
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_14() {
    val socket = Socket()
    
    try {
        // ruleid: kotlin-unencrypted-socket
        socket.connect(InetSocketAddress("licensing-server.example.com", 7890), 3000)
        
        val out = DataOutputStream(socket.getOutputStream())
        val in = DataInputStream(socket.getInputStream())
        
        // Send license key validation request
        val licenseKey = "ABCD-EFGH-IJKL-MNOP-QRST"
        val productId = "ENTERPRISE-CRM-2023"
        val companyName = "Acme Corporation"
        val employeeCount = 500
        
        out.writeUTF(licenseKey)
        out.writeUTF(productId)
        out.writeUTF(companyName)
        out.writeInt(employeeCount)
        
        // Get validation response
        val isValid = in.readBoolean()
        val expirationDate = in.readUTF()
        
        println("License valid: $isValid, expires: $expirationDate")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        socket.close()
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_15() {
    val serverAddress = "backup-server.example.com"
    val serverPort = 2222
    
    // ruleid: kotlin-unencrypted-socket
    val socket = Socket(serverAddress, serverPort)
    
    val out = PrintWriter(socket.getOutputStream(), true)
    
    // Send backup data including sensitive information
    out.println("BEGIN_BACKUP")
    out.println("customer_database.sql")
    out.println("-- SQL Dump of Customer Database")
    out.println("CREATE TABLE customers (id INT, name VARCHAR(100), email VARCHAR(100), credit_card VARCHAR(16), ssn VARCHAR(11));")
    out.println("INSERT INTO customers VALUES (1, 'John Doe', 'john@example.com', '4111111111111111', '123-45-6789');")
    out.println("INSERT INTO customers VALUES (2, 'Jane Smith', 'jane@example.com', '5555555555554444', '987-65-4321');")
    out.println("END_BACKUP")
    
    socket.close()
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_1() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslSocketFactory = sslContext.socketFactory
    
    // ok: kotlin-unencrypted-socket
    val socket = sslSocketFactory.createSocket("example.com", 443)
    
    val outputStream = socket.getOutputStream()
    val writer = PrintWriter(outputStream, true)
    
    val username = "admin"
    val password = "secret123"
    
    writer.println("LOGIN $username $password")
    
    val inputStream = socket.getInputStream()
    val reader = BufferedReader(InputStreamReader(inputStream))
    val response = reader.readLine()
    
    socket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_2() {
    val url = URL("https://api.example.com:8443/payment")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    
    connection.requestMethod = "POST"
    connection.doOutput = true
    
    val creditCardNumber = "4111-1111-1111-1111"
    val cvv = "123"
    val data = "card=$creditCardNumber&cvv=$cvv"
    
    val outputStream = connection.outputStream
    outputStream.write(data.toByteArray())
    
    val inputStream = connection.inputStream
    val reader = BufferedReader(InputStreamReader(inputStream))
    val response = reader.readLine()
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_3() {
    val sslContext = SSLContext.getInstance("TLS")
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) {}
    })
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    
    val sslServerSocketFactory = sslContext.serverSocketFactory
    
    // ok: kotlin-unencrypted-socket
    val serverSocket = sslServerSocketFactory.createServerSocket(9000)
    println("Secure server listening on port 9000")
    
    val clientSocket = serverSocket.accept()
    
    val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
    val writer = PrintWriter(clientSocket.getOutputStream(), true)
    
    val request = reader.readLine()
    if (request.startsWith("GET_USER_DATA")) {
        val userData = "SSN: 123-45-6789, DOB: 01/01/1980"
        writer.println(userData)
    }
    
    clientSocket.close()
    serverSocket.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_4() {
    thread {
        try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, null, null)
            val sslSocketFactory = sslContext.socketFactory
            
            // ok: kotlin-unencrypted-socket
            val socket = sslSocketFactory.createSocket("database.example.com", 5432)
            
            val out = PrintWriter(socket.getOutputStream(), true)
            val in = BufferedReader(InputStreamReader(socket.getInputStream()))
            
            out.println("SELECT * FROM users WHERE username='admin' AND password='adminpass'")
            val response = in.readLine()
            println("Database response: $response")
            
            socket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_5() {
    val url = URL("https://payment-gateway.example.com:7777/process_payment")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    connection.connectTimeout = 5000
    
    connection.requestMethod = "POST"
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
    
    val paymentInfo = "card_type=VISA&card_number=4111111111111111&expiry=12/25&cvv=123"
    
    val out = DataOutputStream(connection.outputStream)
    out.writeBytes(paymentInfo)
    out.flush()
    
    val in = BufferedReader(InputStreamReader(connection.inputStream))
    var line: String?
    val response = StringBuilder()
    while (in.readLine().also { line = it } != null) {
        response.append(line)
    }
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_6() {
    val url = URL("https://auth.example.com:8888/authenticate")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    
    val authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    connection.setRequestProperty("Authorization", "Bearer $authToken")
    
    val responseCode = connection.responseCode
    println("Response Code: $responseCode")
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_7() {
    val url = URL("https://api.example.org:1234/health-data")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/json")
    
    val healthData = """
        {
            "patient_id": "12345",
            "blood_type": "O+",
            "allergies": ["penicillin", "peanuts"],
            "medical_history": "Appendectomy in 2018, chronic asthma"
        }
    """.trimIndent()
    
    val out = DataOutputStream(connection.outputStream)
    out.writeBytes(healthData)
    out.flush()
    
    val in = BufferedReader(InputStreamReader(connection.inputStream))
    val response = in.readLine()
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_8() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslServerSocketFactory = sslContext.serverSocketFactory
    
    // ok: kotlin-unencrypted-socket
    val serverSocket = sslServerSocketFactory.createServerSocket(6543)
    println("Secure chat server started on port 6543")
    
    while (true) {
        try {
            val clientSocket = serverSocket.accept()
            println("Client connected securely: ${clientSocket.inetAddress.hostAddress}")
            
            thread {
                val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                val writer = PrintWriter(clientSocket.getOutputStream(), true)
                
                var message: String?
                while (reader.readLine().also { message = it } != null) {
                    println("Received: $message")
                    writer.println("Server received: $message")
                }
                
                clientSocket.close()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            break
        }
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_9() {
    val properties = Properties()
    val session = javax.mail.Session.getDefaultInstance(properties)
    
    // ok: kotlin-unencrypted-socket
    val transport = session.getTransport("smtps")
    transport.connect("mail.example.com", 465, "username", "password")
    
    val message = javax.mail.internet.MimeMessage(session)
    message.setFrom(javax.mail.internet.InternetAddress("sender@example.com"))
    message.addRecipient(javax.mail.Message.RecipientType.TO, javax.mail.internet.InternetAddress("recipient@example.com"))
    message.subject = "Confidential Information"
    message.setText("This email contains sensitive company financial data.\nRevenue: $10,000,000\nProfit: $2,500,000")
    
    transport.sendMessage(message, message.allRecipients)
    transport.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_10() {
    val url = URL("https://fileserver.example.com:990/confidential/employee_salaries.csv")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    
    connection.requestMethod = "GET"
    connection.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString("admin:secretpassword".toByteArray()))
    
    val inputStream = connection.inputStream
    val reader = BufferedReader(InputStreamReader(inputStream))
    val content = StringBuilder()
    
    var line: String?
    while (reader.readLine().also { line = it } != null) {
        content.append(line).append("\n")
    }
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_11() {
    val url = URL("https://internal-api.example.com:4321/api/v1/users/sensitive-data")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    connection.requestMethod = "GET"
    connection.setRequestProperty("X-API-Key", "a1b2c3d4e5f6g7h8i9j0")
    
    val responseCode = connection.responseCode
    if (responseCode == HttpURLConnection.HTTP_OK) {
        val in = BufferedReader(InputStreamReader(connection.inputStream))
        val response = StringBuilder()
        var inputLine: String?
        
        while (in.readLine().also { inputLine = it } != null) {
            response.append(inputLine)
        }
        in.close()
        
        println("Response: $response")
    } else {
        println("Request failed with response code: $responseCode")
    }
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_12() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslServerSocketFactory = sslContext.serverSocketFactory
    
    // ok: kotlin-unencrypted-socket
    val serverSocket = sslServerSocketFactory.createServerSocket(3333)
    
    try {
        while (true) {
            val socket = serverSocket.accept()
            
            thread {
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                
                // Receive login credentials
                val username = input.readUTF()
                val password = input.readUTF()
                
                // Authenticate (simplified)
                val authenticated = (username == "admin" && password == "admin123")
                
                if (authenticated) {
                    // Send back sensitive user data
                    output.writeUTF("User ID: 12345, Access Level: Admin, Security Clearance: Top Secret")
                } else {
                    output.writeUTF("Authentication failed")
                }
                
                socket.close()
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        serverSocket.close()
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_13() {
    val url = URL("https://config-server.example.com:5555/config/database")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    connection.requestMethod = "GET"
    
    val in = BufferedReader(InputStreamReader(connection.inputStream))
    val response = in.readLine()
    
    // Parse response to extract database credentials
    val dbConfig = response.split(",")
    val dbHost = dbConfig[0]
    val dbUser = dbConfig[1]
    val dbPass = dbConfig[2]
    
    println("Database configured with host=$dbHost, user=$dbUser, pass=$dbPass")
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_14() {
    val url = URL("https://licensing-server.example.com:7890/validate")
    
    // ok: kotlin-unencrypted-socket
    val connection = url.openConnection() as HttpsURLConnection
    connection.connectTimeout = 3000
    connection.requestMethod = "POST"
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/json")
    
    val licenseKey = "ABCD-EFGH-IJKL-MNOP-QRST"
    val productId = "ENTERPRISE-CRM-2023"
    val companyName = "Acme Corporation"
    val employeeCount = 500
    
    val jsonPayload = """
        {
            "licenseKey": "$licenseKey",
            "productId": "$productId",
            "companyName": "$companyName",
            "employeeCount": $employeeCount
        }
    """.trimIndent()
    
    val out = DataOutputStream(connection.outputStream)
    out.writeBytes(jsonPayload)
    out.flush()
    
    val responseCode = connection.responseCode
    if (responseCode == HttpURLConnection.HTTP_OK) {
        val in = BufferedReader(InputStreamReader(connection.inputStream))
        val response = in.readLine()
        println("License validation response: $response")
    }
    
    connection.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_15() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslSocketFactory = sslContext.socketFactory
    
    // ok: kotlin-unencrypted-socket
    val socket = sslSocketFactory.createSocket("backup-server.example.com", 2222)
    
    val out = PrintWriter(socket.getOutputStream(), true)
    
    // Send backup data including sensitive information
    out.println("BEGIN_BACKUP")
    out.println("customer_database.sql")
    out.println("-- SQL Dump of Customer Database")
    out.println("CREATE TABLE customers (id INT, name VARCHAR(100), email VARCHAR(100), credit_card VARCHAR(16), ssn VARCHAR(11));")
    out.println("INSERT INTO customers VALUES (1, 'John Doe', 'john@example.com', '4111111111111111', '123-45-6789');")
    out.println("INSERT INTO customers VALUES (2, 'Jane Smith', 'jane@example.com', '5555555555554444', '987-65-4321');")
    out.println("END_BACKUP")
    
    socket.close()
}
// {/fact}