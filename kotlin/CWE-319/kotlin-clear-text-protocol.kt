// File: ClearTextProtocolTests.kt

import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebSettings
import java.net.URL
import java.net.URLConnection
import org.apache.commons.net.ftp.FTPClient
import org.apache.commons.net.telnet.TelnetClient
import javax.mail.Session
import javax.mail.Transport
import javax.mail.internet.MimeMessage
import javax.mail.internet.InternetAddress
import java.util.Properties
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import javax.net.ssl.HttpsURLConnection

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_1() {
    // Using FTP protocol which transmits data in clear text
    val ftpClient = FTPClient()
    // ruleid: kotlin-clear-text-protocol
    ftpClient.connect("ftp.example.com", 21)
    ftpClient.login("username", "password")
    ftpClient.retrieveFile("sensitive_data.txt", System.out)
    ftpClient.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_2() {
    // Using Telnet protocol which transmits data in clear text
    val telnetClient = TelnetClient()
    // ruleid: kotlin-clear-text-protocol
    telnetClient.connect("telnet.example.com", 23)
    val inputStream = telnetClient.inputStream
    val outputStream = telnetClient.outputStream
    val reader = BufferedReader(InputStreamReader(inputStream))
    val writer = PrintWriter(outputStream, true)
    writer.println("username")
    writer.println("password")
    telnetClient.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_3() {
    // Using SMTP protocol without encryption
    val props = Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    props.put("mail.smtp.port", "25")
    
    val session = Session.getInstance(props, null)
    val message = MimeMessage(session)
    message.setFrom(InternetAddress("sender@example.com"))
    message.addRecipient(MimeMessage.RecipientType.TO, InternetAddress("recipient@example.com"))
    message.subject = "Sensitive Information"
    message.setText("This is confidential data being sent over clear text")
    
    // ruleid: kotlin-clear-text-protocol
    Transport.send(message)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_4(webView: WebView) {
    // Allowing mixed content in WebView
    val webSettings = webView.settings
    // ruleid: kotlin-clear-text-protocol
    webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_5() {
    // Using HTTP URL connection which transmits data in clear text
    val url = URL("http://api.example.com/sensitive-data")
    // ruleid: kotlin-clear-text-protocol
    val connection = url.openConnection()
    connection.connect()
    val reader = BufferedReader(InputStreamReader(connection.getInputStream()))
    val response = reader.readLine()
    reader.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_6(webView: WebView) {
    // Setting JavaScript enabled with mixed content allowed
    val webSettings = webView.settings
    webSettings.javaScriptEnabled = true
    // ruleid: kotlin-clear-text-protocol
    webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_7() {
    // Using FTP URL to download sensitive data
    // ruleid: kotlin-clear-text-protocol
    val url = URL("ftp://ftp.example.com/confidential/report.pdf")
    val connection = url.openConnection()
    val inputStream = connection.getInputStream()
    val data = inputStream.readBytes()
    inputStream.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_8() {
    // Using HTTP for API requests
    val url = URL("http://api.example.com/v1/users")
    // ruleid: kotlin-clear-text-protocol
    val connection = url.openConnection() as java.net.HttpURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true
    val writer = PrintWriter(connection.outputStream)
    writer.write("username=admin&password=secret123")
    writer.flush()
    val response = connection.responseCode
    writer.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_9() {
    // Using Telnet for network device configuration
    val telnetClient = TelnetClient()
    // ruleid: kotlin-clear-text-protocol
    telnetClient.connect("router.internal", 23)
    val outputStream = PrintWriter(telnetClient.outputStream, true)
    outputStream.println("admin")
    outputStream.println("network_password")
    outputStream.println("config terminal")
    outputStream.println("exit")
    telnetClient.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_10(webView: WebView) {
    // Loading HTTP URL directly in WebView
    // ruleid: kotlin-clear-text-protocol
    webView.loadUrl("http://example.com/login")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_11() {
    // Using SMTP without TLS for sending sensitive emails
    val props = Properties()
    props.put("mail.smtp.host", "mail.example.com")
    props.put("mail.smtp.port", "25")
    props.put("mail.smtp.auth", "true")
    // Missing TLS configuration
    
    val session = Session.getDefaultInstance(props)
    val message = MimeMessage(session)
    message.setFrom(InternetAddress("sender@example.com"))
    message.addRecipient(MimeMessage.RecipientType.TO, InternetAddress("recipient@example.com"))
    message.subject = "Financial Report"
    message.setText("Attached is the quarterly financial report.")
    
    // ruleid: kotlin-clear-text-protocol
    Transport.send(message)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_12() {
    // Using HTTP URL for authentication
    val url = URL("http://auth.example.com/login")
    // ruleid: kotlin-clear-text-protocol
    val connection = url.openConnection() as java.net.HttpURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
    
    val writer = PrintWriter(connection.outputStream)
    writer.write("username=admin&password=secret123")
    writer.flush()
    writer.close()
    
    val responseCode = connection.responseCode
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_13() {
    // Using FTP to upload sensitive files
    val ftpClient = FTPClient()
    // ruleid: kotlin-clear-text-protocol
    ftpClient.connect("ftp.company.com", 21)
    ftpClient.login("uploader", "upload123")
    ftpClient.setFileType(org.apache.commons.net.ftp.FTP.BINARY_FILE_TYPE)
    
    val inputStream = java.io.FileInputStream("customer_data.csv")
    ftpClient.storeFile("uploads/customer_data.csv", inputStream)
    inputStream.close()
    ftpClient.logout()
    ftpClient.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_14(webView: WebView) {
    // Configuring WebView to allow file access and mixed content
    val webSettings = webView.settings
    webSettings.allowFileAccess = true
    webSettings.allowContentAccess = true
    // ruleid: kotlin-clear-text-protocol
    webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
    webView.loadUrl("file:///android_asset/index.html")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_15() {
    // Using HTTP for downloading application updates
    val url = URL("http://updates.example.com/app/latest.apk")
    // ruleid: kotlin-clear-text-protocol
    val connection = url.openConnection()
    val inputStream = connection.getInputStream()
    val outputStream = java.io.FileOutputStream("latest.apk")
    
    val buffer = ByteArray(1024)
    var bytesRead: Int
    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
        outputStream.write(buffer, 0, bytesRead)
    }
    
    outputStream.close()
    inputStream.close()
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_1() {
    // Using FTPS (FTP over SSL) for secure file transfer
    val ftpClient = org.apache.commons.net.ftp.FTPSClient(true)
    // ok: kotlin-clear-text-protocol
    ftpClient.connect("ftps.example.com", 990)
    ftpClient.login("username", "password")
    ftpClient.execPBSZ(0)
    ftpClient.execPROT("P")
    ftpClient.retrieveFile("sensitive_data.txt", System.out)
    ftpClient.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_2() {
    // Using SSH instead of Telnet for secure remote access
    val jsch = com.jcraft.jsch.JSch()
    val session = jsch.getSession("username", "ssh.example.com", 22)
    session.setPassword("password")
    val config = java.util.Properties()
    config.put("StrictHostKeyChecking", "no")
    session.setConfig(config)
    // ok: kotlin-clear-text-protocol
    session.connect()
    val channel = session.openChannel("shell")
    channel.connect()
    // Use the secure shell channel
    channel.disconnect()
    session.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_3() {
    // Using SMTPS (SMTP over SSL) for secure email transmission
    val props = Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    props.put("mail.smtp.port", "465")
    props.put("mail.smtp.ssl.enable", "true")
    props.put("mail.smtp.auth", "true")
    
    val session = Session.getInstance(props, null)
    val message = MimeMessage(session)
    message.setFrom(InternetAddress("sender@example.com"))
    message.addRecipient(MimeMessage.RecipientType.TO, InternetAddress("recipient@example.com"))
    message.subject = "Sensitive Information"
    message.setText("This is confidential data being sent securely")
    
    // ok: kotlin-clear-text-protocol
    Transport.send(message)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_4(webView: WebView) {
    // Blocking mixed content in WebView
    val webSettings = webView.settings
    // ok: kotlin-clear-text-protocol
    webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_5() {
    // Using HTTPS URL connection which encrypts data in transit
    val url = URL("https://api.example.com/sensitive-data")
    // ok: kotlin-clear-text-protocol
    val connection = url.openConnection() as HttpsURLConnection
    connection.connect()
    val reader = BufferedReader(InputStreamReader(connection.inputStream))
    val response = reader.readLine()
    reader.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_6(webView: WebView) {
    // Setting JavaScript enabled with mixed content blocked
    val webSettings = webView.settings
    webSettings.javaScriptEnabled = true
    // ok: kotlin-clear-text-protocol
    webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_7() {
    // Using SFTP (SSH File Transfer Protocol) for secure file transfer
    val jsch = com.jcraft.jsch.JSch()
    val session = jsch.getSession("username", "sftp.example.com", 22)
    session.setPassword("password")
    val config = java.util.Properties()
    config.put("StrictHostKeyChecking", "no")
    session.setConfig(config)
    session.connect()
    
    // ok: kotlin-clear-text-protocol
    val channel = session.openChannel("sftp")
    channel.connect()
    val sftpChannel = channel as com.jcraft.jsch.ChannelSftp
    sftpChannel.get("confidential/report.pdf", "local_report.pdf")
    sftpChannel.exit()
    session.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_8() {
    // Using HTTPS for API requests
    val url = URL("https://api.example.com/v1/users")
    // ok: kotlin-clear-text-protocol
    val connection = url.openConnection() as HttpsURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true
    val writer = PrintWriter(connection.outputStream)
    writer.write("username=admin&password=secret123")
    writer.flush()
    val response = connection.responseCode
    writer.close()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_9() {
    // Using SSH for network device configuration instead of Telnet
    val jsch = com.jcraft.jsch.JSch()
    val session = jsch.getSession("admin", "router.internal", 22)
    session.setPassword("network_password")
    val config = java.util.Properties()
    config.put("StrictHostKeyChecking", "no")
    session.setConfig(config)
    session.connect()
    
    // ok: kotlin-clear-text-protocol
    val channel = session.openChannel("exec")
    (channel as com.jcraft.jsch.ChannelExec).setCommand("config terminal")
    channel.connect()
    channel.disconnect()
    session.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_10(webView: WebView) {
    // Loading HTTPS URL in WebView
    // ok: kotlin-clear-text-protocol
    webView.loadUrl("https://example.com/login")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_11() {
    // Using SMTP with TLS for sending sensitive emails
    val props = Properties()
    props.put("mail.smtp.host", "mail.example.com")
    props.put("mail.smtp.port", "587")
    props.put("mail.smtp.auth", "true")
    props.put("mail.smtp.starttls.enable", "true")
    
    val session = Session.getDefaultInstance(props)
    val message = MimeMessage(session)
    message.setFrom(InternetAddress("sender@example.com"))
    message.addRecipient(MimeMessage.RecipientType.TO, InternetAddress("recipient@example.com"))
    message.subject = "Financial Report"
    message.setText("Attached is the quarterly financial report.")
    
    // ok: kotlin-clear-text-protocol
    Transport.send(message)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_12() {
    // Using HTTPS URL for authentication
    val url = URL("https://auth.example.com/login")
    // ok: kotlin-clear-text-protocol
    val connection = url.openConnection() as HttpsURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
    
    val writer = PrintWriter(connection.outputStream)
    writer.write("username=admin&password=secret123")
    writer.flush()
    writer.close()
    
    val responseCode = connection.responseCode
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_13() {
    // Using SFTP to upload sensitive files
    val jsch = com.jcraft.jsch.JSch()
    val session = jsch.getSession("uploader", "sftp.company.com", 22)
    session.setPassword("upload123")
    val config = java.util.Properties()
    config.put("StrictHostKeyChecking", "no")
    session.setConfig(config)
    session.connect()
    
    // ok: kotlin-clear-text-protocol
    val channel = session.openChannel("sftp")
    channel.connect()
    val sftpChannel = channel as com.jcraft.jsch.ChannelSftp
    val inputStream = java.io.FileInputStream("customer_data.csv")
    sftpChannel.put(inputStream, "uploads/customer_data.csv")
    inputStream.close()
    sftpChannel.exit()
    session.disconnect()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_14(webView: WebView) {
    // Configuring WebView securely
    val webSettings = webView.settings
    webSettings.allowFileAccess = false
    webSettings.allowContentAccess = false
    // ok: kotlin-clear-text-protocol
    webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_15() {
    // Using HTTPS for downloading application updates
    val url = URL("https://updates.example.com/app/latest.apk")
    // ok: kotlin-clear-text-protocol
    val connection = url.openConnection() as HttpsURLConnection
    val inputStream = connection.inputStream
    val outputStream = java.io.FileOutputStream("latest.apk")
    
    val buffer = ByteArray(1024)
    var bytesRead: Int
    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
        outputStream.write(buffer, 0, bytesRead)
    }
    
    outputStream.close()
    inputStream.close()
}
// {/fact}