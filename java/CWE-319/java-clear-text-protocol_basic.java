import java.net.URL;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HttpsURLConnection;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPSClient;
import java.util.Properties;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;
import org.apache.commons.net.telnet.TelnetClient;
import java.sql.Connection;
import java.sql.DriverManager;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContexts;
import javax.net.ssl.SSLContext;

public class ClearTextProtocolExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("http://example.com/api/data");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-clear-text-protocol
            FTPClient ftpClient = new FTPClient();
            ftpClient.connect("ftp.example.com");
            ftpClient.login("username", "password");
            ftpClient.retrieveFile("sensitive-data.txt", System.out);
            ftpClient.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // ruleid: java-clear-text-protocol
            TelnetClient telnet = new TelnetClient();
            telnet.connect("example.com", 23);
            InputStream in = telnet.getInputStream();
            byte[] buffer = new byte[1024];
            int bytesRead = in.read(buffer);
            System.out.println(new String(buffer, 0, bytesRead));
            telnet.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // ruleid: java-clear-text-protocol
            Socket socket = new Socket("example.com", 80);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // ruleid: java-clear-text-protocol
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("http://example.com/api/users");
            httpClient.execute(request);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            Properties props = new Properties();
            props.put("mail.transport.protocol", "smtp");
            props.put("mail.smtp.host", "smtp.example.com");
            props.put("mail.smtp.port", "25");
            
            Session session = Session.getInstance(props);
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("sender@example.com"));
            message.setRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"));
            message.setSubject("Sensitive Information");
            message.setText("This is sensitive data being sent over clear text SMTP");
            
            // ruleid: java-clear-text-protocol
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("http://api.example.com/v1/users");
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // ruleid: java-clear-text-protocol
            HttpClient httpClient = HttpClients.custom().build();
            HttpPost httpPost = new HttpPost("http://example.com/api/submit");
            httpClient.execute(httpPost);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // ruleid: java-clear-text-protocol
            String jdbcUrl = "jdbc:mysql://localhost:3306/mydb";
            Connection connection = DriverManager.getConnection(jdbcUrl, "username", "password");
            // Perform database operations
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("http://example.com:8080/api/data");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.getOutputStream().write("sensitive=data".getBytes());
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // ruleid: java-clear-text-protocol
            Socket socket = new Socket("example.com", 21); // FTP control port
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String response = reader.readLine();
            System.out.println("FTP Server response: " + response);
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("gopher://example.com/");
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("ldap://ldap.example.com:389");
            URLConnection connection = url.openConnection();
            connection.connect();
            // Process LDAP connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("imap://mail.example.com:143");
            URLConnection connection = url.openConnection();
            connection.connect();
            // Process IMAP connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // ruleid: java-clear-text-protocol
            URL url = new URL("pop3://mail.example.com:110");
            URLConnection connection = url.openConnection();
            connection.connect();
            // Process POP3 connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("https://example.com/api/data");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-clear-text-protocol
            FTPSClient ftpsClient = new FTPSClient(true);
            ftpsClient.connect("ftps.example.com");
            ftpsClient.login("username", "password");
            ftpsClient.retrieveFile("sensitive-data.txt", System.out);
            ftpsClient.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // ok: java-clear-text-protocol
            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("example.com", 443);
            BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            sslSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // ok: java-clear-text-protocol
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                    .build();
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslsf)
                    .build();
            HttpGet request = new HttpGet("https://example.com/api/users");
            httpClient.execute(request);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            Properties props = new Properties();
            props.put("mail.transport.protocol", "smtps");
            props.put("mail.smtps.host", "smtp.example.com");
            props.put("mail.smtps.port", "465");
            props.put("mail.smtps.auth", "true");
            props.put("mail.smtps.ssl.enable", "true");
            
            Session session = Session.getInstance(props);
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("sender@example.com"));
            message.setRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"));
            message.setSubject("Sensitive Information");
            message.setText("This is sensitive data being sent over encrypted SMTPS");
            
            // ok: java-clear-text-protocol
            Transport transport = session.getTransport("smtps");
            transport.connect("smtp.example.com", "username", "password");
            transport.sendMessage(message, message.getAllRecipients());
            transport.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("https://api.example.com/v1/users");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // ok: java-clear-text-protocol
            HttpClient httpClient = HttpClients.custom().build();
            HttpPost httpPost = new HttpPost("https://example.com/api/submit");
            httpClient.execute(httpPost);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // ok: java-clear-text-protocol
            String jdbcUrl = "jdbc:mysql://localhost:3306/mydb?useSSL=true&requireSSL=true";
            Connection connection = DriverManager.getConnection(jdbcUrl, "username", "password");
            // Perform database operations
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("https://example.com:8443/api/data");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.getOutputStream().write("sensitive=data".getBytes());
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("sftp://example.com:22/path/to/file");
            URLConnection connection = url.openConnection();
            // Process SFTP connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("ldaps://ldap.example.com:636");
            URLConnection connection = url.openConnection();
            connection.connect();
            // Process secure LDAP connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("imaps://mail.example.com:993");
            URLConnection connection = url.openConnection();
            connection.connect();
            // Process secure IMAPS connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // ok: java-clear-text-protocol
            URL url = new URL("pop3s://mail.example.com:995");
            URLConnection connection = url.openConnection();
            connection.connect();
            // Process secure POP3S connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-clear-text-protocol
            String jdbcUrl = "jdbc:postgresql://localhost:5432/mydb?ssl=true";
            Connection connection = DriverManager.getConnection(jdbcUrl, "username", "password");
            // Perform database operations with SSL
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // ok: java-clear-text-protocol
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("example.com", 443);
            socket.startHandshake();
            // Secure communication
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}