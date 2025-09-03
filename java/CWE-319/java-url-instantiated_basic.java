import java.net.URL;
import java.net.MalformedURLException;
import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.io.FileInputStream;
import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.net.URLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import java.util.Scanner;

public class URLSecurityExamples {

    // True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-url-instantiated
            URL url = new URL("http://example.com/api/data");
            URLConnection connection = url.openConnection();
            InputStream response = connection.getInputStream();
            // Process the response
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            String apiEndpoint = "http://api.example.org/v1/users";
            // ruleid: java-url-instantiated
            URL url = new URL(apiEndpoint);
            URLConnection connection = url.openConnection();
            // Send sensitive data
            connection.setDoOutput(true);
            connection.getOutputStream().write("username=admin&password=secret123".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        String host = "example.com";
        try {
            // ruleid: java-url-instantiated
            URL url = new URL("http://" + host + "/login");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            // Send login credentials
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            String protocol = "http";
            String domain = "api.example.com";
            // ruleid: java-url-instantiated
            URL url = new URL(protocol + "://" + domain + "/sensitive/data");
            URLConnection connection = url.openConnection();
            // Process sensitive data
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // ruleid: java-url-instantiated
            URL url = new URL("http", "payments.example.com", "/process");
            URLConnection connection = url.openConnection();
            // Process payment information
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            String baseUrl = "http://";
            String endpoint = "api.example.com/user/profile";
            // ruleid: java-url-instantiated
            URL url = new URL(baseUrl + endpoint);
            URLConnection connection = url.openConnection();
            // Fetch user profile data
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // ruleid: java-url-instantiated
            URL url = new URL("http", "example.com", 80, "/checkout");
            URLConnection connection = url.openConnection();
            // Process checkout information
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        Properties config = new Properties();
        try {
            config.load(new FileInputStream("config.properties"));
            String apiUrl = config.getProperty("api.url", "http://default-api.example.com");
            // ruleid: java-url-instantiated
            URL url = new URL(apiUrl);
            URLConnection connection = url.openConnection();
            // Fetch API data
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            String[] endpoints = {"https://secure.example.com", "http://legacy.example.com"};
            for (String endpoint : endpoints) {
                // ruleid: java-url-instantiated
                URL url = new URL(endpoint);
                URLConnection connection = url.openConnection();
                // Process data from both secure and insecure endpoints
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            boolean useSecure = false;
            String protocol = useSecure ? "https" : "http";
            // ruleid: java-url-instantiated
            URL url = new URL(protocol + "://example.com/data");
            URLConnection connection = url.openConnection();
            // Fetch data
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter URL:");
            String userInput = scanner.nextLine();
            if (!userInput.startsWith("https://")) {
                userInput = "http://" + userInput;
            }
            // ruleid: java-url-instantiated
            URL url = new URL(userInput);
            URLConnection connection = url.openConnection();
            // Process user-provided URL
            scanner.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-url-instantiated
            URL url = new URL("http://internal-api.company.local/employee/data");
            URLConnection connection = url.openConnection();
            // Fetch internal employee data over insecure connection
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            String environment = System.getProperty("env", "dev");
            String urlString = environment.equals("prod") ? 
                "https://api.example.com" : "http://dev-api.example.com";
            // ruleid: java-url-instantiated
            URL url = new URL(urlString);
            URLConnection connection = url.openConnection();
            // Fetch API data based on environment
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Using HTTP for file download
            // ruleid: java-url-instantiated
            URL url = new URL("http://downloads.example.com/files/report.pdf");
            URLConnection connection = url.openConnection();
            InputStream in = connection.getInputStream();
            // Download file over insecure connection
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            String[] protocols = {"http", "https"};
            for (String protocol : protocols) {
                // ruleid: java-url-instantiated
                URL url = new URL(protocol, "example.com", "/api/data");
                URLConnection connection = url.openConnection();
                // Process data with different protocols
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-url-instantiated
            URL url = new URL("https://example.com/api/data");
            URLConnection connection = url.openConnection();
            InputStream response = connection.getInputStream();
            // Process the response
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            String apiEndpoint = "https://api.example.org/v1/users";
            // ok: java-url-instantiated
            URL url = new URL(apiEndpoint);
            URLConnection connection = url.openConnection();
            // Send sensitive data
            connection.setDoOutput(true);
            connection.getOutputStream().write("username=admin&password=secret123".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        String host = "example.com";
        try {
            // ok: java-url-instantiated
            URL url = new URL("https://" + host + "/login");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            // Send login credentials
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            String protocol = "https";
            String domain = "api.example.com";
            // ok: java-url-instantiated
            URL url = new URL(protocol + "://" + domain + "/sensitive/data");
            URLConnection connection = url.openConnection();
            // Process sensitive data
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-url-instantiated
            URL url = new URL("https", "payments.example.com", "/process");
            URLConnection connection = url.openConnection();
            // Process payment information
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // Using URI to construct URL with HTTPS
            // ok: java-url-instantiated
            URI uri = new URI("https", null, "api.example.com", -1, "/user/profile", null, null);
            URL url = uri.toURL();
            URLConnection connection = url.openConnection();
            // Fetch user profile data
        } catch (URISyntaxException | IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // ok: java-url-instantiated
            URL url = new URL("https", "example.com", 443, "/checkout");
            URLConnection connection = url.openConnection();
            // Process checkout information
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        Properties config = new Properties();
        try {
            config.load(new FileInputStream("config.properties"));
            String apiUrl = config.getProperty("api.url");
            if (apiUrl != null && apiUrl.startsWith("https://")) {
                // ok: java-url-instantiated
                URL url = new URL(apiUrl);
                URLConnection connection = url.openConnection();
                // Fetch API data
            } else {
                throw new IllegalArgumentException("Only HTTPS URLs are allowed");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            String endpoint = "example.com";
            // ok: java-url-instantiated
            URL url = new URL("https", endpoint, "/api/data");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            // Configure TLS version
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, null, null);
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            // Process data with secure connection
        } catch (IOException | NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            boolean useSecure = true; // Always use secure connections
            String protocol = useSecure ? "https" : "http";
            // ok: java-url-instantiated
            URL url = new URL(protocol + "://example.com/data");
            URLConnection connection = url.openConnection();
            // Fetch data
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter URL (must be HTTPS):");
            String userInput = scanner.nextLine();
            if (!userInput.startsWith("https://")) {
                throw new IllegalArgumentException("Only HTTPS URLs are allowed");
            }
            // ok: java-url-instantiated
            URL url = new URL(userInput);
            URLConnection connection = url.openConnection();
            // Process user-provided URL
            scanner.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // Using Apache HttpClient with HTTPS
            HttpClient httpClient = HttpClients.createDefault();
            // ok: java-url-instantiated
            HttpGet request = new HttpGet("https://api.example.com/data");
            // Execute request and process response
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            String environment = System.getProperty("env", "dev");
            String urlString = environment.equals("prod") ? 
                "https://api.example.com" : "https://dev-api.example.com";
            // ok: java-url-instantiated
            URL url = new URL(urlString);
            URLConnection connection = url.openConnection();
            // Fetch API data based on environment
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // Using HTTPS for file download
            // ok: java-url-instantiated
            URL url = new URL("https://downloads.example.com/files/report.pdf");
            URLConnection connection = url.openConnection();
            InputStream in = connection.getInputStream();
            // Download file over secure connection
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // Using file protocol for local resources (not transmitting over network)
            // ok: java-url-instantiated
            URL url = new URL("file:///home/user/documents/local-data.json");
            URLConnection connection = url.openConnection();
            InputStream in = connection.getInputStream();
            // Process local file
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}