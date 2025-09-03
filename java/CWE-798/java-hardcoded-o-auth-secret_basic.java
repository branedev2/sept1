import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class OAuthSecretExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        URL url = new URL("https://api.example.com/oauth/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        String clientId = "my-client-id";
        String clientSecret = "my-super-secret-value-12345";
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
        connection.connect();
    }

    public void bad_case_2() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://oauth2.googleapis.com/token");
        
        String clientId = "google-client-id";
        String clientSecret = "google-oauth2-secret-key-abc123";
        String credentials = clientId + ":" + clientSecret;
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", "Basic " + encoded);
        httpClient.execute(httpPost);
    }

    public void bad_case_3() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        String oauthClientId = "client_12345";
        String oauthSecret = "oauth2-secret-value-xyz789";
        String authString = oauthClientId + ":" + oauthSecret;
        String encodedAuthString = Base64.getEncoder().encodeToString(authString.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthString);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
                "https://auth.example.org/oauth/token", 
                HttpMethod.POST, 
                entity, 
                String.class);
    }

    public void bad_case_4() throws IOException {
        OkHttpClient client = new OkHttpClient();
        
        String clientId = "okhttp-client";
        String clientSecret = "okhttp-secret-token-456def";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        Request request = new Request.Builder()
                .url("https://api.service.com/oauth/token")
                // ruleid: java-hardcoded-o-auth-secret
                .header("Authorization", "Basic " + encodedCredentials)
                .build();
                
        Response response = client.newCall(request).execute();
    }

    public void bad_case_5() throws IOException {
        URL url = new URL("https://api.twitter.com/oauth2/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Hard-coded Twitter API OAuth credentials
        String apiKey = "twitter-api-key-123";
        String apiSecretKey = "twitter-api-secret-key-456abc";
        String combined = apiKey + ":" + apiSecretKey;
        String base64Encoded = Base64.getEncoder().encodeToString(combined.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + base64Encoded);
        connection.connect();
    }

    public void bad_case_6() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.github.com/user");
        
        // Hard-coded GitHub OAuth token
        String clientId = "github-oauth-client";
        String clientSecret = "github-oauth-secret-789xyz";
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        httpGet.setHeader("Authorization", "Basic " + encodedAuth);
        httpClient.execute(httpGet);
    }

    public void bad_case_7() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Hard-coded Salesforce OAuth credentials
        String sfClientId = "salesforce-client-id";
        String sfClientSecret = "salesforce-client-secret-key-123456";
        String authValue = sfClientId + ":" + sfClientSecret;
        String encodedAuthValue = Base64.getEncoder().encodeToString(authValue.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthValue);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        restTemplate.exchange("https://login.salesforce.com/services/oauth2/token", 
                HttpMethod.POST, entity, String.class);
    }

    public void bad_case_8() throws IOException {
        OkHttpClient client = new OkHttpClient();
        
        // Hard-coded Azure AD OAuth credentials
        String azureClientId = "azure-ad-client-id";
        String azureClientSecret = "azure-ad-client-secret-value-987654";
        String credentials = azureClientId + ":" + azureClientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        Request request = new Request.Builder()
                .url("https://login.microsoftonline.com/common/oauth2/v2.0/token")
                // ruleid: java-hardcoded-o-auth-secret
                .header("Authorization", "Basic " + encodedCredentials)
                .build();
                
        Response response = client.newCall(request).execute();
    }

    public void bad_case_9() throws IOException {
        URL url = new URL("https://accounts.google.com/o/oauth2/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Hard-coded Google OAuth credentials in a different format
        String clientId = "google-client-id-123";
        String clientSecret = "google-client-secret-456";
        String combined = clientId + ":" + clientSecret;
        String base64Encoded = Base64.getEncoder().encodeToString(combined.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + base64Encoded);
        connection.connect();
    }

    public void bad_case_10() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.dropbox.com/oauth2/token");
        
        // Hard-coded Dropbox OAuth credentials
        String clientId = "dropbox-app-key";
        String clientSecret = "dropbox-app-secret-789xyz";
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", "Basic " + encodedAuth);
        httpClient.execute(httpPost);
    }

    public void bad_case_11() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Hard-coded Slack OAuth credentials
        String slackClientId = "slack-client-id";
        String slackClientSecret = "slack-client-secret-abcdef123456";
        String authValue = slackClientId + ":" + slackClientSecret;
        String encodedAuthValue = Base64.getEncoder().encodeToString(authValue.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthValue);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        restTemplate.exchange("https://slack.com/api/oauth.v2.access", 
                HttpMethod.POST, entity, String.class);
    }

    public void bad_case_12() throws IOException {
        OkHttpClient client = new OkHttpClient();
        
        // Hard-coded LinkedIn OAuth credentials
        String linkedInClientId = "linkedin-client-id";
        String linkedInClientSecret = "linkedin-client-secret-value-123abc";
        String credentials = linkedInClientId + ":" + linkedInClientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        Request request = new Request.Builder()
                .url("https://www.linkedin.com/oauth/v2/accessToken")
                // ruleid: java-hardcoded-o-auth-secret
                .header("Authorization", "Basic " + encodedCredentials)
                .build();
                
        Response response = client.newCall(request).execute();
    }

    public void bad_case_13() throws IOException {
        URL url = new URL("https://api.box.com/oauth2/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Hard-coded Box OAuth credentials
        String boxClientId = "box-client-id-123";
        String boxClientSecret = "box-client-secret-456def";
        String combined = boxClientId + ":" + boxClientSecret;
        String base64Encoded = Base64.getEncoder().encodeToString(combined.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + base64Encoded);
        connection.connect();
    }

    public void bad_case_14() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://zoom.us/oauth/token");
        
        // Hard-coded Zoom OAuth credentials
        String zoomClientId = "zoom-client-id";
        String zoomClientSecret = "zoom-client-secret-789ghi";
        String auth = zoomClientId + ":" + zoomClientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", "Basic " + encodedAuth);
        httpClient.execute(httpPost);
    }

    public void bad_case_15() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Hard-coded custom OAuth server credentials
        String customClientId = "my-custom-client";
        String customClientSecret = "my-custom-secret-value-xyz987";
        String authValue = customClientId + ":" + customClientSecret;
        String encodedAuthValue = Base64.getEncoder().encodeToString(authValue.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthValue);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        restTemplate.exchange("https://auth.mycompany.com/oauth/token", 
                HttpMethod.POST, entity, String.class);
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() throws IOException {
        URL url = new URL("https://api.example.com/oauth/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Get credentials from environment variables
        String clientId = System.getenv("OAUTH_CLIENT_ID");
        String clientSecret = System.getenv("OAUTH_CLIENT_SECRET");
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
        connection.connect();
    }

    public void good_case_2() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://oauth2.googleapis.com/token");
        
        // Load credentials from properties file
        Properties props = new Properties();
        try (InputStream input = new FileInputStream("config.properties")) {
            props.load(input);
        }
        
        String clientId = props.getProperty("google.client.id");
        String clientSecret = props.getProperty("google.client.secret");
        String credentials = clientId + ":" + clientSecret;
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", "Basic " + encoded);
        httpClient.execute(httpPost);
    }

    public void good_case_3() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Get credentials from a secure vault service
        SecureVaultService secureVault = new SecureVaultService();
        String oauthClientId = secureVault.getSecret("oauth.client.id");
        String oauthSecret = secureVault.getSecret("oauth.client.secret");
        String authString = oauthClientId + ":" + oauthSecret;
        String encodedAuthString = Base64.getEncoder().encodeToString(authString.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthString);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
                "https://auth.example.org/oauth/token", 
                HttpMethod.POST, 
                entity, 
                String.class);
    }

    public void good_case_4() throws IOException {
        OkHttpClient client = new OkHttpClient();
        
        // Get credentials from system properties
        String clientId = System.getProperty("okhttp.client.id");
        String clientSecret = System.getProperty("okhttp.client.secret");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        Request request = new Request.Builder()
                .url("https://api.service.com/oauth/token")
                // ok: java-hardcoded-o-auth-secret
                .header("Authorization", "Basic " + encodedCredentials)
                .build();
                
        Response response = client.newCall(request).execute();
    }

    public void good_case_5() throws IOException {
        URL url = new URL("https://api.twitter.com/oauth2/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Get Twitter API OAuth credentials from environment variables
        String apiKey = System.getenv("TWITTER_API_KEY");
        String apiSecretKey = System.getenv("TWITTER_API_SECRET_KEY");
        String combined = apiKey + ":" + apiSecretKey;
        String base64Encoded = Base64.getEncoder().encodeToString(combined.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + base64Encoded);
        connection.connect();
    }

    public void good_case_6() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.github.com/user");
        
        // Load GitHub OAuth credentials from configuration file
        Properties config = new Properties();
        try (FileInputStream fis = new FileInputStream("github-config.properties")) {
            config.load(fis);
        }
        
        String clientId = config.getProperty("github.client.id");
        String clientSecret = config.getProperty("github.client.secret");
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        httpGet.setHeader("Authorization", "Basic " + encodedAuth);
        httpClient.execute(httpGet);
    }

    public void good_case_7() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Get Salesforce OAuth credentials from database
        DatabaseCredentialProvider credProvider = new DatabaseCredentialProvider();
        Map<String, String> sfCredentials = credProvider.getCredentials("salesforce");
        String sfClientId = sfCredentials.get("clientId");
        String sfClientSecret = sfCredentials.get("clientSecret");
        String authValue = sfClientId + ":" + sfClientSecret;
        String encodedAuthValue = Base64.getEncoder().encodeToString(authValue.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthValue);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        restTemplate.exchange("https://login.salesforce.com/services/oauth2/token", 
                HttpMethod.POST, entity, String.class);
    }

    public void good_case_8() throws IOException {
        OkHttpClient client = new OkHttpClient();
        
        // Get Azure AD OAuth credentials from a secure key vault
        AzureKeyVaultClient keyVault = new AzureKeyVaultClient();
        String azureClientId = keyVault.getSecret("azure-ad-client-id");
        String azureClientSecret = keyVault.getSecret("azure-ad-client-secret");
        String credentials = azureClientId + ":" + azureClientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        Request request = new Request.Builder()
                .url("https://login.microsoftonline.com/common/oauth2/v2.0/token")
                // ok: java-hardcoded-o-auth-secret
                .header("Authorization", "Basic " + encodedCredentials)
                .build();
                
        Response response = client.newCall(request).execute();
    }

    public void good_case_9() throws IOException {
        URL url = new URL("https://accounts.google.com/o/oauth2/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Get Google OAuth credentials from encrypted file
        EncryptedFileReader encryptedReader = new EncryptedFileReader("google-creds.enc");
        Map<String, String> googleCreds = encryptedReader.readCredentials();
        String clientId = googleCreds.get("clientId");
        String clientSecret = googleCreds.get("clientSecret");
        String combined = clientId + ":" + clientSecret;
        String base64Encoded = Base64.getEncoder().encodeToString(combined.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + base64Encoded);
        connection.connect();
    }

    public void good_case_10() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.dropbox.com/oauth2/token");
        
        // Get Dropbox OAuth credentials from environment variables with fallback
        String clientId = System.getenv("DROPBOX_CLIENT_ID");
        String clientSecret = System.getenv("DROPBOX_CLIENT_SECRET");
        
        // If environment variables are not set, use a secure configuration service
        if (clientId == null || clientSecret == null) {
            ConfigurationService configService = new ConfigurationService();
            clientId = configService.getSecureConfig("dropbox.client.id");
            clientSecret = configService.getSecureConfig("dropbox.client.secret");
        }
        
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", "Basic " + encodedAuth);
        httpClient.execute(httpPost);
    }

    public void good_case_11() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Get Slack OAuth credentials from a secure credential manager
        CredentialManager credManager = CredentialManager.getInstance();
        String slackClientId = credManager.getCredential("slack.client.id");
        String slackClientSecret = credManager.getCredential("slack.client.secret");
        String authValue = slackClientId + ":" + slackClientSecret;
        String encodedAuthValue = Base64.getEncoder().encodeToString(authValue.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthValue);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        restTemplate.exchange("https://slack.com/api/oauth.v2.access", 
                HttpMethod.POST, entity, String.class);
    }

    public void good_case_12() throws IOException {
        OkHttpClient client = new OkHttpClient();
        
        // Get LinkedIn OAuth credentials from a properties file loaded at runtime
        Properties linkedInProps = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("linkedin.properties")) {
            linkedInProps.load(input);
        }
        
        String linkedInClientId = linkedInProps.getProperty("linkedin.client.id");
        String linkedInClientSecret = linkedInProps.getProperty("linkedin.client.secret");
        String credentials = linkedInClientId + ":" + linkedInClientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        Request request = new Request.Builder()
                .url("https://www.linkedin.com/oauth/v2/accessToken")
                // ok: java-hardcoded-o-auth-secret
                .header("Authorization", "Basic " + encodedCredentials)
                .build();
                
        Response response = client.newCall(request).execute();
    }

    public void good_case_13() throws IOException {
        URL url = new URL("https://api.box.com/oauth2/token");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        
        // Get Box OAuth credentials from a secure external service
        ExternalSecretService secretService = new ExternalSecretService();
        String boxClientId = secretService.fetchSecret("BOX_CLIENT_ID");
        String boxClientSecret = secretService.fetchSecret("BOX_CLIENT_SECRET");
        String combined = boxClientId + ":" + boxClientSecret;
        String base64Encoded = Base64.getEncoder().encodeToString(combined.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        connection.setRequestProperty("Authorization", "Basic " + base64Encoded);
        connection.connect();
    }

    public void good_case_14() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://zoom.us/oauth/token");
        
        // Get Zoom OAuth credentials from a secure file with restricted permissions
        String credentialsFilePath = "/etc/secrets/zoom-credentials.txt";
        List<String> lines = Files.readAllLines(Paths.get(credentialsFilePath));
        String zoomClientId = lines.get(0);
        String zoomClientSecret = lines.get(1);
        
        String auth = zoomClientId + ":" + zoomClientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", "Basic " + encodedAuth);
        httpClient.execute(httpPost);
    }

    public void good_case_15(HttpServletRequest request) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // Get custom OAuth server credentials from a secure session attribute
        // This is a more advanced pattern where credentials might be obtained after user authentication
        String customClientId = (String) request.getSession().getAttribute("oauth_client_id");
        String customClientSecret = (String) request.getSession().getAttribute("oauth_client_secret");
        String authValue = customClientId + ":" + customClientSecret;
        String encodedAuthValue = Base64.getEncoder().encodeToString(authValue.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        headers.set("Authorization", "Basic " + encodedAuthValue);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        restTemplate.exchange("https://auth.mycompany.com/oauth/token", 
                HttpMethod.POST, entity, String.class);
    }
    
    // Helper classes for the examples (mock implementations)
    
    private class SecureVaultService {
        public String getSecret(String key) {
            // Mock implementation that would retrieve secrets from a secure vault
            return "secure-" + key + "-value";
        }
    }
    
    private class DatabaseCredentialProvider {
        public Map<String, String> getCredentials(String service) {
            // Mock implementation that would retrieve credentials from a database
            Map<String, String> credentials = new HashMap<>();
            credentials.put("clientId", service + "-client-id");
            credentials.put("clientSecret", service + "-client-secret");
            return credentials;
        }
    }
    
    private class AzureKeyVaultClient {
        public String getSecret(String secretName) {
            // Mock implementation that would retrieve secrets from Azure Key Vault
            return "azure-vault-" + secretName + "-value";
        }
    }
    
    private class EncryptedFileReader {
        private String filePath;
        
        public EncryptedFileReader(String filePath) {
            this.filePath = filePath;
        }
        
        public Map<String, String> readCredentials() {
            // Mock implementation that would decrypt and read credentials from a file
            Map<String, String> credentials = new HashMap<>();
            credentials.put("clientId", "decrypted-client-id");
            credentials.put("clientSecret", "decrypted-client-secret");
            return credentials;
        }
    }
    
    private class ConfigurationService {
        public String getSecureConfig(String key) {
            // Mock implementation that would retrieve secure configuration
            return "secure-config-" + key + "-value";
        }
    }
    
    private class CredentialManager {
        private static CredentialManager instance;
        
        public static CredentialManager getInstance() {
            if (instance == null) {
                instance = new CredentialManager();
            }
            return instance;
        }
        
        public String getCredential(String key) {
            // Mock implementation that would retrieve credentials from a secure store
            return "credential-" + key + "-value";
        }
    }
    
    private class ExternalSecretService {
        public String fetchSecret(String secretKey) {
            // Mock implementation that would fetch secrets from an external service
            return "external-" + secretKey + "-value";
        }
    }
}
// {/fact}