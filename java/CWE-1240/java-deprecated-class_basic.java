import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class HttpClientExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-deprecated-class
            HttpClient client = new DefaultHttpClient();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = client.execute(request);
            HttpEntity entity = response.getEntity();
            String responseString = EntityUtils.toString(entity, "UTF-8");
            System.out.println(responseString);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-deprecated-class
            DefaultHttpClient client = new DefaultHttpClient();
            HttpPost post = new HttpPost("https://api.example.com/submit");
            post.setEntity(new StringEntity("{\"data\":\"test\"}"));
            post.setHeader("Content-Type", "application/json");
            HttpResponse response = client.execute(post);
            System.out.println(response.getStatusLine().getStatusCode());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // ruleid: java-deprecated-class
            DefaultHttpClient client = new DefaultHttpClient();
            URI uri = new URIBuilder()
                .setScheme("https")
                .setHost("api.example.com")
                .setPath("/search")
                .setParameter("query", "security")
                .build();
            HttpGet request = new HttpGet(uri);
            client.execute(request);
        } catch (URISyntaxException | IOException e) {
            e.printStackTrace();
        }
    }

    public HttpClient bad_case_4() {
        // ruleid: java-deprecated-class
        return new DefaultHttpClient();
    }

    public void bad_case_5() {
        try {
            // ruleid: java-deprecated-class
            DefaultHttpClient client = new DefaultHttpClient();
            for (String endpoint : new String[]{"users", "products", "orders"}) {
                HttpGet request = new HttpGet("https://api.example.com/" + endpoint);
                HttpResponse response = client.execute(request);
                System.out.println("Status for " + endpoint + ": " + response.getStatusLine());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // ruleid: java-deprecated-class
            HttpClient client = new DefaultHttpClient();
            if (System.currentTimeMillis() % 2 == 0) {
                HttpGet request = new HttpGet("https://api.example.com/even");
                client.execute(request);
            } else {
                HttpGet request = new HttpGet("https://api.example.com/odd");
                client.execute(request);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        try {
            HttpGet request = new HttpGet("https://api.example.com/data");
            request.setHeader("Authorization", "Bearer token123");
            request.setHeader("Accept", "application/json");
            client.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    public void bad_case_8() {
        try {
            // ruleid: java-deprecated-class
            DefaultHttpClient client = new DefaultHttpClient();
            HttpPost post = new HttpPost("https://api.example.com/login");
            post.setEntity(new StringEntity("{\"username\":\"user\",\"password\":\"pass\"}"));
            post.setHeader("Content-Type", "application/json");
            HttpResponse response = client.execute(post);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                System.out.println("Login successful");
            } else {
                System.out.println("Login failed with status: " + statusCode);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // ruleid: java-deprecated-class
        DefaultHttpClient client1 = new DefaultHttpClient();
        // ruleid: java-deprecated-class
        DefaultHttpClient client2 = new DefaultHttpClient();
        
        try {
            HttpGet request1 = new HttpGet("https://api1.example.com/data");
            HttpGet request2 = new HttpGet("https://api2.example.com/data");
            
            client1.execute(request1);
            client2.execute(request2);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            String url = "https://api.example.com/data";
            // ruleid: java-deprecated-class
            HttpClient client = new DefaultHttpClient();
            HttpGet request = new HttpGet(url);
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            switch (statusCode) {
                case 200:
                    System.out.println("Success");
                    break;
                case 404:
                    System.out.println("Not found");
                    break;
                default:
                    System.out.println("Unexpected status: " + statusCode);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        try {
            for (int i = 0; i < 5; i++) {
                HttpGet request = new HttpGet("https://api.example.com/data?page=" + i);
                HttpResponse response = client.execute(request);
                System.out.println("Page " + i + " status: " + response.getStatusLine());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-deprecated-class
            DefaultHttpClient client = new DefaultHttpClient();
            HttpPost post = new HttpPost("https://api.example.com/upload");
            StringEntity entity = new StringEntity("file content");
            post.setEntity(entity);
            client.execute(post);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        try {
            HttpGet request = new HttpGet("https://api.example.com/secure-endpoint");
            request.setHeader("Authorization", "Basic " + "base64encodedcredentials");
            client.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-deprecated-class
            DefaultHttpClient client = new DefaultHttpClient();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = null;
            try {
                response = client.execute(request);
                HttpEntity entity = response.getEntity();
                String result = EntityUtils.toString(entity);
                System.out.println(result);
            } finally {
                if (response != null) {
                    EntityUtils.consume(response.getEntity());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        try {
            URI uri = new URI("https", null, "api.example.com", -1, "/path", "param=value", null);
            HttpGet request = new HttpGet(uri);
            client.execute(request);
        } catch (URISyntaxException | IOException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-deprecated-class
            HttpClient client = HttpClientBuilder.create().build();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = client.execute(request);
            HttpEntity entity = response.getEntity();
            String responseString = EntityUtils.toString(entity, "UTF-8");
            System.out.println(responseString);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClients.createDefault();
            HttpPost post = new HttpPost("https://api.example.com/submit");
            post.setEntity(new StringEntity("{\"data\":\"test\"}"));
            post.setHeader("Content-Type", "application/json");
            HttpResponse response = client.execute(post);
            System.out.println(response.getStatusLine().getStatusCode());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClients.custom()
                .setMaxConnTotal(100)
                .setMaxConnPerRoute(20)
                .build();
            URI uri = new URIBuilder()
                .setScheme("https")
                .setHost("api.example.com")
                .setPath("/search")
                .setParameter("query", "security")
                .build();
            HttpGet request = new HttpGet(uri);
            client.execute(request);
        } catch (URISyntaxException | IOException e) {
            e.printStackTrace();
        }
    }

    public HttpClient good_case_4() {
        // ok: java-deprecated-class
        return HttpClientBuilder.create().build();
    }

    public void good_case_5() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClients.createDefault();
            for (String endpoint : new String[]{"users", "products", "orders"}) {
                HttpGet request = new HttpGet("https://api.example.com/" + endpoint);
                HttpResponse response = client.execute(request);
                System.out.println("Status for " + endpoint + ": " + response.getStatusLine());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClientBuilder.create().build();
            if (System.currentTimeMillis() % 2 == 0) {
                HttpGet request = new HttpGet("https://api.example.com/even");
                client.execute(request);
            } else {
                HttpGet request = new HttpGet("https://api.example.com/odd");
                client.execute(request);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClients.createDefault();
        try {
            HttpGet request = new HttpGet("https://api.example.com/data");
            request.setHeader("Authorization", "Bearer token123");
            request.setHeader("Accept", "application/json");
            client.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_8() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(RequestConfig.custom()
                    .setConnectTimeout(5000)
                    .setSocketTimeout(5000)
                    .build())
                .build();
            HttpPost post = new HttpPost("https://api.example.com/login");
            post.setEntity(new StringEntity("{\"username\":\"user\",\"password\":\"pass\"}"));
            post.setHeader("Content-Type", "application/json");
            HttpResponse response = client.execute(post);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                System.out.println("Login successful");
            } else {
                System.out.println("Login failed with status: " + statusCode);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        // ok: java-deprecated-class
        SSLContext sslContext = SSLContextBuilder
            .create()
            .loadTrustMaterial(new TrustSelfSignedStrategy())
            .build();
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            sslContext, 
            new String[] { "TLSv1.2" }, 
            null, 
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        CloseableHttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
        
        try {
            HttpGet request = new HttpGet("https://api.example.com/secure");
            client.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            String url = "https://api.example.com/data";
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClientBuilder.create().build();
            HttpGet request = new HttpGet(url);
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            switch (statusCode) {
                case 200:
                    System.out.println("Success");
                    break;
                case 404:
                    System.out.println("Not found");
                    break;
                default:
                    System.out.println("Unexpected status: " + statusCode);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClients.createDefault();
        try {
            for (int i = 0; i < 5; i++) {
                HttpGet request = new HttpGet("https://api.example.com/data?page=" + i);
                HttpResponse response = client.execute(request);
                System.out.println("Page " + i + " status: " + response.getStatusLine());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClientBuilder.create()
                .setMaxConnTotal(100)
                .setMaxConnPerRoute(20)
                .build();
            HttpPost post = new HttpPost("https://api.example.com/upload");
            StringEntity entity = new StringEntity("file content");
            post.setEntity(entity);
            client.execute(post);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClients.custom()
            .disableAutomaticRetries()
            .build();
        try {
            HttpGet request = new HttpGet("https://api.example.com/secure-endpoint");
            request.setHeader("Authorization", "Basic " + "base64encodedcredentials");
            client.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-deprecated-class
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = null;
            try {
                response = client.execute(request);
                HttpEntity entity = response.getEntity();
                String result = EntityUtils.toString(entity);
                System.out.println(result);
            } finally {
                if (response != null) {
                    EntityUtils.consume(response.getEntity());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create()
            .setUserAgent("MyCustomUserAgent/1.0")
            .build();
        try {
            URI uri = new URI("https", null, "api.example.com", -1, "/path", "param=value", null);
            HttpGet request = new HttpGet(uri);
            client.execute(request);
        } catch (URISyntaxException | IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}