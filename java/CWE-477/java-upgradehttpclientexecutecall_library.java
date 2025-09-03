import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.httpclient.HttpClient; // Old v3 client
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.params.HttpMethodParams;

import org.apache.http.client.methods.HttpGet; // New v4 client
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.CloseableHttpResponse;

// Security Issue: Using outdated Apache HttpClient (pre-version 4) which may contain security vulnerabilities

// True Positive Examples (Vulnerable/Insecure Code)
public class HttpClientExamples {

// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        // Basic usage of deprecated HttpClient v3
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("http://example.com/api");
        client.executeMethod(method);
        String response = method.getResponseBodyAsString();
        method.releaseConnection();
    }

    public void bad_case_2() throws IOException {
        // HttpClient v3 with POST request and parameters
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod("http://example.com/submit");
        post.addParameter("username", "user1");
        post.addParameter("password", "secret");
        client.executeMethod(post);
        post.releaseConnection();
    }

    public void bad_case_3() throws IOException {
        // HttpClient v3 with custom timeout settings
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        client.getHttpConnectionManager().getParams().setConnectionTimeout(5000);
        client.getHttpConnectionManager().getParams().setSoTimeout(10000);
        GetMethod get = new GetMethod("http://example.com/api/data");
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_4() throws IOException {
        // HttpClient v3 with JSON payload
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod("http://example.com/api/json");
        post.setRequestHeader("Content-Type", "application/json");
        String jsonPayload = "{\"name\":\"John\",\"age\":30}";
        post.setRequestEntity(new StringRequestEntity(jsonPayload, "application/json", "UTF-8"));
        client.executeMethod(post);
        post.releaseConnection();
    }

    public void bad_case_5() throws IOException {
        // HttpClient v3 with authentication
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        client.getState().setCredentials(
                new org.apache.commons.httpclient.auth.AuthScope("example.com", 80),
                new org.apache.commons.httpclient.UsernamePasswordCredentials("username", "password")
        );
        GetMethod get = new GetMethod("http://example.com/secure");
        get.setDoAuthentication(true);
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_6() throws IOException {
        // HttpClient v3 with retry handler
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        GetMethod get = new GetMethod("http://example.com/flaky-api");
        get.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, 
                new org.apache.commons.httpclient.DefaultHttpMethodRetryHandler(3, false));
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_7() throws IOException {
        // HttpClient v3 with proxy configuration
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        client.getHostConfiguration().setProxy("proxy.example.com", 8080);
        GetMethod get = new GetMethod("http://example.com/api");
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_8() throws IOException {
        // HttpClient v3 with custom headers
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        GetMethod get = new GetMethod("http://example.com/api");
        get.addRequestHeader("X-API-Key", "abcd1234");
        get.addRequestHeader("User-Agent", "CustomClient/1.0");
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_9() throws IOException {
        // HttpClient v3 with cookie handling
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        client.getState().addCookie(
                new org.apache.commons.httpclient.Cookie("example.com", "sessionId", "abc123", "/", null, false)
        );
        GetMethod get = new GetMethod("http://example.com/dashboard");
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_10() throws IOException {
        // HttpClient v3 with form submission
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod("http://example.com/register");
        post.addParameter("email", "user@example.com");
        post.addParameter("name", "John Doe");
        post.addParameter("subscribe", "true");
        client.executeMethod(post);
        post.releaseConnection();
    }

    public void bad_case_11() throws IOException {
        // HttpClient v3 with connection pooling
        // ruleid: java-upgradehttpclientexecutecall
        org.apache.commons.httpclient.MultiThreadedHttpConnectionManager connectionManager = 
                new org.apache.commons.httpclient.MultiThreadedHttpConnectionManager();
        HttpClient client = new HttpClient(connectionManager);
        GetMethod get = new GetMethod("http://example.com/api");
        client.executeMethod(get);
        get.releaseConnection();
    }

    public void bad_case_12() throws IOException {
        // HttpClient v3 with DELETE method
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        org.apache.commons.httpclient.methods.DeleteMethod delete = 
                new org.apache.commons.httpclient.methods.DeleteMethod("http://example.com/api/resource/123");
        client.executeMethod(delete);
        delete.releaseConnection();
    }

    public void bad_case_13() throws IOException {
        // HttpClient v3 with PUT method and binary data
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        org.apache.commons.httpclient.methods.PutMethod put = 
                new org.apache.commons.httpclient.methods.PutMethod("http://example.com/api/upload");
        byte[] data = "binary content".getBytes();
        put.setRequestEntity(new org.apache.commons.httpclient.methods.ByteArrayRequestEntity(data));
        client.executeMethod(put);
        put.releaseConnection();
    }

    public void bad_case_14() throws IOException {
        // HttpClient v3 with multiple requests in sequence
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        GetMethod get1 = new GetMethod("http://example.com/api/step1");
        client.executeMethod(get1);
        String token = get1.getResponseHeader("X-Token").getValue();
        get1.releaseConnection();
        
        GetMethod get2 = new GetMethod("http://example.com/api/step2");
        get2.addRequestHeader("X-Token", token);
        client.executeMethod(get2);
        get2.releaseConnection();
    }

    public void bad_case_15() throws IOException {
        // HttpClient v3 with custom method
        // ruleid: java-upgradehttpclientexecutecall
        HttpClient client = new HttpClient();
        HttpMethod method = new org.apache.commons.httpclient.methods.EntityEnclosingMethod("PATCH", "http://example.com/api/update") {};
        method.setRequestHeader("Content-Type", "application/json");
        client.executeMethod(method);
        method.releaseConnection();
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() throws IOException {
        // Using HttpClient v4 for basic GET request
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet("http://example.com/api");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_2() throws IOException {
        // Using HttpClient v4 for POST request with parameters
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost("http://example.com/submit");
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new org.apache.http.message.BasicNameValuePair("username", "user1"));
        params.add(new org.apache.http.message.BasicNameValuePair("password", "secret"));
        post.setEntity(new org.apache.http.client.entity.UrlEncodedFormEntity(params));
        CloseableHttpResponse response = client.execute(post);
        client.close();
    }

    public void good_case_3() throws IOException {
        // Using HttpClient v4 with custom timeout settings
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.client.config.RequestConfig config = org.apache.http.client.config.RequestConfig.custom()
                .setConnectTimeout(5000)
                .setSocketTimeout(10000)
                .build();
        CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .build();
        HttpGet request = new HttpGet("http://example.com/api/data");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_4() throws IOException {
        // Using HttpClient v4 with JSON payload
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost("http://example.com/api/json");
        post.setHeader("Content-Type", "application/json");
        String jsonPayload = "{\"name\":\"John\",\"age\":30}";
        post.setEntity(new StringEntity(jsonPayload));
        CloseableHttpResponse response = client.execute(post);
        client.close();
    }

    public void good_case_5() throws IOException {
        // Using HttpClient v4 with authentication
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.auth.Credentials credentials = 
                new org.apache.http.auth.UsernamePasswordCredentials("username", "password");
        org.apache.http.auth.AuthScope authScope = 
                new org.apache.http.auth.AuthScope("example.com", 80);
        org.apache.http.client.CredentialsProvider credentialsProvider = 
                new org.apache.http.impl.client.BasicCredentialsProvider();
        credentialsProvider.setCredentials(authScope, credentials);
        
        CloseableHttpClient client = HttpClients.custom()
                .setDefaultCredentialsProvider(credentialsProvider)
                .build();
        HttpGet request = new HttpGet("http://example.com/secure");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_6() throws IOException {
        // Using HttpClient v4 with retry handler
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.impl.client.HttpClientBuilder builder = org.apache.http.impl.client.HttpClientBuilder.create();
        builder.setRetryHandler(new org.apache.http.impl.client.DefaultHttpRequestRetryHandler(3, false));
        CloseableHttpClient client = builder.build();
        HttpGet request = new HttpGet("http://example.com/flaky-api");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_7() throws IOException {
        // Using HttpClient v4 with proxy configuration
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.HttpHost proxy = new org.apache.http.HttpHost("proxy.example.com", 8080);
        org.apache.http.client.config.RequestConfig config = org.apache.http.client.config.RequestConfig.custom()
                .setProxy(proxy)
                .build();
        CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .build();
        HttpGet request = new HttpGet("http://example.com/api");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_8() throws IOException {
        // Using HttpClient v4 with custom headers
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet("http://example.com/api");
        request.addHeader("X-API-Key", "abcd1234");
        request.addHeader("User-Agent", "CustomClient/1.0");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_9() throws IOException {
        // Using HttpClient v4 with cookie handling
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.impl.client.BasicCookieStore cookieStore = new org.apache.http.impl.client.BasicCookieStore();
        org.apache.http.cookie.Cookie cookie = new org.apache.http.impl.cookie.BasicClientCookie("sessionId", "abc123");
        ((org.apache.http.impl.cookie.BasicClientCookie)cookie).setDomain("example.com");
        ((org.apache.http.impl.cookie.BasicClientCookie)cookie).setPath("/");
        cookieStore.addCookie(cookie);
        
        CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .build();
        HttpGet request = new HttpGet("http://example.com/dashboard");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_10() throws IOException {
        // Using HttpClient v4 with form submission
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost("http://example.com/register");
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new org.apache.http.message.BasicNameValuePair("email", "user@example.com"));
        params.add(new org.apache.http.message.BasicNameValuePair("name", "John Doe"));
        params.add(new org.apache.http.message.BasicNameValuePair("subscribe", "true"));
        post.setEntity(new org.apache.http.client.entity.UrlEncodedFormEntity(params));
        CloseableHttpResponse response = client.execute(post);
        client.close();
    }

    public void good_case_11() throws IOException {
        // Using HttpClient v4 with connection pooling
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.impl.conn.PoolingHttpClientConnectionManager cm = 
                new org.apache.http.impl.conn.PoolingHttpClientConnectionManager();
        cm.setMaxTotal(100);
        cm.setDefaultMaxPerRoute(20);
        
        CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(cm)
                .build();
        HttpGet request = new HttpGet("http://example.com/api");
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }

    public void good_case_12() throws IOException {
        // Using HttpClient v4 with DELETE method
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        org.apache.http.client.methods.HttpDelete delete = 
                new org.apache.http.client.methods.HttpDelete("http://example.com/api/resource/123");
        CloseableHttpResponse response = client.execute(delete);
        client.close();
    }

    public void good_case_13() throws IOException {
        // Using HttpClient v4 with PUT method and binary data
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        org.apache.http.client.methods.HttpPut put = 
                new org.apache.http.client.methods.HttpPut("http://example.com/api/upload");
        byte[] data = "binary content".getBytes();
        put.setEntity(new org.apache.http.entity.ByteArrayEntity(data));
        CloseableHttpResponse response = client.execute(put);
        client.close();
    }

    public void good_case_14() throws IOException {
        // Using HttpClient v4 with multiple requests in sequence
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet get1 = new HttpGet("http://example.com/api/step1");
        CloseableHttpResponse response1 = client.execute(get1);
        String token = response1.getFirstHeader("X-Token").getValue();
        response1.close();
        
        HttpGet get2 = new HttpGet("http://example.com/api/step2");
        get2.addHeader("X-Token", token);
        CloseableHttpResponse response2 = client.execute(get2);
        response2.close();
        client.close();
    }

    public void good_case_15() throws URISyntaxException, IOException {
        // Using HttpClient v4 with URI builder
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        URI uri = new URIBuilder()
                .setScheme("http")
                .setHost("example.com")
                .setPath("/api/search")
                .setParameter("q", "test query")
                .setParameter("page", "1")
                .build();
        HttpGet request = new HttpGet(uri);
        CloseableHttpResponse response = client.execute(request);
        client.close();
    }
}
// {/fact}