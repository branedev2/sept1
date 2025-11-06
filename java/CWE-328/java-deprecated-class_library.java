import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.params.HttpParams;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.client.CircularRedirectException;
import org.apache.http.NoHttpResponseException;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.ResponseHandler;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.StandardHttpRequestRetryHandler;

import java.io.IOException;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.util.concurrent.TimeUnit;

// Security Issue: Using DefaultHttpClient which is deprecated and doesn't support TLS 1.2

// True Positive Examples (Vulnerable/Insecure Code)
public class HttpClientExamples {

// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        // Basic usage of DefaultHttpClient for a simple GET request
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        HttpGet request = new HttpGet("https://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response status: " + response.getStatusLine());
    }

    public void bad_case_2() throws IOException {
        // Using DefaultHttpClient with POST request and custom parameters
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        HttpPost post = new HttpPost("https://api.example.com/submit");
        post.setEntity(new StringEntity("{\"name\":\"John\",\"age\":30}"));
        post.setHeader("Content-Type", "application/json");
        HttpResponse response = client.execute(post);
        System.out.println("Response code: " + response.getStatusLine().getStatusCode());
    }

    public void bad_case_3() throws IOException {
        // Using DefaultHttpClient with custom timeout settings
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        HttpParams params = client.getParams();
        HttpConnectionParams.setConnectionTimeout(params, 5000);
        HttpConnectionParams.setSoTimeout(params, 30000);
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response received: " + EntityUtils.toString(response.getEntity()));
    }

    public void bad_case_4() throws IOException {
        // Using DefaultHttpClient with DELETE method
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        HttpDelete delete = new HttpDelete("https://api.example.com/resource/123");
        delete.setHeader("Authorization", "Bearer token123");
        HttpResponse response = client.execute(delete);
        System.out.println("Delete operation status: " + response.getStatusLine());
    }

    public void bad_case_5() throws IOException {
        // Using DefaultHttpClient with PUT method and custom entity
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        HttpPut put = new HttpPut("https://api.example.com/update/123");
        put.setEntity(new StringEntity("{\"status\":\"completed\"}"));
        put.setHeader("Content-Type", "application/json");
        HttpResponse response = client.execute(put);
        System.out.println("Update status: " + response.getStatusLine().getStatusCode());
    }

    public void bad_case_6() throws IOException {
        // Using DefaultHttpClient with custom connection manager
        ClientConnectionManager connectionManager = new ThreadSafeClientConnManager();
        HttpParams params = new BasicHttpParams();
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient(connectionManager, params);
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response: " + EntityUtils.toString(response.getEntity()));
    }

    public void bad_case_7() throws IOException {
        // Using DefaultHttpClient with authentication
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        client.getCredentialsProvider().setCredentials(
            new AuthScope("api.example.com", 443),
            new org.apache.http.auth.UsernamePasswordCredentials("username", "password")
        );
        
        HttpGet request = new HttpGet("https://api.example.com/secure-data");
        HttpResponse response = client.execute(request);
        System.out.println("Authenticated response: " + response.getStatusLine());
    }

    public void bad_case_8() throws IOException {
        // Using DefaultHttpClient with scheme registry
        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
        
        ThreadSafeClientConnManager cm = new ThreadSafeClientConnManager(schemeRegistry);
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient(cm);
        
        HttpGet request = new HttpGet("http://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response with custom scheme: " + response.getStatusLine());
    }

    public void bad_case_9() throws IOException, URISyntaxException {
        // Using DefaultHttpClient with URIBuilder
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        
        URI uri = new URIBuilder()
            .setScheme("https")
            .setHost("api.example.com")
            .setPath("/search")
            .setParameter("q", "query term")
            .setParameter("limit", "10")
            .build();
            
        HttpGet request = new HttpGet(uri);
        HttpResponse response = client.execute(request);
        System.out.println("Search response: " + EntityUtils.toString(response.getEntity()));
    }

    public void bad_case_10() throws IOException {
        // Using DefaultHttpClient with request retry handler
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        client.setHttpRequestRetryHandler((exception, executionCount, context) -> {
            if (executionCount > 3) {
                return false;
            }
            return true;
        });
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response with retry: " + response.getStatusLine());
    }

    public void bad_case_11() throws IOException {
        // Using DefaultHttpClient with form data submission
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        
        HttpPost post = new HttpPost("https://api.example.com/form");
        List<NameValuePair> formParams = new ArrayList<>();
        formParams.add(new BasicNameValuePair("username", "john_doe"));
        formParams.add(new BasicNameValuePair("password", "secret123"));
        post.setEntity(new UrlEncodedFormEntity(formParams));
        
        HttpResponse response = client.execute(post);
        System.out.println("Form submission response: " + response.getStatusLine());
    }

    public void bad_case_12() throws IOException {
        // Using DefaultHttpClient with response handler
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        String responseBody = client.execute(request, responseHandler);
        
        System.out.println("Response body: " + responseBody);
    }

    public void bad_case_13() throws IOException {
        // Using DefaultHttpClient with context
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        
        HttpClientContext context = HttpClientContext.create();
        HttpGet request = new HttpGet("https://api.example.com/data");
        
        HttpResponse response = client.execute(request, context);
        System.out.println("Response with context: " + response.getStatusLine());
    }

    public void bad_case_14() throws IOException {
        // Using DefaultHttpClient with multipart entity
        // ruleid: java-deprecated-class
        HttpClient client = new DefaultHttpClient();
        
        HttpPost post = new HttpPost("https://api.example.com/upload");
        
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.addTextBody("field1", "value1");
        builder.addTextBody("field2", "value2");
        builder.addBinaryBody("file", new File("document.pdf"), ContentType.APPLICATION_OCTET_STREAM, "document.pdf");
        
        post.setEntity(builder.build());
        HttpResponse response = client.execute(post);
        System.out.println("Upload response: " + response.getStatusLine());
    }

    public void bad_case_15() throws IOException {
        // Using DefaultHttpClient with custom protocol parameters
        // ruleid: java-deprecated-class
        DefaultHttpClient client = new DefaultHttpClient();
        HttpParams params = client.getParams();
        HttpProtocolParams.setUserAgent(params, "MyCustomUserAgent/1.0");
        HttpProtocolParams.setVersion(params, org.apache.http.HttpVersion.HTTP_1_1);
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response with custom protocol: " + response.getStatusLine());
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() throws IOException {
        // Using HttpClientBuilder instead of DefaultHttpClient for a simple GET request
        // ok: java-deprecated-class
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet("https://api.example.com/data");
        HttpResponse response = client.execute(request);
        System.out.println("Response status: " + response.getStatusLine());
    }

    public void good_case_2() throws IOException {
        // Using HttpClientBuilder with POST request and custom parameters
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost("https://api.example.com/submit");
        post.setEntity(new StringEntity("{\"name\":\"John\",\"age\":30}"));
        post.setHeader("Content-Type", "application/json");
        CloseableHttpResponse response = client.execute(post);
        System.out.println("Response code: " + response.getStatusLine().getStatusCode());
        response.close();
        client.close();
    }

    public void good_case_3() throws IOException {
        // Using HttpClientBuilder with custom timeout settings
        // ok: java-deprecated-class
        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(5000)
            .setSocketTimeout(30000)
            .build();
            
        CloseableHttpClient client = HttpClientBuilder.create()
            .setDefaultRequestConfig(config)
            .build();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Response received: " + EntityUtils.toString(response.getEntity()));
        response.close();
        client.close();
    }

    public void good_case_4() throws IOException {
        // Using HttpClientBuilder with DELETE method
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpDelete delete = new HttpDelete("https://api.example.com/resource/123");
        delete.setHeader("Authorization", "Bearer token123");
        CloseableHttpResponse response = client.execute(delete);
        System.out.println("Delete operation status: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_5() throws IOException {
        // Using HttpClientBuilder with PUT method and custom entity
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpPut put = new HttpPut("https://api.example.com/update/123");
        put.setEntity(new StringEntity("{\"status\":\"completed\"}"));
        put.setHeader("Content-Type", "application/json");
        CloseableHttpResponse response = client.execute(put);
        System.out.println("Update status: " + response.getStatusLine().getStatusCode());
        response.close();
        client.close();
    }

    public void good_case_6() throws IOException {
        // Using HttpClientBuilder with connection manager
        // ok: java-deprecated-class
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(100);
        connectionManager.setDefaultMaxPerRoute(20);
        
        CloseableHttpClient client = HttpClientBuilder.create()
            .setConnectionManager(connectionManager)
            .build();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Response: " + EntityUtils.toString(response.getEntity()));
        response.close();
        client.close();
    }

    public void good_case_7() throws IOException {
        // Using HttpClientBuilder with authentication
        // ok: java-deprecated-class
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
            new AuthScope("api.example.com", 443),
            new org.apache.http.auth.UsernamePasswordCredentials("username", "password")
        );
        
        CloseableHttpClient client = HttpClientBuilder.create()
            .setDefaultCredentialsProvider(credentialsProvider)
            .build();
        
        HttpGet request = new HttpGet("https://api.example.com/secure-data");
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Authenticated response: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_8() throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // Using HttpClientBuilder with SSL context
        // ok: java-deprecated-class
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(null, new TrustSelfSignedStrategy())
            .build();
            
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
            sslContext, new DefaultHostnameVerifier());
            
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
            .register("http", PlainConnectionSocketFactory.getSocketFactory())
            .register("https", sslSocketFactory)
            .build();
            
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(registry);
        
        CloseableHttpClient client = HttpClientBuilder.create()
            .setConnectionManager(connectionManager)
            .build();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Response with SSL: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_9() throws IOException, URISyntaxException {
        // Using HttpClientBuilder with URIBuilder
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        
        URI uri = new URIBuilder()
            .setScheme("https")
            .setHost("api.example.com")
            .setPath("/search")
            .setParameter("q", "query term")
            .setParameter("limit", "10")
            .build();
            
        HttpGet request = new HttpGet(uri);
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Search response: " + EntityUtils.toString(response.getEntity()));
        response.close();
        client.close();
    }

    public void good_case_10() throws IOException {
        // Using HttpClientBuilder with request retry handler
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create()
            .setRetryHandler(new DefaultHttpRequestRetryHandler(3, true))
            .build();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Response with retry: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_11() throws IOException {
        // Using HttpClientBuilder with form data submission
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        
        HttpPost post = new HttpPost("https://api.example.com/form");
        List<NameValuePair> formParams = new ArrayList<>();
        formParams.add(new BasicNameValuePair("username", "john_doe"));
        formParams.add(new BasicNameValuePair("password", "secret123"));
        post.setEntity(new UrlEncodedFormEntity(formParams));
        
        CloseableHttpResponse response = client.execute(post);
        System.out.println("Form submission response: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_12() throws IOException {
        // Using HttpClientBuilder with response handler
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        String responseBody = client.execute(request, responseHandler);
        
        System.out.println("Response body: " + responseBody);
        client.close();
    }

    public void good_case_13() throws IOException {
        // Using HttpClientBuilder with context
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        
        HttpClientContext context = HttpClientContext.create();
        HttpGet request = new HttpGet("https://api.example.com/data");
        
        CloseableHttpResponse response = client.execute(request, context);
        System.out.println("Response with context: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_14() throws IOException {
        // Using HttpClientBuilder with multipart entity
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClientBuilder.create().build();
        
        HttpPost post = new HttpPost("https://api.example.com/upload");
        
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.addTextBody("field1", "value1");
        builder.addTextBody("field2", "value2");
        builder.addBinaryBody("file", new File("document.pdf"), ContentType.APPLICATION_OCTET_STREAM, "document.pdf");
        
        post.setEntity(builder.build());
        CloseableHttpResponse response = client.execute(post);
        System.out.println("Upload response: " + response.getStatusLine());
        response.close();
        client.close();
    }

    public void good_case_15() throws IOException {
        // Using HttpClients factory methods
        // ok: java-deprecated-class
        CloseableHttpClient client = HttpClients.createDefault();
        
        HttpGet request = new HttpGet("https://api.example.com/data");
        request.setHeader("User-Agent", "MyCustomUserAgent/1.0");
        
        CloseableHttpResponse response = client.execute(request);
        System.out.println("Response with custom headers: " + response.getStatusLine());
        response.close();
        client.close();
    }
}
// {/fact}