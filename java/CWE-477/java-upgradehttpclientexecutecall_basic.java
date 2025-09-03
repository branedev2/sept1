import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.params.HttpMethodParams;

// Modern imports for version 4
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;

public class HttpClientExamples {

    // True positive examples (vulnerable code using outdated HttpClient)
    
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("https://example.com/api/data");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        String response = method.getResponseBodyAsString();
        method.releaseConnection();
    }
    
    public void bad_case_2() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        PostMethod method = new PostMethod("https://example.com/api/submit");
        method.addParameter("username", "user1");
        method.addParameter("password", "password123");
        // ruleid: java-upgradehttpclientexecutecall
        int statusCode = client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_3() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("https://example.com/api/search");
        method.setQueryString(new NameValuePair[] {
            new NameValuePair("q", "security"),
            new NameValuePair("limit", "10")
        });
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_4() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        client.getParams().setParameter(HttpMethodParams.USER_AGENT, "CustomAgent/1.0");
        PostMethod method = new PostMethod("https://example.com/api/upload");
        method.setRequestEntity(new StringRequestEntity("file content", "text/plain", "UTF-8"));
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_5() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("https://example.com/api/status");
        method.setFollowRedirects(true);
        // ruleid: java-upgradehttpclientexecutecall
        int statusCode = client.executeMethod(method);
        if (statusCode == 200) {
            String response = method.getResponseBodyAsString();
            System.out.println(response);
        }
        method.releaseConnection();
    }
    
    public void bad_case_6() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        for (int i = 0; i < 5; i++) {
            GetMethod method = new GetMethod("https://example.com/api/item/" + i);
            try {
                // ruleid: java-upgradehttpclientexecutecall
                client.executeMethod(method);
                String response = method.getResponseBodyAsString();
                System.out.println("Item " + i + ": " + response);
            } finally {
                method.releaseConnection();
            }
        }
    }
    
    public void bad_case_7() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        PostMethod method = new PostMethod("https://example.com/api/login");
        method.addParameter("username", "admin");
        method.addParameter("password", "admin123");
        method.addParameter("remember", "true");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        String sessionId = method.getResponseHeader("Session-Id").getValue();
        method.releaseConnection();
    }
    
    public void bad_case_8() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        client.getParams().setSoTimeout(5000);
        GetMethod method = new GetMethod("https://example.com/api/longrunning");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_9() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        PostMethod method = new PostMethod("https://example.com/api/json");
        method.setRequestHeader("Content-Type", "application/json");
        method.setRequestEntity(new StringRequestEntity("{\"key\":\"value\"}", "application/json", "UTF-8"));
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_10() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("https://example.com/api/secure");
        method.setRequestHeader("Authorization", "Bearer token123");
        // ruleid: java-upgradehttpclientexecutecall
        int statusCode = client.executeMethod(method);
        if (statusCode == 401) {
            System.out.println("Unauthorized access");
        }
        method.releaseConnection();
    }
    
    public void bad_case_11() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        client.getParams().setParameter("http.protocol.content-charset", "UTF-8");
        PostMethod method = new PostMethod("https://example.com/api/comment");
        method.addParameter("text", "This is a comment");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_12() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("https://example.com/api/download");
        method.setRequestHeader("Accept", "application/pdf");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        byte[] responseBody = method.getResponseBody();
        method.releaseConnection();
    }
    
    public void bad_case_13() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        PostMethod method = new PostMethod("https://example.com/api/register");
        method.addParameter("email", "user@example.com");
        method.addParameter("name", "John Doe");
        method.addParameter("agree_terms", "yes");
        // ruleid: java-upgradehttpclientexecutecall
        int statusCode = client.executeMethod(method);
        method.releaseConnection();
    }
    
    public void bad_case_14() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod("https://example.com/api/products");
        method.setQueryString("category=electronics&sort=price&order=asc");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        String response = method.getResponseBodyAsString();
        method.releaseConnection();
    }
    
    public void bad_case_15() throws HttpException, IOException {
        HttpClient client = new HttpClient();
        client.getHttpConnectionManager().getParams().setConnectionTimeout(3000);
        PostMethod method = new PostMethod("https://example.com/api/checkout");
        method.addParameter("product_id", "12345");
        method.addParameter("quantity", "2");
        // ruleid: java-upgradehttpclientexecutecall
        client.executeMethod(method);
        method.releaseConnection();
    }
    
    // True negative examples (safe code using HttpClient 4.x)
    
    public void good_case_1() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/api/data");
        client.execute(request);
    }
    
    public void good_case_2() throws IOException, URISyntaxException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = new HttpPost("https://example.com/api/submit");
        
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("username", "user1"));
        params.add(new BasicNameValuePair("password", "password123"));
        request.setEntity(new UrlEncodedFormEntity(params));
        
        client.execute(request);
    }
    
    public void good_case_3() throws IOException, URISyntaxException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        
        URI uri = new URIBuilder("https://example.com/api/search")
            .addParameter("q", "security")
            .addParameter("limit", "10")
            .build();
            
        HttpGet request = new HttpGet(uri);
        client.execute(request);
    }
    
    public void good_case_4() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.custom()
            .setUserAgent("CustomAgent/1.0")
            .build();
        
        HttpPost request = new HttpPost("https://example.com/api/upload");
        request.setEntity(new StringEntity("file content"));
        client.execute(request);
    }
    
    public void good_case_5() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/api/status");
        
        org.apache.http.HttpResponse response = client.execute(request);
        int statusCode = response.getStatusLine().getStatusCode();
        
        if (statusCode == 200) {
            org.apache.http.HttpEntity entity = response.getEntity();
            if (entity != null) {
                System.out.println(org.apache.http.util.EntityUtils.toString(entity));
            }
        }
    }
    
    public void good_case_6() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        
        for (int i = 0; i < 5; i++) {
            HttpGet request = new HttpGet("https://example.com/api/item/" + i);
            org.apache.http.HttpResponse response = client.execute(request);
            org.apache.http.HttpEntity entity = response.getEntity();
            if (entity != null) {
                String responseString = org.apache.http.util.EntityUtils.toString(entity);
                System.out.println("Item " + i + ": " + responseString);
            }
        }
    }
    
    public void good_case_7() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = new HttpPost("https://example.com/api/login");
        
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("username", "admin"));
        params.add(new BasicNameValuePair("password", "admin123"));
        params.add(new BasicNameValuePair("remember", "true"));
        request.setEntity(new UrlEncodedFormEntity(params));
        
        org.apache.http.HttpResponse response = client.execute(request);
        String sessionId = response.getFirstHeader("Session-Id").getValue();
    }
    
    public void good_case_8() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.custom()
            .setConnectionTimeToLive(5000, java.util.concurrent.TimeUnit.MILLISECONDS)
            .build();
            
        HttpGet request = new HttpGet("https://example.com/api/longrunning");
        client.execute(request);
    }
    
    public void good_case_9() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = new HttpPost("https://example.com/api/json");
        
        request.setHeader("Content-Type", "application/json");
        request.setEntity(new StringEntity("{\"key\":\"value\"}"));
        
        client.execute(request);
    }
    
    public void good_case_10() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/api/secure");
        
        request.setHeader("Authorization", "Bearer token123");
        org.apache.http.HttpResponse response = client.execute(request);
        
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode == 401) {
            System.out.println("Unauthorized access");
        }
    }
    
    public void good_case_11() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = new HttpPost("https://example.com/api/comment");
        
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("text", "This is a comment"));
        request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
        
        client.execute(request);
    }
    
    public void good_case_12() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/api/download");
        
        request.setHeader("Accept", "application/pdf");
        org.apache.http.HttpResponse response = client.execute(request);
        
        org.apache.http.HttpEntity entity = response.getEntity();
        if (entity != null) {
            byte[] responseBody = org.apache.http.util.EntityUtils.toByteArray(entity);
        }
    }
    
    public void good_case_13() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = new HttpPost("https://example.com/api/register");
        
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("email", "user@example.com"));
        params.add(new BasicNameValuePair("name", "John Doe"));
        params.add(new BasicNameValuePair("agree_terms", "yes"));
        request.setEntity(new UrlEncodedFormEntity(params));
        
        org.apache.http.HttpResponse response = client.execute(request);
    }
    
    public void good_case_14() throws IOException, URISyntaxException {
        // ok: java-upgradehttpclientexecutecall
        CloseableHttpClient client = HttpClients.createDefault();
        
        URI uri = new URIBuilder("https://example.com/api/products")
            .addParameter("category", "electronics")
            .addParameter("sort", "price")
            .addParameter("order", "asc")
            .build();
            
        HttpGet request = new HttpGet(uri);
        org.apache.http.HttpResponse response = client.execute(request);
    }
    
    public void good_case_15() throws IOException {
        // ok: java-upgradehttpclientexecutecall
        org.apache.http.impl.client.HttpClientBuilder builder = org.apache.http.impl.client.HttpClientBuilder.create();
        builder.setConnectionTimeToLive(3000, java.util.concurrent.TimeUnit.MILLISECONDS);
        CloseableHttpClient client = builder.build();
        
        HttpPost request = new HttpPost("https://example.com/api/checkout");
        
        List<org.apache.http.NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("product_id", "12345"));
        params.add(new BasicNameValuePair("quantity", "2"));
        request.setEntity(new UrlEncodedFormEntity(params));
        
        client.execute(request);
    }
}
// {/fact}