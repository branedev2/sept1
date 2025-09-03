import java.net.URL;
import java.net.URI;
import java.net.MalformedURLException;
import java.io.IOException;
import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.RequestBody;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.Call;
import retrofit2.Callback;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.Response;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.core.http.HttpMethod;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobClientBuilder;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.Blob;
import org.apache.commons.io.FileUtils;
import java.io.File;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

// Security Issue: Using insecure URL protocols (HTTP) that transmit data in cleartext

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://api.example.com/user/data");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        // Process the connection...
    } catch (MalformedURLException | IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        // Apache HttpClient with insecure protocol
        HttpClient httpClient = HttpClients.createDefault();
        // ruleid: java-url-instantiated
        URL url = new URL("http://services.example.org/customer/profile");
        URI uri = url.toURI();
        HttpGet request = new HttpGet(uri);
        httpClient.execute(request);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Spring RestTemplate with insecure URL
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    HttpEntity<String> entity = new HttpEntity<>(headers);
    
    try {
        // ruleid: java-url-instantiated
        URL targetUrl = new URL("http://api.weather.com/forecast");
        ResponseEntity<String> response = restTemplate.exchange(
            targetUrl.toString(), HttpMethod.GET, entity, String.class);
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    // OkHttp client with insecure URL
    OkHttpClient client = new OkHttpClient();
    
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://analytics.example.com/track");
        Request request = new Request.Builder()
            .url(url)
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            // Process response
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Retrofit with insecure base URL
    try {
        // ruleid: java-url-instantiated
        URL baseUrl = new URL("http://api.github.com/");
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(baseUrl.toString())
            .addConverterFactory(GsonConverterFactory.create())
            .build();
            
        // Use retrofit instance
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // JSoup with insecure URL
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://news.example.com/articles");
        Document doc = Jsoup.parse(url, 3000);
        // Process the document
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Google HTTP Client with insecure URL
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        // ruleid: java-url-instantiated
        URL url = new URL("http://maps.example.com/directions");
        GenericUrl genericUrl = new GenericUrl(url);
        HttpRequest request = requestFactory.buildGetRequest(genericUrl);
        // Execute the request
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // Unirest with insecure URL
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://search.example.com/query");
        com.mashape.unirest.http.HttpResponse<String> response = 
            Unirest.get(url.toString())
                .header("Accept", "application/json")
                .asString();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // AsyncHttpClient with insecure URL
    AsyncHttpClient client = new DefaultAsyncHttpClient();
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://metrics.example.com/collect");
        Future<org.asynchttpclient.Response> f = 
            client.prepareGet(url.toString())
                .execute();
        org.asynchttpclient.Response r = f.get();
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_10() {
    // Vert.x Web Client with insecure URL
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx);
    
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://content.example.com/images");
        client.requestAbs(io.vertx.core.http.HttpMethod.GET, url.toString())
            .send(ar -> {
                if (ar.succeeded()) {
                    // Process response
                }
            });
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Apache Commons IO with insecure URL
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://files.example.com/document.pdf");
        File destination = new File("/tmp/document.pdf");
        FileUtils.copyURLToFile(url, destination);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Java URL with FTP protocol (also insecure)
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("ftp://files.example.com/public/data.csv");
        // Process the URL connection
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // Java URL with custom protocol handler
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://custom.example.com/api/v1");
        URLConnection conn = url.openConnection();
        // Process connection
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Java URL with query parameters
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://search.example.com/find?q=test&page=1");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        // Process connection
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Java URL with port specification
    try {
        // ruleid: java-url-instantiated
        URL url = new URL("http://admin.example.com:8080/dashboard");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        // Process connection
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://api.example.com/user/data");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        // Process the connection...
    } catch (MalformedURLException | IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        // Apache HttpClient with secure protocol
        HttpClient httpClient = HttpClients.createDefault();
        // ok: java-url-instantiated
        URL url = new URL("https://services.example.org/customer/profile");
        URI uri = url.toURI();
        HttpGet request = new HttpGet(uri);
        httpClient.execute(request);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Spring RestTemplate with secure URL
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    HttpEntity<String> entity = new HttpEntity<>(headers);
    
    try {
        // ok: java-url-instantiated
        URL targetUrl = new URL("https://api.weather.com/forecast");
        ResponseEntity<String> response = restTemplate.exchange(
            targetUrl.toString(), HttpMethod.GET, entity, String.class);
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    // OkHttp client with secure URL
    OkHttpClient client = new OkHttpClient();
    
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://analytics.example.com/track");
        Request request = new Request.Builder()
            .url(url)
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            // Process response
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Retrofit with secure base URL
    try {
        // ok: java-url-instantiated
        URL baseUrl = new URL("https://api.github.com/");
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(baseUrl.toString())
            .addConverterFactory(GsonConverterFactory.create())
            .build();
            
        // Use retrofit instance
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // JSoup with secure URL
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://news.example.com/articles");
        Document doc = Jsoup.parse(url, 3000);
        // Process the document
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // Google HTTP Client with secure URL
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        // ok: java-url-instantiated
        URL url = new URL("https://maps.example.com/directions");
        GenericUrl genericUrl = new GenericUrl(url);
        HttpRequest request = requestFactory.buildGetRequest(genericUrl);
        // Execute the request
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // Unirest with secure URL
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://search.example.com/query");
        com.mashape.unirest.http.HttpResponse<String> response = 
            Unirest.get(url.toString())
                .header("Accept", "application/json")
                .asString();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // AsyncHttpClient with secure URL
    AsyncHttpClient client = new DefaultAsyncHttpClient();
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://metrics.example.com/collect");
        Future<org.asynchttpclient.Response> f = 
            client.prepareGet(url.toString())
                .execute();
        org.asynchttpclient.Response r = f.get();
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void good_case_10() {
    // Vert.x Web Client with secure URL
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx);
    
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://content.example.com/images");
        client.requestAbs(io.vertx.core.http.HttpMethod.GET, url.toString())
            .send(ar -> {
                if (ar.succeeded()) {
                    // Process response
                }
            });
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Apache Commons IO with secure URL
    try {
        // ok: java-url-instantiated
        URL url = new URL("https://files.example.com/document.pdf");
        File destination = new File("/tmp/document.pdf");
        FileUtils.copyURLToFile(url, destination);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // AWS S3 Client (uses HTTPS by default)
    Region region = Region.US_WEST_2;
    S3Client s3Client = S3Client.builder()
        .region(region)
        .credentialsProvider(DefaultCredentialsProvider.create())
        .build();
    
    // ok: java-url-instantiated
    s3Client.getObject(GetObjectRequest.builder()
        .bucket("my-bucket")
        .key("my-object")
        .build());
}

public void good_case_13() {
    // Azure Blob Storage (uses HTTPS by default)
    // ok: java-url-instantiated
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
        .buildClient();
        
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("mycontainer");
    BlobClient blobClient = containerClient.getBlobClient("myblob");
    blobClient.downloadToFile("/tmp/downloaded-file.txt");
}

public void good_case_14() {
    // Google Cloud Storage (uses HTTPS by default)
    // ok: java-url-instantiated
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Blob blob = storage.get(BlobId.of("bucket-name", "object-name"));
    blob.downloadTo(new File("/tmp/downloaded-file.txt").toPath());
}

public void good_case_15() {
    // Using file URL (local resource, not network transmission)
    try {
        // ok: java-url-instantiated
        URL url = new URL("file:///home/user/documents/local-file.txt");
        // Process the file URL
    } catch (MalformedURLException e) {
        e.printStackTrace();
    }
}