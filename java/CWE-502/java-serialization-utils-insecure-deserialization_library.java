import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.commons.lang3.SerializationUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;
import retrofit2.http.Path;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.apache.commons.io.IOUtils;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import java.util.concurrent.Future;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Base64;
import com.google.gson.Gson;
import org.springframework.web.multipart.MultipartFile;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.MediaType;
import java.net.URI;
import java.net.URL;
import java.net.HttpURLConnection;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Callback;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.core.json.JsonObject;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

// Security Issue: Insecure Deserialization using SerializationUtils.deserialize()

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
public class SerializationVulnerabilities {

    // Spring MVC Controller with insecure deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @RequestMapping("/bad1")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // Get serialized data from request parameter
            String serializedData = request.getParameter("data");
            byte[] data = Base64.decodeBase64(serializedData);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(data);
            
            response.getWriter().write("Processed: " + deserializedObject.toString());
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    // OkHttp client with insecure deserialization
    public void bad_case_2() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/serialized-data")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                byte[] serializedData = response.body().bytes();
                
                // ruleid: java-serialization-utils-insecure-deserialization
                Object deserializedObject = SerializationUtils.deserialize(serializedData);
                
                System.out.println("Received object: " + deserializedObject);
            }
        }
    }
    
    // Apache HttpClient with insecure deserialization
    public void bad_case_3() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/api/data");
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                byte[] serializedData = EntityUtils.toByteArray(entity);
                
                // ruleid: java-serialization-utils-insecure-deserialization
                Map<String, Object> deserializedMap = SerializationUtils.deserialize(serializedData);
                
                System.out.println("Received data: " + deserializedMap);
            }
        }
    }
    
    // Servlet file upload with insecure deserialization
    public void bad_case_4(HttpServletRequest request) throws Exception {
        if (ServletFileUpload.isMultipartContent(request)) {
            DiskFileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            
            List<FileItem> items = upload.parseRequest(request);
            for (FileItem item : items) {
                if (!item.isFormField() && "serializedData".equals(item.getFieldName())) {
                    byte[] serializedData = item.get();
                    
                    // ruleid: java-serialization-utils-insecure-deserialization
                    Object deserializedObject = SerializationUtils.deserialize(serializedData);
                    
                    System.out.println("Processed uploaded object: " + deserializedObject);
                    break;
                }
            }
        }
    }
    
    // Spring RestTemplate with insecure deserialization
    public void bad_case_5() {
        RestTemplate restTemplate = new RestTemplateBuilder().build();
        ResponseEntity<byte[]> response = restTemplate.getForEntity(
            "https://example.com/api/serialized-object", byte[].class);
        
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(response.getBody());
            
            System.out.println("Received object: " + deserializedObject);
        }
    }
    
    // AWS S3 client with insecure deserialization
    public void bad_case_6() throws IOException {
        S3Client s3Client = S3Client.builder().build();
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("serialized-data.bin")
            .build();
            
        ResponseInputStream<GetObjectResponse> s3Object = s3Client.getObject(getObjectRequest);
        byte[] serializedData = IOUtils.toByteArray(s3Object);
        
        // ruleid: java-serialization-utils-insecure-deserialization
        Object deserializedObject = SerializationUtils.deserialize(serializedData);
        
        System.out.println("S3 object deserialized: " + deserializedObject);
    }
    
    // Google HTTP Client with insecure deserialization
    public void bad_case_7() throws IOException {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://example.com/api/serialized"));
            
        byte[] serializedData = request.execute().getContent().readAllBytes();
        
        // ruleid: java-serialization-utils-insecure-deserialization
        Object deserializedObject = SerializationUtils.deserialize(serializedData);
        
        System.out.println("Received object: " + deserializedObject);
    }
    
    // Async HTTP Client with insecure deserialization
    public void bad_case_8() throws Exception {
        AsyncHttpClient client = Dsl.asyncHttpClient();
        Future<Response> f = client.prepareGet("https://example.com/api/data")
            .execute();
        Response response = f.get();
        
        byte[] serializedData = response.getResponseBodyAsBytes();
        
        // ruleid: java-serialization-utils-insecure-deserialization
        Object deserializedObject = SerializationUtils.deserialize(serializedData);
        
        System.out.println("Async received object: " + deserializedObject);
        client.close();
    }
    
    // Spring MultipartFile with insecure deserialization
    @PostMapping("/upload")
    public void bad_case_9(@RequestParam("file") MultipartFile file) throws IOException {
        if (!file.isEmpty()) {
            byte[] serializedData = file.getBytes();
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(serializedData);
            
            System.out.println("Uploaded object: " + deserializedObject);
        }
    }
    
    // Java HttpURLConnection with insecure deserialization
    public void bad_case_10() throws Exception {
        URL url = new URL("https://example.com/api/data");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        try (InputStream inputStream = connection.getInputStream()) {
            byte[] serializedData = IOUtils.toByteArray(inputStream);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(serializedData);
            
            System.out.println("Received object: " + deserializedObject);
        }
    }
    
    // Retrofit client with insecure deserialization
    public void bad_case_11() throws IOException {
        interface ApiService {
            @GET("api/data")
            retrofit2.Call<byte[]> getData();
        }
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
            
        ApiService service = retrofit.create(ApiService.class);
        byte[] serializedData = service.getData().execute().body();
        
        if (serializedData != null) {
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(serializedData);
            
            System.out.println("Retrofit received object: " + deserializedObject);
        }
    }
    
    // Vertx Web Client with insecure deserialization
    public void bad_case_12() {
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        client.get(8080, "example.com", "/api/data")
            .send(ar -> {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    byte[] serializedData = response.bodyAsBuffer().getBytes();
                    
                    // ruleid: java-serialization-utils-insecure-deserialization
                    Object deserializedObject = SerializationUtils.deserialize(serializedData);
                    
                    System.out.println("Vertx received object: " + deserializedObject);
                }
                vertx.close();
            });
    }
    
    // Spring RequestEntity with insecure deserialization
    public void bad_case_13() {
        RestTemplate restTemplate = new RestTemplate();
        RequestEntity<Void> requestEntity = RequestEntity
            .method(HttpMethod.GET, URI.create("https://example.com/api/data"))
            .accept(MediaType.APPLICATION_OCTET_STREAM)
            .build();
            
        ResponseEntity<byte[]> responseEntity = restTemplate.exchange(requestEntity, byte[].class);
        byte[] serializedData = responseEntity.getBody();
        
        if (serializedData != null) {
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(serializedData);
            
            System.out.println("Received object: " + deserializedObject);
        }
    }
    
    // Base64 encoded serialized data from request header
    public void bad_case_14(HttpServletRequest request) {
        String serializedBase64 = request.getHeader("X-Serialized-Data");
        if (StringUtils.isNotEmpty(serializedBase64)) {
            byte[] serializedData = Base64.decodeBase64(serializedBase64);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(serializedData);
            
            System.out.println("Header data deserialized: " + deserializedObject);
        }
    }
    
    // Request cookie with insecure deserialization
    public void bad_case_15(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("serializedData".equals(cookie.getName())) {
                    byte[] serializedData = Base64.decodeBase64(cookie.getValue());
                    
                    // ruleid: java-serialization-utils-insecure-deserialization
                    Object deserializedObject = SerializationUtils.deserialize(serializedData);
                    
                    System.out.println("Cookie data deserialized: " + deserializedObject);
                    break;
                }
            }
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring MVC Controller with JSON deserialization instead of SerializationUtils
    @RequestMapping("/good1")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String jsonData = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            
            // ok: java-serialization-utils-insecure-deserialization
            Map<String, Object> deserializedMap = mapper.readValue(jsonData, Map.class);
            
            response.getWriter().write("Processed: " + deserializedMap.toString());
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    // OkHttp client with JSON deserialization
    public void good_case_2() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/data")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                String jsonData = response.body().string();
                ObjectMapper mapper = new ObjectMapper();
                
                // ok: java-serialization-utils-insecure-deserialization
                Map<String, Object> deserializedMap = mapper.readValue(jsonData, Map.class);
                
                System.out.println("Received object: " + deserializedMap);
            }
        }
    }
    
    // Apache HttpClient with JSON deserialization
    public void good_case_3() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/api/data");
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                String jsonData = EntityUtils.toString(entity);
                Gson gson = new Gson();
                
                // ok: java-serialization-utils-insecure-deserialization
                Map<String, Object> deserializedMap = gson.fromJson(jsonData, Map.class);
                
                System.out.println("Received data: " + deserializedMap);
            }
        }
    }
    
    // Servlet file upload with JSON parsing
    public void good_case_4(HttpServletRequest request) throws Exception {
        if (ServletFileUpload.isMultipartContent(request)) {
            DiskFileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            
            List<FileItem> items = upload.parseRequest(request);
            for (FileItem item : items) {
                if (!item.isFormField() && "jsonData".equals(item.getFieldName())) {
                    String jsonData = new String(item.get(), StandardCharsets.UTF_8);
                    ObjectMapper mapper = new ObjectMapper();
                    
                    // ok: java-serialization-utils-insecure-deserialization
                    Object deserializedObject = mapper.readValue(jsonData, Object.class);
                    
                    System.out.println("Processed uploaded JSON: " + deserializedObject);
                    break;
                }
            }
        }
    }
    
    // Spring RestTemplate with JSON deserialization
    public void good_case_5() {
        RestTemplate restTemplate = new RestTemplateBuilder().build();
        
        // ok: java-serialization-utils-insecure-deserialization
        Map<String, Object> response = restTemplate.getForObject(
            "https://example.com/api/data", Map.class);
            
        System.out.println("Received object: " + response);
    }
    
    // AWS S3 client with ValidatingObjectInputStream
    public void good_case_6() throws IOException, ClassNotFoundException {
        S3Client s3Client = S3Client.builder().build();
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("serialized-data.bin")
            .build();
            
        ResponseInputStream<GetObjectResponse> s3Object = s3Client.getObject(getObjectRequest);
        
        // ok: java-serialization-utils-insecure-deserialization
        try (ValidatingObjectInputStream vois = new ValidatingObjectInputStream(s3Object)) {
            // Only allow deserialization of safe classes
            vois.accept(HashMap.class, ArrayList.class, String.class);
            Object deserializedObject = vois.readObject();
            System.out.println("S3 object deserialized safely: " + deserializedObject);
        }
    }
    
    // Google HTTP Client with JSON deserialization
    public void good_case_7() throws IOException {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://example.com/api/data"));
            
        String jsonData = request.execute().parseAsString();
        ObjectMapper mapper = new ObjectMapper();
        
        // ok: java-serialization-utils-insecure-deserialization
        Map<String, Object> deserializedMap = mapper.readValue(jsonData, Map.class);
        
        System.out.println("Received object: " + deserializedMap);
    }
    
    // Async HTTP Client with JSON deserialization
    public void good_case_8() throws Exception {
        AsyncHttpClient client = Dsl.asyncHttpClient();
        Future<Response> f = client.prepareGet("https://example.com/api/data")
            .execute();
        Response response = f.get();
        
        String jsonData = response.getResponseBody();
        ObjectMapper mapper = new ObjectMapper();
        
        // ok: java-serialization-utils-insecure-deserialization
        Map<String, Object> deserializedMap = mapper.readValue(jsonData, Map.class);
        
        System.out.println("Async received object: " + deserializedMap);
        client.close();
    }
    
    // Spring MultipartFile with JSON parsing
    @PostMapping("/upload-json")
    public void good_case_9(@RequestParam("file") MultipartFile file) throws IOException {
        if (!file.isEmpty()) {
            String jsonData = new String(file.getBytes(), StandardCharsets.UTF_8);
            ObjectMapper mapper = new ObjectMapper();
            
            // ok: java-serialization-utils-insecure-deserialization
            Object deserializedObject = mapper.readValue(jsonData, Object.class);
            
            System.out.println("Uploaded JSON: " + deserializedObject);
        }
    }
    
    // Java HttpURLConnection with JSON deserialization
    public void good_case_10() throws Exception {
        URL url = new URL("https://example.com/api/data");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        try (InputStream inputStream = connection.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            
            StringBuilder jsonData = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonData.append(line);
            }
            
            ObjectMapper mapper = new ObjectMapper();
            
            // ok: java-serialization-utils-insecure-deserialization
            Map<String, Object> deserializedMap = mapper.readValue(jsonData.toString(), Map.class);
            
            System.out.println("Received object: " + deserializedMap);
        }
    }
    
    // Retrofit client with JSON deserialization
    public void good_case_11() throws IOException {
        interface ApiService {
            @GET("api/data")
            retrofit2.Call<Map<String, Object>> getData();
        }
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
            
        ApiService service = retrofit.create(ApiService.class);
        
        // ok: java-serialization-utils-insecure-deserialization
        Map<String, Object> deserializedMap = service.getData().execute().body();
        
        System.out.println("Retrofit received object: " + deserializedMap);
    }
    
    // Vertx Web Client with JSON deserialization
    public void good_case_12() {
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        client.get(8080, "example.com", "/api/data")
            .send(ar -> {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    
                    // ok: java-serialization-utils-insecure-deserialization
                    JsonObject jsonObject = response.bodyAsJsonObject();
                    
                    System.out.println("Vertx received object: " + jsonObject);
                }
                vertx.close();
            });
    }
    
    // Spring RequestEntity with JSON deserialization
    public void good_case_13() {
        RestTemplate restTemplate = new RestTemplate();
        RequestEntity<Void> requestEntity = RequestEntity
            .method(HttpMethod.GET, URI.create("https://example.com/api/data"))
            .accept(MediaType.APPLICATION_JSON)
            .build();
            
        // ok: java-serialization-utils-insecure-deserialization
        ResponseEntity<Map> responseEntity = restTemplate.exchange(requestEntity, Map.class);
        Map<String, Object> deserializedMap = responseEntity.getBody();
        
        System.out.println("Received object: " + deserializedMap);
    }
    
    // Base64 encoded JSON data from request header
    public void good_case_14(HttpServletRequest request) throws IOException {
        String base64Json = request.getHeader("X-JSON-Data");
        if (StringUtils.isNotEmpty(base64Json)) {
            String jsonData = new String(Base64.decodeBase64(base64Json), StandardCharsets.UTF_8);
            ObjectMapper mapper = new ObjectMapper();
            
            // ok: java-serialization-utils-insecure-deserialization
            Map<String, Object> deserializedMap = mapper.readValue(jsonData, Map.class);
            
            System.out.println("Header data deserialized: " + deserializedMap);
        }
    }
    
    // Request cookie with JSON deserialization
    public void good_case_15(HttpServletRequest request) throws IOException {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("jsonData".equals(cookie.getName())) {
                    String jsonData = cookie.getValue();
                    ObjectMapper mapper = new ObjectMapper();
                    
                    // ok: java-serialization-utils-insecure-deserialization
                    Map<String, Object> deserializedMap = mapper.readValue(jsonData, Map.class);
                    
                    System.out.println("Cookie data deserialized: " + deserializedMap);
                    break;
                }
            }
        }
    }
}
// {/fact}