import java.util.concurrent.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import io.reactivex.Observable;
import io.reactivex.schedulers.Schedulers;
import okhttp3.*;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.converter.gson.GsonConverterFactory;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import com.azure.core.http.rest.Response;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobProperties;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import akka.actor.ActorSystem;
import akka.http.javadsl.Http;
import akka.http.javadsl.model.HttpRequest;
import akka.stream.Materializer;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.http.HttpHost;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

// Security Issue: Blocking operations within asynchronous tasks can degrade performance

// True Positive Examples (Vulnerable/Insecure Code)

public class BlockingServiceCallsExamples {

    // Spring WebFlux with blocking HTTP call
// {fact rule=misconfigured-concurrency@v1.0 defects=1}
    public void bad_case_1() {
        WebClient webClient = WebClient.create();
        
        Mono<String> result = webClient.get()
            .uri("https://api.example.com/data")
            .retrieve()
            .bodyToMono(String.class)
            .map(response -> {
                // ruleid: java-detect-blocking-service-calls
                try {
                    Thread.sleep(5000); // Blocking call in reactive pipeline
                    return processData(response);
                } catch (InterruptedException e) {
                    return "Error processing data";
                }
            });
        
        result.subscribe(data -> System.out.println("Processed: " + data));
    }
    
    // RxJava with blocking file I/O
    public void bad_case_2() {
        Observable<String> observable = Observable.fromCallable(() -> "Processing request")
            .subscribeOn(Schedulers.io())
            .map(input -> {
                // ruleid: java-detect-blocking-service-calls
                try {
                    List<String> lines = Files.readAllLines(Paths.get("/large/file.txt")); // Blocking file I/O
                    return lines.stream().collect(Collectors.joining("\n"));
                } catch (IOException e) {
                    return "Error reading file";
                }
            });
        
        observable.subscribe(result -> System.out.println(result));
    }
    
    // CompletableFuture with blocking JDBC database call
    public void bad_case_3() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "pass");
                 PreparedStatement stmt = conn.prepareStatement("SELECT * FROM large_table");
                 ResultSet rs = stmt.executeQuery()) {
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("data")).append("\n");
                }
                return result.toString();
            } catch (SQLException e) {
                return "Database error: " + e.getMessage();
            }
        });
        
        future.thenAccept(System.out::println);
    }
    
    // Vert.x with blocking Redis operation
    public void bad_case_4() {
        Vertx vertx = Vertx.vertx();
        JedisPool jedisPool = new JedisPool("localhost", 6379);
        
        vertx.createHttpServer().requestHandler(request -> {
            vertx.executeBlocking(promise -> {
                // ruleid: java-detect-blocking-service-calls
                try (Jedis jedis = jedisPool.getResource()) {
                    String value = jedis.get("large-key"); // Blocking Redis call
                    promise.complete(value);
                } catch (Exception e) {
                    promise.fail(e);
                }
            }, false, result -> {
                if (result.succeeded()) {
                    request.response().end((String) result.result());
                } else {
                    request.response().setStatusCode(500).end("Error");
                }
            });
        }).listen(8080);
    }
    
    // Akka HTTP with blocking Elasticsearch query
    public void bad_case_5() {
        ActorSystem system = ActorSystem.create();
        Materializer materializer = Materializer.createMaterializer(system);
        
        RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
        
        Http.get(system)
            .singleRequest(HttpRequest.create("http://localhost:8080/search"))
            .thenCompose(response -> {
                // ruleid: java-detect-blocking-service-calls
                try {
                    GetRequest getRequest = new GetRequest("index", "1");
                    return CompletableFuture.completedFuture(
                        client.get(getRequest, RequestOptions.DEFAULT).getSourceAsString());
                } catch (IOException e) {
                    return CompletableFuture.failedFuture(e);
                }
            })
            .thenAccept(System.out::println);
    }
    
    // OkHttp with blocking call in CompletableFuture
    public void bad_case_6() {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
            
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                Response response = client.newCall(request).execute(); // Blocking HTTP call
                return response.body().string();
            } catch (IOException e) {
                return "Error: " + e.getMessage();
            }
        });
        
        future.thenAccept(System.out::println);
    }
    
    // Retrofit with blocking API call in RxJava
    public void bad_case_7() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
            
        ApiService service = retrofit.create(ApiService.class);
        
        Observable.fromCallable(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                return service.getData().execute().body(); // Blocking Retrofit call
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        })
        .subscribeOn(Schedulers.io())
        .subscribe(data -> System.out.println("Received: " + data));
    }
    
    // Apache HttpClient with blocking call in Reactor
    public void bad_case_8() {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.example.com/data");
        
        Mono.fromCallable(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                return EntityUtils.toString(httpClient.execute(httpGet).getEntity()); // Blocking HTTP call
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        })
        .subscribe(response -> System.out.println("Response: " + response));
    }
    
    // AWS SDK S3 with blocking call in CompletableFuture
    public void bad_case_9() {
        S3AsyncClient s3Client = S3AsyncClient.create();
        
        CompletableFuture.supplyAsync(() -> {
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .build();
                
            // ruleid: java-detect-blocking-service-calls
            try {
                return s3Client.getObject(getObjectRequest, 
                    AsyncResponseTransformer.toBytes()).get(); // Blocking on Future.get()
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        })
        .thenAccept(response -> System.out.println("File size: " + response.asByteArray().length));
    }
    
    // Azure Storage Blob with blocking operation in CompletableFuture
    public void bad_case_10() {
        BlobClient blobClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient()
            .getBlobContainerClient("container")
            .getBlobClient("blob.txt");
            
        CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            BlobProperties properties = blobClient.getProperties(); // Blocking call
            return properties.getBlobSize();
        })
        .thenAccept(size -> System.out.println("Blob size: " + size));
    }
    
    // Google Cloud Storage with blocking call in reactive stream
    public void bad_case_11() {
        Storage storage = StorageOptions.getDefaultInstance().getService();
        
        Mono.fromCallable(() -> {
            // ruleid: java-detect-blocking-service-calls
            Blob blob = storage.get("bucket-name", "object-name"); // Blocking call
            return new String(blob.getContent());
        })
        .subscribe(content -> System.out.println("Content: " + content));
    }
    
    // AsyncHttpClient with blocking wait in CompletableFuture
    public void bad_case_12() {
        AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient();
        
        CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                return asyncHttpClient.prepareGet("https://api.example.com/data")
                    .execute()
                    .get() // Blocking call on Future.get()
                    .getResponseBody();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        })
        .thenAccept(System.out::println);
    }
    
    // MongoDB with blocking operation in reactive stream
    public void bad_case_13() {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("documents");
        
        Mono.fromCallable(() -> {
            // ruleid: java-detect-blocking-service-calls
            Document doc = collection.find(new Document("_id", "12345")).first(); // Blocking MongoDB call
            return doc.toJson();
        })
        .subscribe(json -> System.out.println("Document: " + json));
    }
    
    // ExecutorService with blocking I/O in Future
    public void bad_case_14() {
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        Future<String> future = executorService.submit(() -> {
            URL url = new URL("https://api.example.com/data");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // ruleid: java-detect-blocking-service-calls
            try (var reader = connection.getInputStream()) {
                return new String(reader.readAllBytes()); // Blocking I/O
            } catch (IOException e) {
                return "Error: " + e.getMessage();
            }
        });
        
        try {
            System.out.println(future.get()); // This is outside the async task, so not the issue
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Vert.x WebClient with blocking operation
    public void bad_case_15() {
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx, new WebClientOptions());
        
        vertx.createHttpServer().requestHandler(request -> {
            client.get(8080, "localhost", "/api/data").send().onSuccess(response -> {
                // ruleid: java-detect-blocking-service-calls
                try {
                    Thread.sleep(2000); // Blocking call in async handler
                    request.response().end(response.bodyAsString());
                } catch (InterruptedException e) {
                    request.response().setStatusCode(500).end("Error");
                }
            });
        }).listen(8080);
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring WebFlux with non-blocking approach
    public void good_case_1() {
        WebClient webClient = WebClient.create();
        
        // ok: java-detect-blocking-service-calls
        Mono<String> result = webClient.get()
            .uri("https://api.example.com/data")
            .retrieve()
            .bodyToMono(String.class)
            .delayElement(java.time.Duration.ofSeconds(5)) // Non-blocking delay
            .map(this::processData);
        
        result.subscribe(data -> System.out.println("Processed: " + data));
    }
    
    // RxJava with non-blocking file I/O
    public void good_case_2() {
        // ok: java-detect-blocking-service-calls
        Observable<String> observable = Observable.fromCallable(() -> "Processing request")
            .subscribeOn(Schedulers.io())
            .flatMap(input -> {
                return Observable.fromCallable(() -> {
                    List<String> lines = Files.readAllLines(Paths.get("/large/file.txt"));
                    return lines.stream().collect(Collectors.joining("\n"));
                }).subscribeOn(Schedulers.io()); // Offload blocking I/O to a separate thread
            });
        
        observable.subscribe(result -> System.out.println(result));
    }
    
    // CompletableFuture with properly offloaded JDBC call
    public void good_case_3() {
        ExecutorService jdbcExecutor = Executors.newFixedThreadPool(10);
        
        // ok: java-detect-blocking-service-calls
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "pass");
                 PreparedStatement stmt = conn.prepareStatement("SELECT * FROM large_table");
                 ResultSet rs = stmt.executeQuery()) {
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("data")).append("\n");
                }
                return result.toString();
            } catch (SQLException e) {
                return "Database error: " + e.getMessage();
            }
        }, jdbcExecutor); // Using dedicated executor for blocking operations
        
        future.thenAccept(System.out::println);
    }
    
    // Vert.x with proper blocking handler for Redis
    public void good_case_4() {
        Vertx vertx = Vertx.vertx();
        JedisPool jedisPool = new JedisPool("localhost", 6379);
        
        vertx.createHttpServer().requestHandler(request -> {
            // ok: java-detect-blocking-service-calls
            vertx.executeBlocking(promise -> {
                try (Jedis jedis = jedisPool.getResource()) {
                    String value = jedis.get("large-key");
                    promise.complete(value);
                } catch (Exception e) {
                    promise.fail(e);
                }
            }, true, result -> { // Using 'true' for ordered=true to properly handle blocking
                if (result.succeeded()) {
                    request.response().end((String) result.result());
                } else {
                    request.response().setStatusCode(500).end("Error");
                }
            });
        }).listen(8080);
    }
    
    // Akka HTTP with non-blocking Elasticsearch client
    public void good_case_5() {
        ActorSystem system = ActorSystem.create();
        Materializer materializer = Materializer.createMaterializer(system);
        
        RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
        
        // ok: java-detect-blocking-service-calls
        Http.get(system)
            .singleRequest(HttpRequest.create("http://localhost:8080/search"))
            .thenCompose(response -> {
                CompletableFuture<String> future = new CompletableFuture<>();
                system.dispatcher().execute(() -> {
                    try {
                        GetRequest getRequest = new GetRequest("index", "1");
                        future.complete(client.get(getRequest, RequestOptions.DEFAULT).getSourceAsString());
                    } catch (IOException e) {
                        future.completeExceptionally(e);
                    }
                });
                return future;
            })
            .thenAccept(System.out::println);
    }
    
    // OkHttp with non-blocking call
    public void good_case_6() {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
            
        // ok: java-detect-blocking-service-calls
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                System.out.println("Error: " + e.getMessage());
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                System.out.println(response.body().string());
            }
        });
    }
    
    // Retrofit with non-blocking API call
    public void good_case_7() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
            
        ApiService service = retrofit.create(ApiService.class);
        
        // ok: java-detect-blocking-service-calls
        service.getDataAsync().enqueue(new retrofit2.Callback<String>() {
            @Override
            public void onResponse(retrofit2.Call<String> call, retrofit2.Response<String> response) {
                System.out.println("Received: " + response.body());
            }
            
            @Override
            public void onFailure(retrofit2.Call<String> call, Throwable t) {
                System.out.println("Error: " + t.getMessage());
            }
        });
    }
    
    // Apache HttpClient with non-blocking approach
    public void good_case_8() {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.example.com/data");
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // ok: java-detect-blocking-service-calls
        Mono.fromFuture(CompletableFuture.supplyAsync(() -> {
            try {
                return EntityUtils.toString(httpClient.execute(httpGet).getEntity());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }, executor)) // Using dedicated executor for blocking operations
        .subscribe(response -> System.out.println("Response: " + response));
    }
    
    // AWS SDK S3 with non-blocking approach
    public void good_case_9() {
        S3AsyncClient s3Client = S3AsyncClient.create();
        
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("my-key")
            .build();
            
        // ok: java-detect-blocking-service-calls
        s3Client.getObject(getObjectRequest, AsyncResponseTransformer.toBytes())
            .whenComplete((response, error) -> {
                if (error != null) {
                    System.err.println("Error: " + error.getMessage());
                } else {
                    System.out.println("File size: " + response.asByteArray().length);
                }
            });
    }
    
    // Azure Storage Blob with non-blocking operation
    public void good_case_10() {
        BlobClient blobClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient()
            .getBlobContainerClient("container")
            .getBlobClient("blob.txt");
            
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // ok: java-detect-blocking-service-calls
        CompletableFuture.supplyAsync(() -> {
            BlobProperties properties = blobClient.getProperties();
            return properties.getBlobSize();
        }, executor) // Using dedicated executor for blocking operations
        .thenAccept(size -> System.out.println("Blob size: " + size));
    }
    
    // Google Cloud Storage with non-blocking approach
    public void good_case_11() {
        Storage storage = StorageOptions.getDefaultInstance().getService();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // ok: java-detect-blocking-service-calls
        Mono.fromFuture(CompletableFuture.supplyAsync(() -> {
            Blob blob = storage.get("bucket-name", "object-name");
            return new String(blob.getContent());
        }, executor)) // Using dedicated executor for blocking operations
        .subscribe(content -> System.out.println("Content: " + content));
    }
    
    // AsyncHttpClient with non-blocking approach
    public void good_case_12() {
        AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient();
        
        // ok: java-detect-blocking-service-calls
        asyncHttpClient.prepareGet("https://api.example.com/data")
            .execute()
            .toCompletableFuture()
            .thenApply(response -> response.getResponseBody())
            .thenAccept(System.out::println);
    }
    
    // MongoDB with non-blocking operation
    public void good_case_13() {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("documents");
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // ok: java-detect-blocking-service-calls
        Mono.fromFuture(CompletableFuture.supplyAsync(() -> {
            Document doc = collection.find(new Document("_id", "12345")).first();
            return doc.toJson();
        }, executor)) // Using dedicated executor for blocking operations
        .subscribe(json -> System.out.println("Document: " + json));
    }
    
    // ExecutorService with properly managed blocking I/O
    public void good_case_14() {
        ExecutorService ioExecutor = Executors.newFixedThreadPool(10);
        ExecutorService computeExecutor = Executors.newFixedThreadPool(10);
        
        // ok: java-detect-blocking-service-calls
        CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL("https://api.example.com/data");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                try (var reader = connection.getInputStream()) {
                    return new String(reader.readAllBytes());
                }
            } catch (IOException e) {
                return "Error: " + e.getMessage();
            }
        }, ioExecutor) // Using dedicated I/O executor for blocking operations
        .thenApplyAsync(data -> processData(data), computeExecutor)
        .thenAccept(System.out::println);
    }
    
    // Vert.x WebClient with non-blocking operation
    public void good_case_15() {
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx, new WebClientOptions());
        
        // ok: java-detect-blocking-service-calls
        vertx.createHttpServer().requestHandler(request -> {
            client.get(8080, "localhost", "/api/data").send().onSuccess(response -> {
                vertx.setTimer(2000, id -> { // Non-blocking delay
                    request.response().end(response.bodyAsString());
                });
            });
        }).listen(8080);
    }
    
    // Helper methods
    private String processData(String data) {
        return "Processed: " + data;
    }
    
    // Mock interface for examples
    interface ApiService {
        Call<String> getData();
        retrofit2.Call<String> getDataAsync();
    }
}
// {/fact}