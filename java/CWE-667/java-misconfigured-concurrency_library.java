import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpMethod;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.ApiCallContext;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.Blob;
import com.azure.core.http.rest.Response;
import com.azure.storage.blob.BlobAsyncClient;
import com.azure.storage.blob.BlobClientBuilder;
import com.azure.storage.blob.models.BlobProperties;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.HttpResponse;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.schedulers.Schedulers;
import reactor.core.publisher.Mono;
import java.time.Duration;

// Security Issue: Using CompletableFuture.get() or Future.get() without timeout parameters can lead to threads
// waiting indefinitely, potentially causing application hangs or resource exhaustion.

// True Positive Examples (Vulnerable/Insecure Code)

public class MisconfiguredConcurrencyExamples {

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
    public void bad_case_1() {
        // Java HttpClient with CompletableFuture without timeout
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data"))
                .build();
        
        CompletableFuture<HttpResponse<String>> responseFuture = 
                client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        
        try {
            // ruleid: java-misconfigured-concurrency
            HttpResponse<String> response = responseFuture.get(); // No timeout specified
            System.out.println(response.body());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        // Spring RestTemplate with ExecutorService and Future
        RestTemplate restTemplate = new RestTemplate();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        Future<ResponseEntity<String>> future = executor.submit(() -> 
            restTemplate.exchange("https://api.example.com/data", HttpMethod.GET, null, String.class));
        
        try {
            // ruleid: java-misconfigured-concurrency
            ResponseEntity<String> response = future.get(); // No timeout specified
            System.out.println(response.getBody());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_3() {
        // Apache HttpClient with CompletableFuture
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://api.example.com/data");
            
            CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
                try {
                    return EntityUtils.toString(httpClient.execute(request).getEntity());
                } catch (Exception e) {
                    throw new CompletionException(e);
                }
            });
            
            try {
                // ruleid: java-misconfigured-concurrency
                String response = future.get(); // No timeout specified
                System.out.println(response);
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        // Retrofit API client with Future
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        
        ApiService service = retrofit.create(ApiService.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        Future<retrofit2.Response<Object>> future = executor.submit(() -> {
            Call<Object> call = service.getData();
            return call.execute();
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            retrofit2.Response<Object> response = future.get(); // No timeout specified
            System.out.println(response.body());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_5() {
        // OkHttp with CompletableFuture
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try (Response response = client.newCall(request).execute()) {
                return response.body().string();
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            String responseBody = future.get(); // No timeout specified
            System.out.println(responseBody);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        // AWS S3 Async Client
        S3AsyncClient s3Client = S3AsyncClient.create();
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .build();
        
        CompletableFuture<byte[]> future = s3Client.getObject(
                getObjectRequest, 
                AsyncResponseTransformer.toBytes());
        
        try {
            // ruleid: java-misconfigured-concurrency
            byte[] data = future.get(); // No timeout specified
            System.out.println("Data size: " + data.length);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // Google Cloud Storage with CompletableFuture
        Storage storage = StorageOptions.getDefaultInstance().getService();
        CompletableFuture<byte[]> future = CompletableFuture.supplyAsync(() -> {
            Blob blob = storage.get("my-bucket", "my-object");
            return blob.getContent();
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            byte[] content = future.get(); // No timeout specified
            System.out.println("Content length: " + content.length);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        // Azure Blob Storage with CompletableFuture
        BlobAsyncClient blobClient = new BlobClientBuilder()
                .connectionString("connection-string")
                .containerName("container-name")
                .blobName("blob-name")
                .buildAsyncClient();
        
        CompletableFuture<com.azure.storage.blob.models.BlobProperties> future = 
                blobClient.getProperties().toFuture();
        
        try {
            // ruleid: java-misconfigured-concurrency
            BlobProperties properties = future.get(); // No timeout specified
            System.out.println("Blob size: " + properties.getBlobSize());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // Vert.x WebClient with CompletableFuture
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        CompletableFuture<String> future = new CompletableFuture<>();
        
        client.get(8080, "localhost", "/api/data")
              .send(ar -> {
                  if (ar.succeeded()) {
                      HttpResponse<Buffer> response = ar.result();
                      future.complete(response.bodyAsString());
                  } else {
                      future.completeExceptionally(ar.cause());
                  }
              });
        
        try {
            // ruleid: java-misconfigured-concurrency
            String result = future.get(); // No timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            vertx.close();
        }
    }

    public void bad_case_10() {
        // AsyncHttpClient with CompletableFuture
        AsyncHttpClient client = Dsl.asyncHttpClient();
        CompletableFuture<Response> future = client.prepareGet("https://api.example.com/data")
                .execute()
                .toCompletableFuture();
        
        try {
            // ruleid: java-misconfigured-concurrency
            Response response = future.get(); // No timeout specified
            System.out.println(response.getResponseBody());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            try {
                client.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void bad_case_11() {
        // Caffeine Cache with CompletableFuture
        AsyncLoadingCache<String, String> cache = Caffeine.newBuilder()
                .buildAsync(key -> fetchDataFromApi(key));
        
        CompletableFuture<String> future = cache.get("user-123");
        
        try {
            // ruleid: java-misconfigured-concurrency
            String data = future.get(); // No timeout specified
            System.out.println(data);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // RxJava with CompletableFuture
        Single<String> single = Single.fromCallable(() -> {
            // Simulate HTTP request
            Thread.sleep(1000);
            return "Response from API";
        }).subscribeOn(Schedulers.io());
        
        CompletableFuture<String> future = single.toFuture();
        
        try {
            // ruleid: java-misconfigured-concurrency
            String result = future.get(); // No timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // Project Reactor with CompletableFuture
        Mono<String> mono = Mono.fromCallable(() -> {
            // Simulate HTTP request
            Thread.sleep(1000);
            return "Response from API";
        });
        
        CompletableFuture<String> future = mono.toFuture();
        
        try {
            // ruleid: java-misconfigured-concurrency
            String result = future.get(); // No timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // Custom ThreadPoolExecutor with Future
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                2, 5, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        Future<String> future = executor.submit(() -> {
            // Simulate HTTP request
            URL url = new URL("https://api.example.com/data");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            String result = future.get(); // No timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_15() {
        // ForkJoinPool with CompletableFuture
        ForkJoinPool customPool = new ForkJoinPool(4);
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulate HTTP request
                URL url = new URL("https://api.example.com/data");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    return reader.lines().collect(Collectors.joining("\n"));
                }
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, customPool);
        
        try {
            // ruleid: java-misconfigured-concurrency
            String result = future.get(); // No timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            customPool.shutdown();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1() {
        // Java HttpClient with CompletableFuture with timeout
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data"))
                .build();
        
        CompletableFuture<HttpResponse<String>> responseFuture = 
                client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        
        try {
            // ok: java-misconfigured-concurrency
            HttpResponse<String> response = responseFuture.get(30, TimeUnit.SECONDS); // Timeout specified
            System.out.println(response.body());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        // Spring RestTemplate with ExecutorService and Future with timeout
        RestTemplate restTemplate = new RestTemplate();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        Future<ResponseEntity<String>> future = executor.submit(() -> 
            restTemplate.exchange("https://api.example.com/data", HttpMethod.GET, null, String.class));
        
        try {
            // ok: java-misconfigured-concurrency
            ResponseEntity<String> response = future.get(10, TimeUnit.SECONDS); // Timeout specified
            System.out.println(response.getBody());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_3() {
        // Apache HttpClient with CompletableFuture with timeout
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://api.example.com/data");
            
            CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
                try {
                    return EntityUtils.toString(httpClient.execute(request).getEntity());
                } catch (Exception e) {
                    throw new CompletionException(e);
                }
            });
            
            try {
                // ok: java-misconfigured-concurrency
                String response = future.get(5, TimeUnit.SECONDS); // Timeout specified
                System.out.println(response);
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        // Retrofit API client with Future with timeout
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        
        ApiService service = retrofit.create(ApiService.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        Future<retrofit2.Response<Object>> future = executor.submit(() -> {
            Call<Object> call = service.getData();
            return call.execute();
        });
        
        try {
            // ok: java-misconfigured-concurrency
            retrofit2.Response<Object> response = future.get(15, TimeUnit.SECONDS); // Timeout specified
            System.out.println(response.body());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_5() {
        // OkHttp with CompletableFuture with timeout
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try (Response response = client.newCall(request).execute()) {
                return response.body().string();
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });
        
        try {
            // ok: java-misconfigured-concurrency
            String responseBody = future.get(20, TimeUnit.SECONDS); // Timeout specified
            System.out.println(responseBody);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        // AWS S3 Async Client with timeout
        S3AsyncClient s3Client = S3AsyncClient.create();
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .build();
        
        CompletableFuture<byte[]> future = s3Client.getObject(
                getObjectRequest, 
                AsyncResponseTransformer.toBytes());
        
        try {
            // ok: java-misconfigured-concurrency
            byte[] data = future.get(30, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Data size: " + data.length);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // Google Cloud Storage with CompletableFuture with timeout
        Storage storage = StorageOptions.getDefaultInstance().getService();
        CompletableFuture<byte[]> future = CompletableFuture.supplyAsync(() -> {
            Blob blob = storage.get("my-bucket", "my-object");
            return blob.getContent();
        });
        
        try {
            // ok: java-misconfigured-concurrency
            byte[] content = future.get(45, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Content length: " + content.length);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        // Azure Blob Storage with CompletableFuture with timeout
        BlobAsyncClient blobClient = new BlobClientBuilder()
                .connectionString("connection-string")
                .containerName("container-name")
                .blobName("blob-name")
                .buildAsyncClient();
        
        CompletableFuture<com.azure.storage.blob.models.BlobProperties> future = 
                blobClient.getProperties().toFuture();
        
        try {
            // ok: java-misconfigured-concurrency
            BlobProperties properties = future.get(25, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Blob size: " + properties.getBlobSize());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Vert.x WebClient with CompletableFuture with timeout
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        CompletableFuture<String> future = new CompletableFuture<>();
        
        client.get(8080, "localhost", "/api/data")
              .send(ar -> {
                  if (ar.succeeded()) {
                      HttpResponse<Buffer> response = ar.result();
                      future.complete(response.bodyAsString());
                  } else {
                      future.completeExceptionally(ar.cause());
                  }
              });
        
        try {
            // ok: java-misconfigured-concurrency
            String result = future.get(5, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        } finally {
            vertx.close();
        }
    }

    public void good_case_10() {
        // AsyncHttpClient with CompletableFuture with timeout
        AsyncHttpClient client = Dsl.asyncHttpClient();
        CompletableFuture<Response> future = client.prepareGet("https://api.example.com/data")
                .execute()
                .toCompletableFuture();
        
        try {
            // ok: java-misconfigured-concurrency
            Response response = future.get(10, TimeUnit.SECONDS); // Timeout specified
            System.out.println(response.getResponseBody());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        } finally {
            try {
                client.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_11() {
        // Caffeine Cache with CompletableFuture with timeout
        AsyncLoadingCache<String, String> cache = Caffeine.newBuilder()
                .buildAsync(key -> fetchDataFromApi(key));
        
        CompletableFuture<String> future = cache.get("user-123");
        
        try {
            // ok: java-misconfigured-concurrency
            String data = future.get(8, TimeUnit.SECONDS); // Timeout specified
            System.out.println(data);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // RxJava with CompletableFuture with timeout
        Single<String> single = Single.fromCallable(() -> {
            // Simulate HTTP request
            Thread.sleep(1000);
            return "Response from API";
        }).subscribeOn(Schedulers.io());
        
        CompletableFuture<String> future = single.toFuture();
        
        try {
            // ok: java-misconfigured-concurrency
            String result = future.get(2, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // Project Reactor with CompletableFuture with timeout
        Mono<String> mono = Mono.fromCallable(() -> {
            // Simulate HTTP request
            Thread.sleep(1000);
            return "Response from API";
        });
        
        CompletableFuture<String> future = mono.toFuture();
        
        try {
            // ok: java-misconfigured-concurrency
            String result = future.get(3, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        // Custom ThreadPoolExecutor with Future with timeout
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                2, 5, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        Future<String> future = executor.submit(() -> {
            // Simulate HTTP request
            URL url = new URL("https://api.example.com/data");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        });
        
        try {
            // ok: java-misconfigured-concurrency
            String result = future.get(12, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_15() {
        // ForkJoinPool with CompletableFuture with timeout
        ForkJoinPool customPool = new ForkJoinPool(4);
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulate HTTP request
                URL url = new URL("https://api.example.com/data");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    return reader.lines().collect(Collectors.joining("\n"));
                }
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, customPool);
        
        try {
            // ok: java-misconfigured-concurrency
            String result = future.get(7, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        } finally {
            customPool.shutdown();
        }
    }

    // Helper method for Caffeine cache example
    private String fetchDataFromApi(String key) {
        // Simulate API call
        try {
            Thread.sleep(100);
            return "Data for " + key;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    // Interface for Retrofit example
    interface ApiService {
        @retrofit2.http.GET("data")
        Call<Object> getData();
    }
}
// {/fact}