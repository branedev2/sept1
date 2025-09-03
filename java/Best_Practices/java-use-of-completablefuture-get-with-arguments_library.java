import java.util.concurrent.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.lambda.LambdaAsyncClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.ApiCallContext;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.Storage;
import com.google.cloud.pubsub.v1.Publisher;
import com.google.pubsub.v1.PubsubMessage;
import com.azure.core.http.rest.Response;
import com.azure.storage.blob.BlobAsyncClient;
import com.azure.storage.blob.BlobClientBuilder;
import com.azure.core.util.Context;
import reactor.core.publisher.Mono;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.schedulers.Schedulers;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.Call;
import feign.Feign;
import feign.jackson.JacksonDecoder;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import java.io.IOException;

// Security Issue: Using CompletableFuture.get() without timeout arguments or using join() can lead to indefinite waiting,
// potentially causing deadlocks or wasting resources.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Java HTTP Client with CompletableFuture.join()
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/data"))
            .build();
    
    CompletableFuture<HttpResponse<String>> responseFuture = 
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        HttpResponse<String> response = responseFuture.join(); // Can block indefinitely
        System.out.println("Response: " + response.body());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // Spring WebClient with CompletableFuture.get()
    WebClient webClient = WebClient.create();
    
    CompletableFuture<String> responseFuture = webClient.get()
            .uri("https://api.example.com/users")
            .retrieve()
            .bodyToMono(String.class)
            .toFuture();
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String response = responseFuture.get(); // Can block indefinitely
        System.out.println("User data: " + response);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // AWS S3 Async Client with CompletableFuture.join()
    S3AsyncClient s3Client = S3AsyncClient.create();
    
    CompletableFuture<byte[]> futureObject = s3Client.getObject(
            GetObjectRequest.builder()
                    .bucket("my-bucket")
                    .key("my-object")
                    .build(),
            AsyncResponseTransformer.toBytes());
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        byte[] objectData = futureObject.join(); // Can block indefinitely
        System.out.println("Object size: " + objectData.length);
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        s3Client.close();
    }
}

public void bad_case_4() {
    // OkHttp with CompletableFuture.get()
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://api.example.com/products")
            .build();
    
    CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String responseBody = future.get(); // Can block indefinitely
        System.out.println("Products: " + responseBody);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // AWS DynamoDB Async Client with CompletableFuture.join()
    DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.create();
    
    CompletableFuture<software.amazon.awssdk.services.dynamodb.model.GetItemResponse> future = 
            dynamoClient.getItem(GetItemRequest.builder()
                    .tableName("Users")
                    .key(java.util.Map.of("userId", 
                         software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("user123").build()))
                    .build());
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        software.amazon.awssdk.services.dynamodb.model.GetItemResponse response = future.join(); // Can block indefinitely
        System.out.println("User data: " + response.item());
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        dynamoClient.close();
    }
}

public void bad_case_6() {
    // Google Cloud Storage with CompletableFuture.get()
    Storage storage = StorageOptions.getDefaultInstance().getService();
    
    CompletableFuture<byte[]> future = CompletableFuture.supplyAsync(() -> {
        try {
            return storage.readAllBytes("my-bucket", "my-object");
        } catch (Exception e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        byte[] data = future.get(); // Can block indefinitely
        System.out.println("Object size: " + data.length);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Azure Blob Storage with CompletableFuture.join()
    BlobAsyncClient blobClient = new BlobClientBuilder()
            .connectionString("DefaultEndpointsProtocol=https;...")
            .containerName("my-container")
            .blobName("my-blob")
            .buildAsyncClient();
    
    CompletableFuture<byte[]> future = blobClient.downloadContent().toFuture();
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        byte[] blobContent = future.join(); // Can block indefinitely
        System.out.println("Blob size: " + blobContent.length);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // Vert.x WebClient with CompletableFuture.get()
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx, new WebClientOptions());
    
    CompletableFuture<String> future = new CompletableFuture<>();
    
    client.get(8080, "localhost", "/api/data")
          .send(ar -> {
              if (ar.succeeded()) {
                  future.complete(ar.result().bodyAsString());
              } else {
                  future.completeExceptionally(ar.cause());
              }
          });
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String result = future.get(); // Can block indefinitely
        System.out.println("Response: " + result);
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        vertx.close();
    }
}

public void bad_case_9() {
    // RxJava with CompletableFuture.join()
    Single<String> single = Single.fromCallable(() -> {
        // Simulate HTTP request
        Thread.sleep(1000);
        return "Response data";
    }).subscribeOn(Schedulers.io());
    
    CompletableFuture<String> future = single.toCompletionStage().toCompletableFuture();
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String result = future.join(); // Can block indefinitely
        System.out.println("Result: " + result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // AWS Lambda Async Client with CompletableFuture.get()
    LambdaAsyncClient lambdaClient = LambdaAsyncClient.create();
    
    CompletableFuture<software.amazon.awssdk.services.lambda.model.InvokeResponse> future = 
            lambdaClient.invoke(InvokeRequest.builder()
                    .functionName("my-function")
                    .payload(software.amazon.awssdk.core.SdkBytes.fromUtf8String("{\"key\":\"value\"}"))
                    .build());
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        software.amazon.awssdk.services.lambda.model.InvokeResponse response = future.get(); // Can block indefinitely
        System.out.println("Response: " + response.payload().asUtf8String());
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        lambdaClient.close();
    }
}

public void bad_case_11() {
    // Retrofit with CompletableFuture.join()
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    
    ApiService service = retrofit.create(ApiService.class);
    Call<ResponseData> call = service.getData();
    
    CompletableFuture<ResponseData> future = CompletableFuture.supplyAsync(() -> {
        try {
            return call.execute().body();
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        ResponseData data = future.join(); // Can block indefinitely
        System.out.println("Data: " + data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Feign Client with CompletableFuture.get()
    UserClient userClient = Feign.builder()
            .decoder(new JacksonDecoder())
            .target(UserClient.class, "https://api.example.com");
    
    CompletableFuture<User> future = CompletableFuture.supplyAsync(() -> {
        return userClient.getUser("123");
    });
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        User user = future.get(); // Can block indefinitely
        System.out.println("User: " + user.getName());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // AsyncHttpClient with CompletableFuture.join()
    AsyncHttpClient client = Dsl.asyncHttpClient();
    
    CompletableFuture<Response> future = client.prepareGet("https://api.example.com/data")
            .execute()
            .toCompletableFuture();
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        Response response = future.join(); // Can block indefinitely
        System.out.println("Status: " + response.getStatusCode());
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

public void bad_case_14() {
    // Apache HttpClient with CompletableFuture.get()
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("https://api.example.com/data");
    
    CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
        try {
            return EntityUtils.toString(httpClient.execute(request).getEntity());
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String response = future.get(); // Can block indefinitely
        System.out.println("Response: " + response);
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            httpClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_15() {
    // Google PubSub with CompletableFuture.join()
    try {
        Publisher publisher = Publisher.newBuilder("my-topic").build();
        PubsubMessage message = PubsubMessage.newBuilder().setData(
                com.google.protobuf.ByteString.copyFromUtf8("Hello World")).build();
        
        CompletableFuture<String> future = publisher.publish(message)
                .thenApply(messageId -> messageId)
                .toCompletableFuture();
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String messageId = future.join(); // Can block indefinitely
        System.out.println("Published message ID: " + messageId);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Java HTTP Client with CompletableFuture.get() with timeout
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/data"))
            .build();
    
    CompletableFuture<HttpResponse<String>> responseFuture = 
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        HttpResponse<String> response = responseFuture.get(30, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Response: " + response.body());
    } catch (TimeoutException e) {
        System.out.println("Request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // Spring WebClient with CompletableFuture.get() with timeout
    WebClient webClient = WebClient.create();
    
    CompletableFuture<String> responseFuture = webClient.get()
            .uri("https://api.example.com/users")
            .retrieve()
            .bodyToMono(String.class)
            .toFuture();
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        String response = responseFuture.get(10, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("User data: " + response);
    } catch (TimeoutException e) {
        System.out.println("Request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // AWS S3 Async Client with CompletableFuture.get() with timeout
    S3AsyncClient s3Client = S3AsyncClient.create();
    
    CompletableFuture<byte[]> futureObject = s3Client.getObject(
            GetObjectRequest.builder()
                    .bucket("my-bucket")
                    .key("my-object")
                    .build(),
            AsyncResponseTransformer.toBytes());
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        byte[] objectData = futureObject.get(20, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Object size: " + objectData.length);
    } catch (TimeoutException e) {
        System.out.println("S3 operation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        s3Client.close();
    }
}

public void good_case_4() {
    // OkHttp with CompletableFuture.get() with timeout
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://api.example.com/products")
            .build();
    
    CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        String responseBody = future.get(15, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Products: " + responseBody);
    } catch (TimeoutException e) {
        System.out.println("Request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // AWS DynamoDB Async Client with CompletableFuture.get() with timeout
    DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.create();
    
    CompletableFuture<software.amazon.awssdk.services.dynamodb.model.GetItemResponse> future = 
            dynamoClient.getItem(GetItemRequest.builder()
                    .tableName("Users")
                    .key(java.util.Map.of("userId", 
                         software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("user123").build()))
                    .build());
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        software.amazon.awssdk.services.dynamodb.model.GetItemResponse response = 
                future.get(5, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("User data: " + response.item());
    } catch (TimeoutException e) {
        System.out.println("DynamoDB operation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        dynamoClient.close();
    }
}

public void good_case_6() {
    // Google Cloud Storage with CompletableFuture.get() with timeout
    Storage storage = StorageOptions.getDefaultInstance().getService();
    
    CompletableFuture<byte[]> future = CompletableFuture.supplyAsync(() -> {
        try {
            return storage.readAllBytes("my-bucket", "my-object");
        } catch (Exception e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        byte[] data = future.get(25, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Object size: " + data.length);
    } catch (TimeoutException e) {
        System.out.println("Cloud Storage operation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // Azure Blob Storage with CompletableFuture.get() with timeout
    BlobAsyncClient blobClient = new BlobClientBuilder()
            .connectionString("DefaultEndpointsProtocol=https;...")
            .containerName("my-container")
            .blobName("my-blob")
            .buildAsyncClient();
    
    CompletableFuture<byte[]> future = blobClient.downloadContent().toFuture();
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        byte[] blobContent = future.get(30, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Blob size: " + blobContent.length);
    } catch (TimeoutException e) {
        System.out.println("Azure Blob operation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // Vert.x WebClient with CompletableFuture.get() with timeout
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx, new WebClientOptions());
    
    CompletableFuture<String> future = new CompletableFuture<>();
    
    client.get(8080, "localhost", "/api/data")
          .send(ar -> {
              if (ar.succeeded()) {
                  future.complete(ar.result().bodyAsString());
              } else {
                  future.completeExceptionally(ar.cause());
              }
          });
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        String result = future.get(5, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Response: " + result);
    } catch (TimeoutException e) {
        System.out.println("Vert.x request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        vertx.close();
    }
}

public void good_case_9() {
    // RxJava with CompletableFuture.get() with timeout
    Single<String> single = Single.fromCallable(() -> {
        // Simulate HTTP request
        Thread.sleep(1000);
        return "Response data";
    }).subscribeOn(Schedulers.io());
    
    CompletableFuture<String> future = single.toCompletionStage().toCompletableFuture();
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        String result = future.get(2, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Result: " + result);
    } catch (TimeoutException e) {
        System.out.println("RxJava operation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // AWS Lambda Async Client with CompletableFuture.get() with timeout
    LambdaAsyncClient lambdaClient = LambdaAsyncClient.create();
    
    CompletableFuture<software.amazon.awssdk.services.lambda.model.InvokeResponse> future = 
            lambdaClient.invoke(InvokeRequest.builder()
                    .functionName("my-function")
                    .payload(software.amazon.awssdk.core.SdkBytes.fromUtf8String("{\"key\":\"value\"}"))
                    .build());
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        software.amazon.awssdk.services.lambda.model.InvokeResponse response = 
                future.get(60, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Response: " + response.payload().asUtf8String());
    } catch (TimeoutException e) {
        System.out.println("Lambda invocation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        lambdaClient.close();
    }
}

public void good_case_11() {
    // Retrofit with CompletableFuture.get() with timeout
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    
    ApiService service = retrofit.create(ApiService.class);
    Call<ResponseData> call = service.getData();
    
    CompletableFuture<ResponseData> future = CompletableFuture.supplyAsync(() -> {
        try {
            return call.execute().body();
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        ResponseData data = future.get(10, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Data: " + data);
    } catch (TimeoutException e) {
        System.out.println("Retrofit request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Feign Client with CompletableFuture.get() with timeout
    UserClient userClient = Feign.builder()
            .decoder(new JacksonDecoder())
            .target(UserClient.class, "https://api.example.com");
    
    CompletableFuture<User> future = CompletableFuture.supplyAsync(() -> {
        return userClient.getUser("123");
    });
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        User user = future.get(8, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("User: " + user.getName());
    } catch (TimeoutException e) {
        System.out.println("Feign client request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // AsyncHttpClient with CompletableFuture.get() with timeout
    AsyncHttpClient client = Dsl.asyncHttpClient();
    
    CompletableFuture<Response> future = client.prepareGet("https://api.example.com/data")
            .execute()
            .toCompletableFuture();
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        Response response = future.get(15, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Status: " + response.getStatusCode());
    } catch (TimeoutException e) {
        System.out.println("AsyncHttpClient request timed out");
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

public void good_case_14() {
    // Apache HttpClient with CompletableFuture.get() with timeout
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("https://api.example.com/data");
    
    CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
        try {
            return EntityUtils.toString(httpClient.execute(request).getEntity());
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    });
    
    try {
        // ok: java-use-of-completablefuture-get-with-arguments
        String response = future.get(12, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Response: " + response);
    } catch (TimeoutException e) {
        System.out.println("Apache HttpClient request timed out");
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            httpClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void good_case_15() {
    // Google PubSub with CompletableFuture.get() with timeout
    try {
        Publisher publisher = Publisher.newBuilder("my-topic").build();
        PubsubMessage message = PubsubMessage.newBuilder().setData(
                com.google.protobuf.ByteString.copyFromUtf8("Hello World")).build();
        
        CompletableFuture<String> future = publisher.publish(message)
                .thenApply(messageId -> messageId)
                .toCompletableFuture();
        
        // ok: java-use-of-completablefuture-get-with-arguments
        String messageId = future.get(5, TimeUnit.SECONDS); // Safe with timeout
        System.out.println("Published message ID: " + messageId);
    } catch (TimeoutException e) {
        System.out.println("PubSub publish operation timed out");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Interfaces and classes needed for the examples
interface ApiService {
    Call<ResponseData> getData();
}

interface UserClient {
    User getUser(String id);
}

class ResponseData {
    private String data;
    
    public String getData() {
        return data;
    }
}

class User {
    private String name;
    
    public String getName() {
        return name;
    }
}