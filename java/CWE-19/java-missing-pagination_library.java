import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ListObjectsV2Request;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.youtube.YouTube;
import com.google.api.services.youtube.model.VideoListResponse;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobItem;
import com.azure.storage.blob.models.ListBlobsOptions;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.firestore.CollectionReference;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.FirestoreOptions;
import com.google.cloud.firestore.Query;
import com.google.cloud.firestore.QuerySnapshot;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.jdbc.core.JdbcTemplate;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.ListContainersCmd;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.core.DockerClientBuilder;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.util.Config;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;
import retrofit2.http.Query;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Iterator;

// Security Issue: Missing pagination on API calls that support pagination can lead to incomplete results,
// performance issues, or even application crashes when dealing with large datasets.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // AWS S3 - Missing pagination when listing objects
    String bucketName = request.getParameter("bucket");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    // ruleid: java-missing-pagination
    ListObjectsV2Result result = s3Client.listObjectsV2(bucketName);
    
    // Process all objects without pagination
    result.getObjectSummaries().forEach(obj -> {
        System.out.println(obj.getKey());
    });
}

public void bad_case_2(HttpServletRequest request) {
    // AWS DynamoDB - Missing pagination when scanning a table
    String tableName = request.getParameter("table");
    AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
    
    ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
    
    // ruleid: java-missing-pagination
    ScanResult scanResult = dynamoDB.scan(scanRequest);
    
    // Process all items without pagination
    scanResult.getItems().forEach(item -> {
        System.out.println(item);
    });
}

public void bad_case_3(HttpServletRequest request) throws IOException, GeneralSecurityException {
    // Google Drive API - Missing pagination when listing files
    String userId = request.getParameter("userId");
    
    Drive driveService = new Drive.Builder(
            GoogleNetHttpTransport.newTrustedTransport(),
            JacksonFactory.getDefaultInstance(),
            null)
            .setApplicationName("Drive API Example")
            .build();
    
    // ruleid: java-missing-pagination
    FileList result = driveService.files().list()
            .setQ("'" + userId + "' in owners")
            .execute();
    
    // Process all files without pagination
    result.getFiles().forEach(file -> {
        System.out.println(file.getName());
    });
}

public void bad_case_4(HttpServletRequest request) {
    // MongoDB - Missing pagination when querying documents
    String collectionName = request.getParameter("collection");
    
    MongoClient mongoClient = new MongoClient();
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection(collectionName);
    
    // ruleid: java-missing-pagination
    FindIterable<Document> documents = collection.find();
    
    // Process all documents without pagination
    for (Document doc : documents) {
        System.out.println(doc.toJson());
    }
    mongoClient.close();
}

public void bad_case_5(HttpServletRequest request) throws IOException {
    // Elasticsearch - Missing pagination when searching documents
    String indexName = request.getParameter("index");
    
    RestHighLevelClient client = new RestHighLevelClient();
    SearchRequest searchRequest = new SearchRequest(indexName);
    SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
    searchRequest.source(searchSourceBuilder);
    
    // ruleid: java-missing-pagination
    SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
    
    // Process all search hits without pagination
    Arrays.stream(searchResponse.getHits().getHits()).forEach(hit -> {
        System.out.println(hit.getSourceAsString());
    });
    client.close();
}

public void bad_case_6(HttpServletRequest request) {
    // AWS SDK v2 DynamoDB - Missing pagination when querying items
    String tableName = request.getParameter("table");
    String keyValue = request.getParameter("key");
    
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    QueryRequest queryRequest = QueryRequest.builder()
            .tableName(tableName)
            .keyConditionExpression("partitionKey = :pk")
            .expressionAttributeValues(Map.of(":pk", AttributeValue.builder().s(keyValue).build()))
            .build();
    
    // ruleid: java-missing-pagination
    QueryResponse response = dynamoDbClient.query(queryRequest);
    
    // Process all items without pagination
    response.items().forEach(item -> {
        System.out.println(item);
    });
}

public void bad_case_7(HttpServletRequest request) {
    // Azure Blob Storage - Missing pagination when listing blobs
    String containerName = request.getParameter("container");
    
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("your-connection-string")
            .buildClient();
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
    
    // ruleid: java-missing-pagination
    Iterable<BlobItem> blobs = containerClient.listBlobs();
    
    // Process all blobs without pagination
    for (BlobItem blob : blobs) {
        System.out.println(blob.getName());
    }
}

public void bad_case_8(HttpServletRequest request) {
    // Google Cloud Storage - Missing pagination when listing objects
    String bucketName = request.getParameter("bucket");
    
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Bucket bucket = storage.get(bucketName);
    
    // ruleid: java-missing-pagination
    Iterable<Blob> blobs = bucket.list().iterateAll();
    
    // Process all blobs without pagination
    for (Blob blob : blobs) {
        System.out.println(blob.getName());
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Google Cloud Firestore - Missing pagination when querying documents
    String collectionName = request.getParameter("collection");
    
    Firestore firestore = FirestoreOptions.getDefaultInstance().getService();
    CollectionReference collection = firestore.collection(collectionName);
    
    // ruleid: java-missing-pagination
    QuerySnapshot querySnapshot = collection.get().get();
    
    // Process all documents without pagination
    querySnapshot.getDocuments().forEach(document -> {
        System.out.println(document.getData());
    });
}

public void bad_case_10(HttpServletRequest request) {
    // Docker Java API - Missing pagination when listing containers
    DockerClient dockerClient = DockerClientBuilder.getInstance().build();
    
    ListContainersCmd listContainersCmd = dockerClient.listContainersCmd();
    
    // ruleid: java-missing-pagination
    List<Container> containers = listContainersCmd.exec();
    
    // Process all containers without pagination
    containers.forEach(container -> {
        System.out.println(container.getId());
    });
}

public void bad_case_11(HttpServletRequest request) throws ApiException {
    // Kubernetes Java Client - Missing pagination when listing pods
    String namespace = request.getParameter("namespace");
    
    ApiClient client = Config.defaultClient();
    Configuration.setDefaultApiClient(client);
    CoreV1Api api = new CoreV1Api();
    
    // ruleid: java-missing-pagination
    V1PodList list = api.listNamespacedPod(namespace, null, null, null, null, null, null, null, null, null, null);
    
    // Process all pods without pagination
    list.getItems().forEach(pod -> {
        System.out.println(pod.getMetadata().getName());
    });
}

public void bad_case_12(HttpServletRequest request) {
    // AWS EC2 - Missing pagination when describing instances
    Ec2Client ec2Client = Ec2Client.create();
    
    DescribeInstancesRequest describeInstancesRequest = DescribeInstancesRequest.builder().build();
    
    // ruleid: java-missing-pagination
    DescribeInstancesResponse response = ec2Client.describeInstances(describeInstancesRequest);
    
    // Process all instances without pagination
    response.reservations().forEach(reservation -> {
        reservation.instances().forEach(instance -> {
            System.out.println(instance.instanceId());
        });
    });
}

public void bad_case_13(HttpServletRequest request) throws IOException {
    // OkHttp - Missing pagination when fetching paginated API results
    String apiUrl = request.getParameter("apiUrl");
    
    OkHttpClient client = new OkHttpClient();
    Request okRequest = new Request.Builder()
            .url(apiUrl)
            .build();
    
    // ruleid: java-missing-pagination
    Response response = client.newCall(okRequest).execute();
    String responseBody = response.body().string();
    
    // Process the response without checking for pagination
    System.out.println(responseBody);
}

public void bad_case_14(HttpServletRequest request) throws IOException {
    // Apache HttpClient - Missing pagination when fetching paginated API results
    String apiUrl = request.getParameter("apiUrl");
    
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet httpGet = new HttpGet(apiUrl);
    
    // ruleid: java-missing-pagination
    CloseableHttpResponse response = httpClient.execute(httpGet);
    String responseBody = EntityUtils.toString(response.getEntity());
    
    // Process the response without checking for pagination
    System.out.println(responseBody);
    httpClient.close();
}

public void bad_case_15(HttpServletRequest request) {
    // Retrofit - Missing pagination when fetching paginated API results
    String query = request.getParameter("query");
    
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    
    SearchApi searchApi = retrofit.create(SearchApi.class);
    
    // ruleid: java-missing-pagination
    Call<SearchResult> call = searchApi.search(query);
    SearchResult result = call.execute().body();
    
    // Process the result without checking for pagination
    result.getItems().forEach(item -> {
        System.out.println(item.getName());
    });
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // AWS S3 - Proper pagination when listing objects
    String bucketName = request.getParameter("bucket");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    ListObjectsV2Request listObjectsRequest = new ListObjectsV2Request()
            .withBucketName(bucketName)
            .withMaxKeys(1000);
    
    ListObjectsV2Result result;
    do {
        // ok: java-missing-pagination
        result = s3Client.listObjectsV2(listObjectsRequest);
        
        // Process current page of objects
        result.getObjectSummaries().forEach(obj -> {
            System.out.println(obj.getKey());
        });
        
        // Set continuation token for next page
        listObjectsRequest.setContinuationToken(result.getNextContinuationToken());
    } while (result.isTruncated());
}

public void good_case_2(HttpServletRequest request) {
    // AWS DynamoDB - Proper pagination when scanning a table
    String tableName = request.getParameter("table");
    AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
    
    ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
    
    Map<String, AttributeValue> lastEvaluatedKey = null;
    do {
        scanRequest.withExclusiveStartKey(lastEvaluatedKey);
        
        // ok: java-missing-pagination
        ScanResult scanResult = dynamoDB.scan(scanRequest);
        
        // Process current page of items
        scanResult.getItems().forEach(item -> {
            System.out.println(item);
        });
        
        lastEvaluatedKey = scanResult.getLastEvaluatedKey();
    } while (lastEvaluatedKey != null);
}

public void good_case_3(HttpServletRequest request) throws IOException, GeneralSecurityException {
    // Google Drive API - Proper pagination when listing files
    String userId = request.getParameter("userId");
    
    Drive driveService = new Drive.Builder(
            GoogleNetHttpTransport.newTrustedTransport(),
            JacksonFactory.getDefaultInstance(),
            null)
            .setApplicationName("Drive API Example")
            .build();
    
    String pageToken = null;
    do {
        // ok: java-missing-pagination
        FileList result = driveService.files().list()
                .setQ("'" + userId + "' in owners")
                .setPageSize(100)
                .setPageToken(pageToken)
                .execute();
        
        // Process current page of files
        result.getFiles().forEach(file -> {
            System.out.println(file.getName());
        });
        
        pageToken = result.getNextPageToken();
    } while (pageToken != null);
}

public void good_case_4(HttpServletRequest request) {
    // MongoDB - Proper pagination when querying documents
    String collectionName = request.getParameter("collection");
    int pageSize = Integer.parseInt(request.getParameter("pageSize"));
    int pageNum = Integer.parseInt(request.getParameter("pageNum"));
    
    MongoClient mongoClient = new MongoClient();
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection(collectionName);
    
    // ok: java-missing-pagination
    FindIterable<Document> documents = collection.find()
            .skip(pageSize * (pageNum - 1))
            .limit(pageSize);
    
    // Process current page of documents
    for (Document doc : documents) {
        System.out.println(doc.toJson());
    }
    mongoClient.close();
}

public void good_case_5(HttpServletRequest request) throws IOException {
    // Elasticsearch - Proper pagination when searching documents
    String indexName = request.getParameter("index");
    int from = Integer.parseInt(request.getParameter("from"));
    int size = Integer.parseInt(request.getParameter("size"));
    
    RestHighLevelClient client = new RestHighLevelClient();
    SearchRequest searchRequest = new SearchRequest(indexName);
    SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
    searchSourceBuilder.from(from);
    searchSourceBuilder.size(size);
    searchRequest.source(searchSourceBuilder);
    
    // ok: java-missing-pagination
    SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
    
    // Process current page of search hits
    Arrays.stream(searchResponse.getHits().getHits()).forEach(hit -> {
        System.out.println(hit.getSourceAsString());
    });
    client.close();
}

public void good_case_6(HttpServletRequest request) {
    // AWS SDK v2 DynamoDB - Proper pagination when querying items
    String tableName = request.getParameter("table");
    String keyValue = request.getParameter("key");
    
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    QueryRequest queryRequest = QueryRequest.builder()
            .tableName(tableName)
            .keyConditionExpression("partitionKey = :pk")
            .expressionAttributeValues(Map.of(":pk", AttributeValue.builder().s(keyValue).build()))
            .limit(100)
            .build();
    
    Map<String, AttributeValue> lastEvaluatedKey = null;
    do {
        if (lastEvaluatedKey != null) {
            queryRequest = queryRequest.toBuilder()
                    .exclusiveStartKey(lastEvaluatedKey)
                    .build();
        }
        
        // ok: java-missing-pagination
        QueryResponse response = dynamoDbClient.query(queryRequest);
        
        // Process current page of items
        response.items().forEach(item -> {
            System.out.println(item);
        });
        
        lastEvaluatedKey = response.lastEvaluatedKey();
    } while (lastEvaluatedKey != null && !lastEvaluatedKey.isEmpty());
}

public void good_case_7(HttpServletRequest request) {
    // Azure Blob Storage - Proper pagination when listing blobs
    String containerName = request.getParameter("container");
    
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("your-connection-string")
            .buildClient();
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
    
    ListBlobsOptions options = new ListBlobsOptions().setMaxResultsPerPage(100);
    
    // ok: java-missing-pagination
    Iterator<BlobItem> blobsIterator = containerClient.listBlobs(options, null).iterator();
    
    // Process blobs page by page
    while (blobsIterator.hasNext()) {
        BlobItem blob = blobsIterator.next();
        System.out.println(blob.getName());
    }
}

public void good_case_8(HttpServletRequest request) {
    // Google Cloud Storage - Proper pagination when listing objects
    String bucketName = request.getParameter("bucket");
    
    Storage storage = StorageOptions.getDefaultInstance().getService();
    Bucket bucket = storage.get(bucketName);
    
    // ok: java-missing-pagination
    Page<Blob> blobs = bucket.list(Storage.BlobListOption.pageSize(100));
    
    // Process blobs page by page
    while (true) {
        for (Blob blob : blobs.getValues()) {
            System.out.println(blob.getName());
        }
        
        if (!blobs.hasNextPage()) {
            break;
        }
        
        blobs = blobs.getNextPage();
    }
}

public void good_case_9(HttpServletRequest request) {
    // Google Cloud Firestore - Proper pagination when querying documents
    String collectionName = request.getParameter("collection");
    
    Firestore firestore = FirestoreOptions.getDefaultInstance().getService();
    CollectionReference collection = firestore.collection(collectionName);
    
    // Set up query with pagination
    Query query = collection.limit(25);
    
    // ok: java-missing-pagination
    ApiFuture<QuerySnapshot> future = query.get();
    QuerySnapshot querySnapshot = future.get();
    
    // Process current page of documents
    querySnapshot.getDocuments().forEach(document -> {
        System.out.println(document.getData());
    });
    
    // Get the last document for pagination
    DocumentSnapshot lastDoc = querySnapshot.getDocuments().get(querySnapshot.size() - 1);
    
    // Get next page if needed
    if (querySnapshot.size() == 25) {
        Query nextQuery = collection.startAfter(lastDoc).limit(25);
        // Process next page...
    }
}

public void good_case_10(HttpServletRequest request) {
    // Docker Java API - Proper pagination when listing containers
    DockerClient dockerClient = DockerClientBuilder.getInstance().build();
    
    int limit = Integer.parseInt(request.getParameter("limit"));
    
    // ok: java-missing-pagination
    List<Container> containers = dockerClient.listContainersCmd()
            .withLimit(limit)
            .exec();
    
    // Process current page of containers
    containers.forEach(container -> {
        System.out.println(container.getId());
    });
    
    // For next page, use filters to get next set of results
    if (containers.size() == limit) {
        String lastContainerId = containers.get(containers.size() - 1).getId();
        // Get next page using lastContainerId as a filter...
    }
}

public void good_case_11(HttpServletRequest request) throws ApiException {
    // Kubernetes Java Client - Proper pagination when listing pods
    String namespace = request.getParameter("namespace");
    Integer limit = Integer.parseInt(request.getParameter("limit"));
    
    ApiClient client = Config.defaultClient();
    Configuration.setDefaultApiClient(client);
    CoreV1Api api = new CoreV1Api();
    
    String continueToken = null;
    do {
        // ok: java-missing-pagination
        V1PodList list = api.listNamespacedPod(
                namespace, null, null, continueToken, null, null, limit, null, null, null, null);
        
        // Process current page of pods
        list.getItems().forEach(pod -> {
            System.out.println(pod.getMetadata().getName());
        });
        
        continueToken = list.getMetadata().getContinue();
    } while (continueToken != null && !continueToken.isEmpty());
}

public void good_case_12(HttpServletRequest request) {
    // AWS EC2 - Proper pagination when describing instances
    Ec2Client ec2Client = Ec2Client.create();
    
    String nextToken = null;
    do {
        DescribeInstancesRequest describeInstancesRequest = DescribeInstancesRequest.builder()
                .maxResults(100)
                .nextToken(nextToken)
                .build();
        
        // ok: java-missing-pagination
        DescribeInstancesResponse response = ec2Client.describeInstances(describeInstancesRequest);
        
        // Process current page of instances
        response.reservations().forEach(reservation -> {
            reservation.instances().forEach(instance -> {
                System.out.println(instance.instanceId());
            });
        });
        
        nextToken = response.nextToken();
    } while (nextToken != null);
}

public void good_case_13(HttpServletRequest request) throws IOException {
    // OkHttp - Proper pagination when fetching paginated API results
    String apiUrl = request.getParameter("apiUrl");
    OkHttpClient client = new OkHttpClient();
    
    String nextPageUrl = apiUrl;
    while (nextPageUrl != null) {
        Request okRequest = new Request.Builder()
                .url(nextPageUrl)
                .build();
        
        // ok: java-missing-pagination
        Response response = client.newCall(okRequest).execute();
        String responseBody = response.body().string();
        
        // Process current page of results
        System.out.println(responseBody);
        
        // Extract next page URL from response headers or body
        nextPageUrl = response.header("Link");
        if (nextPageUrl != null && nextPageUrl.contains("rel=\"next\"")) {
            // Parse next page URL from Link header
            nextPageUrl = extractNextPageUrl(nextPageUrl);
        } else {
            nextPageUrl = null;
        }
    }
}

public void good_case_14(HttpServletRequest request) throws IOException {
    // Apache HttpClient - Proper pagination when fetching paginated API results
    String apiUrl = request.getParameter("apiUrl");
    
    CloseableHttpClient httpClient = HttpClients.createDefault();
    
    String nextPageUrl = apiUrl;
    while (nextPageUrl != null) {
        HttpGet httpGet = new HttpGet(nextPageUrl);
        
        // ok: java-missing-pagination
        CloseableHttpResponse response = httpClient.execute(httpGet);
        String responseBody = EntityUtils.toString(response.getEntity());
        
        // Process current page of results
        System.out.println(responseBody);
        
        // Extract next page URL from response headers or body
        org.apache.http.Header linkHeader = response.getFirstHeader("Link");
        if (linkHeader != null && linkHeader.getValue().contains("rel=\"next\"")) {
            // Parse next page URL from Link header
            nextPageUrl = extractNextPageUrl(linkHeader.getValue());
        } else {
            nextPageUrl = null;
        }
    }
    httpClient.close();
}

public void good_case_15(HttpServletRequest request) {
    // Retrofit - Proper pagination when fetching paginated API results
    String query = request.getParameter("query");
    int page = 1;
    
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    
    SearchApi searchApi = retrofit.create(SearchApi.class);
    
    boolean hasMorePages = true;
    while (hasMorePages) {
        // ok: java-missing-pagination
        Call<SearchResult> call = searchApi.searchWithPagination(query, page, 50);
        SearchResult result = call.execute().body();
        
        // Process current page of results
        result.getItems().forEach(item -> {
            System.out.println(item.getName());
        });
        
        // Check if there are more pages
        hasMorePages = result.hasNextPage();
        page++;
    }
}

// Helper interfaces and methods

interface SearchApi {
    @GET("search")
    Call<SearchResult> search(@Query("q") String query);
    
    @GET("search")
    Call<SearchResult> searchWithPagination(@Query("q") String query, @Query("page") int page, @Query("per_page") int perPage);
}

class SearchResult {
    private List<SearchItem> items;
    private boolean hasNextPage;
    
    public List<SearchItem> getItems() {
        return items;
    }
    
    public boolean hasNextPage() {
        return hasNextPage;
    }
}

class SearchItem {
    private String name;
    
    public String getName() {
        return name;
    }
}

private String extractNextPageUrl(String linkHeader) {
    // Extract next page URL from Link header
    // This is a simplified implementation
    if (linkHeader.contains("<") && linkHeader.contains(">")) {
        int start = linkHeader.indexOf("<") + 1;
        int end = linkHeader.indexOf(">");
        return linkHeader.substring(start, end);
    }
    return null;
}