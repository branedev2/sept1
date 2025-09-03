import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ListObjectsV2Request;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListObjectsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsResponse;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobItem;
import com.azure.storage.blob.models.ListBlobsOptions;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.Blob;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.QuerySnapshot;
import com.google.firebase.cloud.FirestoreClient;

public class MissingPaginationExamples {

    // True Positives (Vulnerable Code)

    public void bad_case_1() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/users"))
                .GET()
                .build();
        
        try {
            // ruleid: java-missing-pagination
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("All users: " + response.body());
            // No pagination handling, potentially missing data beyond the first page
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        
        // ruleid: java-missing-pagination
        ListObjectsV2Result result = s3Client.listObjectsV2(bucketName);
        List<S3ObjectSummary> objects = result.getObjectSummaries();
        
        for (S3ObjectSummary os : objects) {
            System.out.println("Object: " + os.getKey());
        }
        // Missing pagination handling with continuation token
    }

    public void bad_case_3() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        String tableName = "users";
        
        ScanRequest scanRequest = ScanRequest.builder()
                .tableName(tableName)
                .build();
        
        // ruleid: java-missing-pagination
        ScanResponse response = dynamoDbClient.scan(scanRequest);
        System.out.println("Found " + response.items().size() + " items");
        // Not handling pagination with LastEvaluatedKey
    }

    public void bad_case_4() throws Exception {
        Drive driveService = new Drive.Builder(
                GoogleNetHttpTransport.newTrustedTransport(),
                JacksonFactory.getDefaultInstance(),
                null)
                .setApplicationName("Drive API Example")
                .build();
        
        // ruleid: java-missing-pagination
        FileList result = driveService.files().list().execute();
        List<File> files = result.getFiles();
        
        for (File file : files) {
            System.out.println("File: " + file.getName());
        }
        // Not handling nextPageToken
    }

    public void bad_case_5(MongoTemplate mongoTemplate) {
        Query query = new Query();
        
        // ruleid: java-missing-pagination
        List<Map> results = mongoTemplate.find(query, Map.class, "users");
        
        for (Map user : results) {
            System.out.println("User: " + user.get("name"));
        }
        // Not using pagination with Spring Data MongoDB
    }

    public void bad_case_6() {
        S3Client s3Client = S3Client.create();
        String bucketName = "my-bucket";
        
        ListObjectsRequest listObjectsRequest = ListObjectsRequest.builder()
                .bucket(bucketName)
                .build();
        
        // ruleid: java-missing-pagination
        ListObjectsResponse response = s3Client.listObjects(listObjectsRequest);
        
        response.contents().forEach(object -> {
            System.out.println("Object: " + object.key());
        });
        // Not handling pagination with marker
    }

    public void bad_case_7() {
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container-name");
        
        // ruleid: java-missing-pagination
        for (BlobItem blobItem : containerClient.listBlobs()) {
            System.out.println("Blob name: " + blobItem.getName());
        }
        // Not handling pagination with continuation token
    }

    public void bad_case_8(RestHighLevelClient client) throws IOException {
        SearchRequest searchRequest = new SearchRequest("users");
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchRequest.source(searchSourceBuilder);
        
        // ruleid: java-missing-pagination
        SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
        SearchHit[] hits = searchResponse.getHits().getHits();
        
        for (SearchHit hit : hits) {
            System.out.println("User: " + hit.getSourceAsString());
        }
        // Not using scroll API or search_after for pagination
    }

    public void bad_case_9() {
        Storage storage = StorageOptions.getDefaultInstance().getService();
        Bucket bucket = storage.get("my-bucket");
        
        // ruleid: java-missing-pagination
        for (Blob blob : bucket.list().iterateAll()) {
            System.out.println("Blob: " + blob.getName());
        }
        // Using iterateAll() which loads all results without pagination control
    }

    public void bad_case_10() throws Exception {
        Firestore db = FirestoreClient.getFirestore();
        
        // ruleid: java-missing-pagination
        QuerySnapshot querySnapshot = db.collection("users").get().get();
        
        for (QueryDocumentSnapshot document : querySnapshot.getDocuments()) {
            System.out.println("User: " + document.getData());
        }
        // Not using pagination with limit and startAfter
    }

    public void bad_case_11() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.github.com/repos/octocat/hello-world/issues"))
                .header("Accept", "application/vnd.github.v3+json")
                .GET()
                .build();
        
        try {
            // ruleid: java-missing-pagination
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Issues: " + response.body());
            // Not handling GitHub API pagination with Link headers
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.twitter.com/2/users/12345/tweets"))
                .header("Authorization", "Bearer TOKEN")
                .GET()
                .build();
        
        try {
            // ruleid: java-missing-pagination
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Tweets: " + response.body());
            // Not handling Twitter API pagination with next_token
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://graph.facebook.com/v12.0/me/posts"))
                .header("Authorization", "Bearer TOKEN")
                .GET()
                .build();
        
        try {
            // ruleid: java-missing-pagination
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Posts: " + response.body());
            // Not handling Facebook Graph API pagination with paging cursors
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.stripe.com/v1/customers"))
                .header("Authorization", "Bearer sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY")
                .GET()
                .build();
        
        try {
            // ruleid: java-missing-pagination
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Customers: " + response.body());
            // Not handling Stripe API pagination with has_more and starting_after
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/products?category=electronics"))
                .GET()
                .build();
        
        try {
            // ruleid: java-missing-pagination
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Products: " + response.body());
            // Not handling pagination for potentially large result set
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        HttpClient client = HttpClient.newHttpClient();
        int page = 1;
        int pageSize = 100;
        boolean hasMorePages = true;
        List<String> allUsers = new ArrayList<>();
        
        try {
            while (hasMorePages) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api.example.com/users?page=" + page + "&pageSize=" + pageSize))
                        .GET()
                        .build();
                
                // ok: java-missing-pagination
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String responseBody = response.body();
                allUsers.add(responseBody);
                
                // Check if there are more pages (simplified example)
                if (responseBody.contains("\"hasNextPage\": false") || responseBody.equals("[]")) {
                    hasMorePages = false;
                } else {
                    page++;
                }
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        List<S3ObjectSummary> allObjects = new ArrayList<>();
        
        ListObjectsV2Request request = new ListObjectsV2Request()
                .withBucketName(bucketName)
                .withMaxKeys(1000);
        
        ListObjectsV2Result result;
        do {
            // ok: java-missing-pagination
            result = s3Client.listObjectsV2(request);
            allObjects.addAll(result.getObjectSummaries());
            String token = result.getNextContinuationToken();
            request.setContinuationToken(token);
        } while (result.isTruncated());
        
        for (S3ObjectSummary os : allObjects) {
            System.out.println("Object: " + os.getKey());
        }
    }

    public void good_case_3() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        String tableName = "users";
        List<Map<String, Object>> allItems = new ArrayList<>();
        
        ScanRequest scanRequest = ScanRequest.builder()
                .tableName(tableName)
                .limit(100)
                .build();
        
        Map<String, Object> lastEvaluatedKey = null;
        do {
            if (lastEvaluatedKey != null) {
                scanRequest = scanRequest.toBuilder()
                        .exclusiveStartKey(lastEvaluatedKey)
                        .build();
            }
            
            // ok: java-missing-pagination
            ScanResponse response = dynamoDbClient.scan(scanRequest);
            allItems.addAll(response.items());
            lastEvaluatedKey = response.lastEvaluatedKey();
        } while (lastEvaluatedKey != null && !lastEvaluatedKey.isEmpty());
        
        System.out.println("Found " + allItems.size() + " items");
    }

    public void good_case_4() throws Exception {
        Drive driveService = new Drive.Builder(
                GoogleNetHttpTransport.newTrustedTransport(),
                JacksonFactory.getDefaultInstance(),
                null)
                .setApplicationName("Drive API Example")
                .build();
        
        List<File> allFiles = new ArrayList<>();
        String pageToken = null;
        
        do {
            Drive.Files.List request = driveService.files().list()
                    .setPageSize(100);
            
            if (pageToken != null) {
                request.setPageToken(pageToken);
            }
            
            // ok: java-missing-pagination
            FileList result = request.execute();
            allFiles.addAll(result.getFiles());
            pageToken = result.getNextPageToken();
        } while (pageToken != null);
        
        for (File file : allFiles) {
            System.out.println("File: " + file.getName());
        }
    }

    public void good_case_5(MongoTemplate mongoTemplate) {
        int pageSize = 50;
        int pageNumber = 0;
        List<Map> allUsers = new ArrayList<>();
        Page<Map> page;
        
        do {
            Pageable pageable = PageRequest.of(pageNumber, pageSize);
            Query query = new Query().with(pageable);
            
            // ok: java-missing-pagination
            page = mongoTemplate.findAll(Map.class, "users", pageable);
            allUsers.addAll(page.getContent());
            pageNumber++;
        } while (page.hasNext());
        
        for (Map user : allUsers) {
            System.out.println("User: " + user.get("name"));
        }
    }

    public void good_case_6() {
        S3Client s3Client = S3Client.create();
        String bucketName = "my-bucket";
        List<software.amazon.awssdk.services.s3.model.S3Object> allObjects = new ArrayList<>();
        
        String nextMarker = null;
        do {
            ListObjectsRequest.Builder requestBuilder = ListObjectsRequest.builder()
                    .bucket(bucketName)
                    .maxKeys(1000);
            
            if (nextMarker != null) {
                requestBuilder.marker(nextMarker);
            }
            
            // ok: java-missing-pagination
            ListObjectsResponse response = s3Client.listObjects(requestBuilder.build());
            allObjects.addAll(response.contents());
            
            if (response.isTruncated()) {
                nextMarker = response.contents().get(response.contents().size() - 1).key();
            } else {
                nextMarker = null;
            }
        } while (nextMarker != null);
        
        allObjects.forEach(object -> {
            System.out.println("Object: " + object.key());
        });
    }

    public void good_case_7() {
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container-name");
        List<BlobItem> allBlobs = new ArrayList<>();
        
        ListBlobsOptions options = new ListBlobsOptions().setMaxResultsPerPage(100);
        String continuationToken = null;
        
        do {
            // ok: java-missing-pagination
            containerClient.listBlobs(options, null).forEach(blobItem -> {
                allBlobs.add(blobItem);
                System.out.println("Blob name: " + blobItem.getName());
            });
            
            // Get continuation token for next page (simplified)
            continuationToken = null; // In real code, get from response
        } while (continuationToken != null);
    }

    public void good_case_8(RestHighLevelClient client) throws IOException {
        SearchRequest searchRequest = new SearchRequest("users");
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.size(100);
        searchRequest.source(searchSourceBuilder);
        
        List<String> allUsers = new ArrayList<>();
        int from = 0;
        boolean hasMore = true;
        
        while (hasMore) {
            searchSourceBuilder.from(from);
            
            // ok: java-missing-pagination
            SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
            SearchHit[] hits = searchResponse.getHits().getHits();
            
            if (hits.length == 0) {
                hasMore = false;
            } else {
                for (SearchHit hit : hits) {
                    allUsers.add(hit.getSourceAsString());
                }
                from += hits.length;
            }
        }
        
        System.out.println("Total users: " + allUsers.size());
    }

    public void good_case_9() {
        Storage storage = StorageOptions.getDefaultInstance().getService();
        Bucket bucket = storage.get("my-bucket");
        List<Blob> allBlobs = new ArrayList<>();
        
        // ok: java-missing-pagination
        for (Blob blob : bucket.list(Storage.BlobListOption.pageSize(100)).iterateAll()) {
            allBlobs.add(blob);
            System.out.println("Blob: " + blob.getName());
        }
    }

    public void good_case_10() throws Exception {
        Firestore db = FirestoreClient.getFirestore();
        List<Map<String, Object>> allUsers = new ArrayList<>();
        
        // Initial query with limit
        com.google.cloud.firestore.Query query = db.collection("users").limit(25);
        QueryDocumentSnapshot lastDoc = null;
        
        while (true) {
            // Apply pagination using startAfter if we have a last document
            if (lastDoc != null) {
                query = query.startAfter(lastDoc);
            }
            
            // ok: java-missing-pagination
            QuerySnapshot querySnapshot = query.get().get();
            List<QueryDocumentSnapshot> documents = querySnapshot.getDocuments();
            
            if (documents.isEmpty()) {
                break;
            }
            
            for (QueryDocumentSnapshot document : documents) {
                allUsers.add(document.getData());
            }
            
            // Update the last document for next iteration
            lastDoc = documents.get(documents.size() - 1);
        }
        
        System.out.println("Total users: " + allUsers.size());
    }

    public void good_case_11() {
        HttpClient client = HttpClient.newHttpClient();
        List<String> allIssues = new ArrayList<>();
        String nextPageUrl = "https://api.github.com/repos/octocat/hello-world/issues";
        
        try {
            while (nextPageUrl != null) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(nextPageUrl))
                        .header("Accept", "application/vnd.github.v3+json")
                        .GET()
                        .build();
                
                // ok: java-missing-pagination
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                allIssues.add(response.body());
                
                // Extract next page URL from Link header
                String linkHeader = response.headers().firstValue("Link").orElse("");
                nextPageUrl = extractNextPageUrl(linkHeader);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    private String extractNextPageUrl(String linkHeader) {
        // Simplified implementation to extract next page URL from GitHub API Link header
        if (linkHeader.contains("rel=\"next\"")) {
            int startIndex = linkHeader.indexOf('<') + 1;
            int endIndex = linkHeader.indexOf('>');
            return linkHeader.substring(startIndex, endIndex);
        }
        return null;
    }

    public void good_case_12() {
        HttpClient client = HttpClient.newHttpClient();
        List<String> allTweets = new ArrayList<>();
        String nextToken = null;
        
        try {
            do {
                String url = "https://api.twitter.com/2/users/12345/tweets?max_results=100";
                if (nextToken != null) {
                    url += "&pagination_token=" + nextToken;
                }
                
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Authorization", "Bearer TOKEN")
                        .GET()
                        .build();
                
                // ok: java-missing-pagination
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String responseBody = response.body();
                allTweets.add(responseBody);
                
                // Extract next_token (simplified)
                nextToken = responseBody.contains("\"next_token\":") ? "next_token_value" : null;
            } while (nextToken != null);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        HttpClient client = HttpClient.newHttpClient();
        List<String> allPosts = new ArrayList<>();
        String nextPageUrl = "https://graph.facebook.com/v12.0/me/posts?limit=25";
        
        try {
            while (nextPageUrl != null) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(nextPageUrl))
                        .header("Authorization", "Bearer TOKEN")
                        .GET()
                        .build();
                
                // ok: java-missing-pagination
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String responseBody = response.body();
                allPosts.add(responseBody);
                
                // Extract next page URL (simplified)
                nextPageUrl = responseBody.contains("\"paging\":{\"next\":") ? 
                        "https://graph.facebook.com/v12.0/me/posts?limit=25&after=cursor_value" : null;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    public void good_case_14() {
        HttpClient client = HttpClient.newHttpClient();
        List<String> allCustomers = new ArrayList<>();
        String startingAfter = null;
        boolean hasMore = true;
        
        try {
            while (hasMore) {
                String url = "https://api.stripe.com/v1/customers?limit=100";
                if (startingAfter != null) {
                    url += "&starting_after=" + startingAfter;
                }
                
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Authorization", "Bearer sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY")
                        .GET()
                        .build();
                
                // ok: java-missing-pagination
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String responseBody = response.body();
                allCustomers.add(responseBody);
                
                // Check if there are more results and get last ID (simplified)
                hasMore = responseBody.contains("\"has_more\":true");
                if (hasMore) {
                    startingAfter = "last_customer_id"; // In real code, extract from response
                }
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        HttpClient client = HttpClient.newHttpClient();
        List<String> allProducts = new ArrayList<>();
        int page = 1;
        int pageSize = 50;
        boolean hasMoreData = true;
        
        try {
            while (hasMoreData) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api.example.com/products?category=electronics&page=" + page + "&pageSize=" + pageSize))
                        .GET()
                        .build();
                
                // ok: java-missing-pagination
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String responseBody = response.body();
                allProducts.add(responseBody);
                
                // Check if we've reached the end (simplified)
                if (responseBody.equals("[]") || responseBody.contains("\"isLastPage\":true")) {
                    hasMoreData = false;
                } else {
                    page++;
                }
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}