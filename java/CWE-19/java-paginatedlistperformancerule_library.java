import java.util.*;
import java.sql.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.*;
import com.google.cloud.firestore.*;
import com.mongodb.client.*;
import com.mongodb.client.model.Filters;
import org.hibernate.Session;
import org.hibernate.query.Query;
import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.servlet.http.HttpServletRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import retrofit2.http.Query;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import com.azure.cosmos.CosmosClient;
import com.azure.cosmos.CosmosContainer;
import com.azure.cosmos.models.CosmosQueryRequestOptions;
import com.azure.cosmos.util.CosmosPagedIterable;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.ScanParams;
import redis.clients.jedis.ScanResult;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Record;
import org.neo4j.driver.Result;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.bigquery.Bigquery;
import com.google.api.services.bigquery.model.QueryRequest;
import com.google.api.services.bigquery.model.QueryResponse;
import org.apache.cassandra.thrift.Cassandra;
import org.apache.cassandra.thrift.Column;
import org.apache.cassandra.thrift.ColumnParent;
import org.apache.cassandra.thrift.ConsistencyLevel;
import org.apache.cassandra.thrift.SlicePredicate;
import org.apache.cassandra.thrift.SliceRange;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.util.Bytes;

// Security Issue: Incomplete data retrieval due to pagination can lead to inaccurate analysis and decision-making based on partial information

public class PaginatedListPerformanceRuleTest {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Spring Data JPA - Retrieving only first page without processing all data
        String searchTerm = request.getParameter("search");
        JpaRepository<User, Long> userRepository = null; // Assume this is initialized
        int pageSize = 10;
        
        // ruleid: java-paginatedlistperformancerule
        Page<User> firstPage = userRepository.findByNameContaining(searchTerm, PageRequest.of(0, pageSize));
        
        // Only analyzing first page data for security decisions
        boolean hasAdminAccess = firstPage.getContent().stream()
                .anyMatch(user -> user.getRole().equals("ADMIN"));
        
        // Security decision based on incomplete data
        if (hasAdminAccess) {
            grantAdminAccess();
        }
    }
    
    public void bad_case_2(HttpServletRequest request) {
        // JDBC direct pagination - Only retrieving first page
        String userId = request.getParameter("userId");
        JdbcTemplate jdbcTemplate = null; // Assume this is initialized
        int pageSize = 20;
        
        // ruleid: java-paginatedlistperformancerule
        List<Map<String, Object>> firstPageLogs = jdbcTemplate.queryForList(
            "SELECT * FROM security_logs WHERE user_id = ? LIMIT ?", 
            userId, pageSize);
        
        // Security audit based on incomplete logs
        boolean hasSuspiciousActivity = firstPageLogs.stream()
            .anyMatch(log -> "SUSPICIOUS".equals(log.get("activity_type")));
        
        if (!hasSuspiciousActivity) {
            markAccountAsVerified(userId);
        }
    }
    
    public void bad_case_3(HttpServletRequest request) {
        // MongoDB pagination - Only checking first batch
        String companyId = request.getParameter("companyId");
        MongoCollection<Document> collection = null; // Assume this is initialized
        
        // ruleid: java-paginatedlistperformancerule
        FindIterable<Document> firstBatch = collection.find(Filters.eq("companyId", companyId))
                                                     .limit(50);
        
        // Compliance check based on incomplete data
        boolean isCompliant = true;
        for (Document doc : firstBatch) {
            if (!doc.getBoolean("compliant", true)) {
                isCompliant = false;
                break;
            }
        }
        
        if (isCompliant) {
            issueComplianceCertificate(companyId);
        }
    }
    
    public void bad_case_4(HttpServletRequest request) {
        // DynamoDB pagination - Only processing first page
        String productCategory = request.getParameter("category");
        AmazonDynamoDB dynamoDB = null; // Assume this is initialized
        
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":category", new AttributeValue().withS(productCategory));
        
        QueryRequest queryRequest = new QueryRequest()
            .withTableName("Products")
            .withKeyConditionExpression("category = :category")
            .withExpressionAttributeValues(expressionAttributeValues)
            .withLimit(25);
        
        // ruleid: java-paginatedlistperformancerule
        QueryResult result = dynamoDB.query(queryRequest);
        
        // Product safety analysis based on incomplete data
        boolean allProductsSafe = result.getItems().stream()
            .allMatch(item -> "SAFE".equals(item.get("safetyRating").getS()));
        
        if (allProductsSafe) {
            approveProductCategory(productCategory);
        }
    }
    
    public void bad_case_5(HttpServletRequest request) {
        // Hibernate Query - Only retrieving first page
        String departmentId = request.getParameter("departmentId");
        Session session = null; // Assume this is initialized
        
        // ruleid: java-paginatedlistperformancerule
        Query<Employee> query = session.createQuery("FROM Employee WHERE departmentId = :deptId", Employee.class)
                                      .setParameter("deptId", departmentId)
                                      .setMaxResults(30);
        
        List<Employee> employees = query.list();
        
        // Security clearance check based on incomplete employee list
        boolean allEmployeesCleared = employees.stream()
            .allMatch(employee -> employee.getSecurityClearance() >= 3);
        
        if (allEmployeesCleared) {
            grantDepartmentAccess(departmentId);
        }
    }
    
    public void bad_case_6(HttpServletRequest request) {
        // Elasticsearch - Only retrieving first page of search results
        String securityThreat = request.getParameter("threat");
        RestHighLevelClient client = null; // Assume this is initialized
        
        SearchRequest searchRequest = new SearchRequest("security_incidents");
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchQuery("threat_type", securityThreat));
        searchSourceBuilder.size(100); // Only get first 100 results
        searchRequest.source(searchSourceBuilder);
        
        try {
            // ruleid: java-paginatedlistperformancerule
            SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
            
            // Threat assessment based on incomplete data
            boolean threatContained = Arrays.stream(searchResponse.getHits().getHits())
                .allMatch(hit -> "CONTAINED".equals(hit.getSourceAsMap().get("status")));
                
            if (threatContained) {
                downgradeSecurityAlert(securityThreat);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7(HttpServletRequest request) {
        // Azure Cosmos DB - Only retrieving first page
        String tenantId = request.getParameter("tenantId");
        CosmosContainer container = null; // Assume this is initialized
        
        // ruleid: java-paginatedlistperformancerule
        CosmosPagedIterable<Document> pagedResponse = container.queryItems(
            "SELECT * FROM c WHERE c.tenantId = '" + tenantId + "'", 
            new CosmosQueryRequestOptions(), 
            Document.class);
        
        List<Document> firstPageItems = new ArrayList<>();
        pagedResponse.iterator().forEachRemaining(item -> {
            firstPageItems.add(item);
            if (firstPageItems.size() >= 50) return; // Only process first 50
        });
        
        // Access control decision based on incomplete tenant data
        boolean hasViolations = firstPageItems.stream()
            .anyMatch(doc -> doc.getBoolean("hasComplianceViolation"));
            
        if (!hasViolations) {
            grantTenantAccess(tenantId);
        }
    }
    
    public void bad_case_8(HttpServletRequest request) {
        // AWS S3 - Only retrieving first page of objects
        String bucketName = request.getParameter("bucket");
        S3Client s3Client = null; // Assume this is initialized
        
        // ruleid: java-paginatedlistperformancerule
        ListObjectsV2Response response = s3Client.listObjectsV2(
            ListObjectsV2Request.builder()
                .bucket(bucketName)
                .maxKeys(1000)
                .build());
        
        // Security scan based on incomplete object list
        boolean allObjectsScanned = response.contents().stream()
            .allMatch(obj -> scanObject(obj.key()));
            
        if (allObjectsScanned) {
            markBucketAsSecure(bucketName);
        }
    }
    
    public void bad_case_9(HttpServletRequest request) {
        // Redis Scan - Only processing first batch
        String pattern = request.getParameter("keyPattern");
        Jedis jedis = null; // Assume this is initialized
        
        // ruleid: java-paginatedlistperformancerule
        ScanResult<String> scanResult = jedis.scan("0", new ScanParams().match(pattern).count(100));
        
        // Security check based on incomplete key scan
        boolean allKeysValid = scanResult.getResult().stream()
            .allMatch(key -> validateKey(key));
            
        if (allKeysValid) {
            approveKeyPattern(pattern);
        }
    }
    
    public void bad_case_10(HttpServletRequest request) {
        // Neo4j - Only retrieving first page of results
        String userId = request.getParameter("userId");
        Driver driver = null; // Assume this is initialized
        
        try (org.neo4j.driver.Session session = driver.session(SessionConfig.forDatabase("neo4j"))) {
            // ruleid: java-paginatedlistperformancerule
            Result result = session.run(
                "MATCH (u:User {id: $userId})-[:HAS_AC_REDACTED_TWILIO_ID]->(r:Resource) RETURN r.name LIMIT 50",
                Map.of("userId", userId)
            );
            
            List<String> accessibleResources = new ArrayList<>();
            while (result.hasNext()) {
                Record record = result.next();
                accessibleResources.add(record.get("r.name").asString());
            }
            
            // Access control based on incomplete resource list
            if (!accessibleResources.contains("sensitive_data")) {
                grantDataAccess(userId);
            }
        }
    }
    
    public void bad_case_11(HttpServletRequest request) {
        // Google BigQuery - Only retrieving limited rows
        String projectId = request.getParameter("projectId");
        Bigquery bigquery = null; // Assume this is initialized
        
        try {
            QueryRequest queryRequest = new QueryRequest()
                .setQuery("SELECT * FROM `security_events` WHERE project_id = '" + projectId + "' LIMIT 1000");
                
            // ruleid: java-paginatedlistperformancerule
            QueryResponse response = bigquery.jobs().query(projectId, queryRequest).execute();
            
            // Security audit based on incomplete event data
            boolean hasSecurityViolations = response.getRows().stream()
                .anyMatch(row -> "VIOLATION".equals(row.getF().get(2).getV()));
                
            if (!hasSecurityViolations) {
                approveProjectDeployment(projectId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12(HttpServletRequest request) {
        // Apache Cassandra - Only retrieving limited columns
        String userId = request.getParameter("userId");
        Cassandra.Client client = null; // Assume this is initialized
        
        try {
            ColumnParent parent = new ColumnParent("user_activities");
            SlicePredicate predicate = new SlicePredicate();
            SliceRange sliceRange = new SliceRange();
            sliceRange.setStart(new byte[0]);
            sliceRange.setFinish(new byte[0]);
            sliceRange.setCount(100); // Only get 100 columns
            predicate.setSlice_range(sliceRange);
            
            // ruleid: java-paginatedlistperformancerule
            List<Column> columns = client.get_slice(
                userId.getBytes(), 
                parent, 
                predicate, 
                ConsistencyLevel.ONE
            );
            
            // User activity analysis based on incomplete data
            boolean hasAnomalousActivity = columns.stream()
                .anyMatch(col -> "ANOMALOUS".equals(new String(col.getValue())));
                
            if (!hasAnomalousActivity) {
                clearUserSuspicion(userId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13(HttpServletRequest request) {
        // HBase - Only scanning limited rows
        String rowPrefix = request.getParameter("rowPrefix");
        Table table = null; // Assume this is initialized
        
        try {
            Scan scan = new Scan();
            scan.setRowPrefixFilter(Bytes.toBytes(rowPrefix));
            scan.setCaching(50); // Small cache size
            scan.setLimit(100); // Limited results
            
            // ruleid: java-paginatedlistperformancerule
            ResultScanner scanner = table.getScanner(scan);
            
            List<org.apache.hadoop.hbase.client.Result> results = new ArrayList<>();
            for (org.apache.hadoop.hbase.client.Result result : scanner) {
                results.add(result);
            }
            
            // Security analysis based on incomplete data
            boolean allRowsSecure = results.stream()
                .allMatch(result -> isSecureRow(result));
                
            if (allRowsSecure) {
                approveDataAccess(rowPrefix);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14(HttpServletRequest request) {
        // Firestore - Only retrieving first batch
        String organizationId = request.getParameter("orgId");
        Firestore firestore = null; // Assume this is initialized
        
        // ruleid: java-paginatedlistperformancerule
        ApiFuture<QuerySnapshot> future = firestore.collection("users")
            .whereEqualTo("organizationId", organizationId)
            .limit(50)
            .get();
            
        try {
            List<QueryDocumentSnapshot> documents = future.get().getDocuments();
            
            // Access control based on incomplete user list
            boolean allUsersVerified = documents.stream()
                .allMatch(doc -> doc.getBoolean("isVerified"));
                
            if (allUsersVerified) {
                grantOrganizationAccess(organizationId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15(HttpServletRequest request) {
        // Custom API client with Retrofit - Only retrieving first page
        String apiKey = request.getParameter("apiKey");
        String query = request.getParameter("query");
        
        Retrofit retrofit = null; // Assume this is initialized
        SecurityApiService service = retrofit.create(SecurityApiService.class);
        
        try {
            // ruleid: java-paginatedlistperformancerule
            Call<SecurityEventsResponse> call = service.getSecurityEvents(apiKey, query, 1, 100);
            SecurityEventsResponse response = call.execute().body();
            
            // Security analysis based on incomplete events
            boolean hasHighSeverityEvents = response.getEvents().stream()
                .anyMatch(event -> event.getSeverity() >= 8);
                
            if (!hasHighSeverityEvents) {
                approveSystemAccess(query);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1(HttpServletRequest request) {
        // Spring Data JPA - Processing all pages
        String searchTerm = request.getParameter("search");
        JpaRepository<User, Long> userRepository = null; // Assume this is initialized
        int pageSize = 10;
        
        // ok: java-paginatedlistperformancerule
        List<User> allUsers = new ArrayList<>();
        Pageable pageable = PageRequest.of(0, pageSize);
        Page<User> page;
        
        do {
            page = userRepository.findByNameContaining(searchTerm, pageable);
            allUsers.addAll(page.getContent());
            pageable = page.nextPageable();
        } while (page.hasNext());
        
        // Security decision based on complete data
        boolean hasAdminAccess = allUsers.stream()
                .anyMatch(user -> user.getRole().equals("ADMIN"));
        
        if (hasAdminAccess) {
            grantAdminAccess();
        }
    }
    
    public void good_case_2(HttpServletRequest request) {
        // JDBC direct pagination - Processing all pages
        String userId = request.getParameter("userId");
        JdbcTemplate jdbcTemplate = null; // Assume this is initialized
        int pageSize = 20;
        
        // ok: java-paginatedlistperformancerule
        List<Map<String, Object>> allLogs = new ArrayList<>();
        int offset = 0;
        List<Map<String, Object>> page;
        
        do {
            page = jdbcTemplate.queryForList(
                "SELECT * FROM security_logs WHERE user_id = ? LIMIT ? OFFSET ?", 
                userId, pageSize, offset);
            
            allLogs.addAll(page);
            offset += pageSize;
        } while (!page.isEmpty() && page.size() == pageSize);
        
        // Security audit based on complete logs
        boolean hasSuspiciousActivity = allLogs.stream()
            .anyMatch(log -> "SUSPICIOUS".equals(log.get("activity_type")));
        
        if (!hasSuspiciousActivity) {
            markAccountAsVerified(userId);
        }
    }
    
    public void good_case_3(HttpServletRequest request) {
        // MongoDB pagination - Processing all documents
        String companyId = request.getParameter("companyId");
        MongoCollection<Document> collection = null; // Assume this is initialized
        
        // ok: java-paginatedlistperformancerule
        List<Document> allDocuments = new ArrayList<>();
        FindIterable<Document> iterable = collection.find(Filters.eq("companyId", companyId));
        
        for (Document doc : iterable) {
            allDocuments.add(doc);
        }
        
        // Compliance check based on complete data
        boolean isCompliant = allDocuments.stream()
            .allMatch(doc -> doc.getBoolean("compliant", false));
        
        if (isCompliant) {
            issueComplianceCertificate(companyId);
        }
    }
    
    public void good_case_4(HttpServletRequest request) {
        // DynamoDB pagination - Processing all pages
        String productCategory = request.getParameter("category");
        AmazonDynamoDB dynamoDB = null; // Assume this is initialized
        
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":category", new AttributeValue().withS(productCategory));
        
        QueryRequest queryRequest = new QueryRequest()
            .withTableName("Products")
            .withKeyConditionExpression("category = :category")
            .withExpressionAttributeValues(expressionAttributeValues)
            .withLimit(25);
        
        // ok: java-paginatedlistperformancerule
        List<Map<String, AttributeValue>> allItems = new ArrayList<>();
        QueryResult result;
        
        do {
            result = dynamoDB.query(queryRequest);
            allItems.addAll(result.getItems());
            queryRequest.setExclusiveStartKey(result.getLastEvaluatedKey());
        } while (result.getLastEvaluatedKey() != null);
        
        // Product safety analysis based on complete data
        boolean allProductsSafe = allItems.stream()
            .allMatch(item -> "SAFE".equals(item.get("safetyRating").getS()));
        
        if (allProductsSafe) {
            approveProductCategory(productCategory);
        }
    }
    
    public void good_case_5(HttpServletRequest request) {
        // Hibernate Query - Processing all results
        String departmentId = request.getParameter("departmentId");
        Session session = null; // Assume this is initialized
        
        // ok: java-paginatedlistperformancerule
        List<Employee> allEmployees = session.createQuery(
            "FROM Employee WHERE departmentId = :deptId", Employee.class)
            .setParameter("deptId", departmentId)
            .list();
        
        // Security clearance check based on complete employee list
        boolean allEmployeesCleared = allEmployees.stream()
            .allMatch(employee -> employee.getSecurityClearance() >= 3);
        
        if (allEmployeesCleared) {
            grantDepartmentAccess(departmentId);
        }
    }
    
    public void good_case_6(HttpServletRequest request) {
        // Elasticsearch - Processing all search results with scroll API
        String securityThreat = request.getParameter("threat");
        RestHighLevelClient client = null; // Assume this is initialized
        
        try {
            // ok: java-paginatedlistperformancerule
            List<Map<String, Object>> allResults = new ArrayList<>();
            
            SearchRequest searchRequest = new SearchRequest("security_incidents");
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchQuery("threat_type", securityThreat));
            searchSourceBuilder.size(100);
            searchRequest.source(searchSourceBuilder);
            searchRequest.scroll(org.elasticsearch.common.unit.TimeValue.timeValueMinutes(1L));
            
            SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
            String scrollId = searchResponse.getScrollId();
            
            while (searchResponse.getHits().getHits().length > 0) {
                for (org.elasticsearch.search.SearchHit hit : searchResponse.getHits().getHits()) {
                    allResults.add(hit.getSourceAsMap());
                }
                
                org.elasticsearch.action.search.SearchScrollRequest scrollRequest = 
                    new org.elasticsearch.action.search.SearchScrollRequest(scrollId);
                scrollRequest.scroll(org.elasticsearch.common.unit.TimeValue.timeValueMinutes(1L));
                searchResponse = client.scroll(scrollRequest, RequestOptions.DEFAULT);
                scrollId = searchResponse.getScrollId();
            }
            
            // Threat assessment based on complete data
            boolean threatContained = allResults.stream()
                .allMatch(result -> "CONTAINED".equals(result.get("status")));
                
            if (threatContained) {
                downgradeSecurityAlert(securityThreat);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7(HttpServletRequest request) {
        // Azure Cosmos DB - Processing all pages
        String tenantId = request.getParameter("tenantId");
        CosmosContainer container = null; // Assume this is initialized
        
        // ok: java-paginatedlistperformancerule
        List<Document> allItems = new ArrayList<>();
        
        CosmosPagedIterable<Document> pagedResponse = container.queryItems(
            "SELECT * FROM c WHERE c.tenantId = '" + tenantId + "'", 
            new CosmosQueryRequestOptions(), 
            Document.class);
        
        pagedResponse.iterator().forEachRemaining(item -> allItems.add(item));
        
        // Access control decision based on complete tenant data
        boolean hasViolations = allItems.stream()
            .anyMatch(doc -> doc.getBoolean("hasComplianceViolation"));
            
        if (!hasViolations) {
            grantTenantAccess(tenantId);
        }
    }
    
    public void good_case_8(HttpServletRequest request) {
        // AWS S3 - Processing all pages of objects
        String bucketName = request.getParameter("bucket");
        S3Client s3Client = null; // Assume this is initialized
        
        // ok: java-paginatedlistperformancerule
        List<software.amazon.awssdk.services.s3.model.S3Object> allObjects = new ArrayList<>();
        
        ListObjectsV2Request listRequest = ListObjectsV2Request.builder()
            .bucket(bucketName)
            .maxKeys(1000)
            .build();
            
        ListObjectsV2Response response;
        do {
            response = s3Client.listObjectsV2(listRequest);
            allObjects.addAll(response.contents());
            
            listRequest = ListObjectsV2Request.builder()
                .bucket(bucketName)
                .maxKeys(1000)
                .continuationToken(response.nextContinuationToken())
                .build();
                
        } while (response.isTruncated());
        
        // Security scan based on complete object list
        boolean allObjectsScanned = allObjects.stream()
            .allMatch(obj -> scanObject(obj.key()));
            
        if (allObjectsScanned) {
            markBucketAsSecure(bucketName);
        }
    }
    
    public void good_case_9(HttpServletRequest request) {
        // Redis Scan - Processing all keys
        String pattern = request.getParameter("keyPattern");
        Jedis jedis = null; // Assume this is initialized
        
        // ok: java-paginatedlistperformancerule
        List<String> allKeys = new ArrayList<>();
        String cursor = "0";
        ScanParams params = new ScanParams().match(pattern).count(100);
        
        do {
            ScanResult<String> scanResult = jedis.scan(cursor, params);
            cursor = scanResult.getCursor();
            allKeys.addAll(scanResult.getResult());
        } while (!cursor.equals("0"));
        
        // Security check based on complete key scan
        boolean allKeysValid = allKeys.stream()
            .allMatch(key -> validateKey(key));
            
        if (allKeysValid) {
            approveKeyPattern(pattern);
        }
    }
    
    public void good_case_10(HttpServletRequest request) {
        // Neo4j - Processing all results without limit
        String userId = request.getParameter("userId");
        Driver driver = null; // Assume this is initialized
        
        try (org.neo4j.driver.Session session = driver.session(SessionConfig.forDatabase("neo4j"))) {
            // ok: java-paginatedlistperformancerule
            Result result = session.run(
                "MATCH (u:User {id: $userId})-[:HAS_AC_REDACTED_TWILIO_ID]->(r:Resource) RETURN r.name",
                Map.of("userId", userId)
            );
            
            List<String> accessibleResources = new ArrayList<>();
            while (result.hasNext()) {
                Record record = result.next();
                accessibleResources.add(record.get("r.name").asString());
            }
            
            // Access control based on complete resource list
            if (!accessibleResources.contains("sensitive_data")) {
                grantDataAccess(userId);
            }
        }
    }
    
    public void good_case_11(HttpServletRequest request) {
        // Google BigQuery - Processing all rows with pagination
        String projectId = request.getParameter("projectId");
        Bigquery bigquery = null; // Assume this is initialized
        
        try {
            // ok: java-paginatedlistperformancerule
            List<List<Object>> allRows = new ArrayList<>();
            String pageToken = null;
            
            do {
                QueryRequest queryRequest = new QueryRequest()
                    .setQuery("SELECT * FROM `security_events` WHERE project_id = '" + projectId + "'")
                    .setMaxResults(1000L)
                    .setPageToken(pageToken);
                    
                QueryResponse response = bigquery.jobs().query(projectId, queryRequest).execute();
                
                if (response.getRows() != null) {
                    allRows.addAll(response.getRows());
                }
                
                pageToken = response.getPageToken();
            } while (pageToken != null);
            
            // Security audit based on complete event data
            boolean hasSecurityViolations = allRows.stream()
                .anyMatch(row -> "VIOLATION".equals(row.get(2)));
                
            if (!hasSecurityViolations) {
                approveProjectDeployment(projectId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12(HttpServletRequest request) {
        // Apache Cassandra - Processing all columns with pagination
        String userId = request.getParameter("userId");
        Cassandra.Client client = null; // Assume this is initialized
        
        try {
            // ok: java-paginatedlistperformancerule
            List<Column> allColumns = new ArrayList<>();
            ColumnParent parent = new ColumnParent("user_activities");
            byte[] lastColumn = new byte[0];
            
            while (true) {
                SlicePredicate predicate = new SlicePredicate();
                SliceRange sliceRange = new SliceRange();
                sliceRange.setStart(lastColumn);
                sliceRange.setFinish(new byte[0]);
                sliceRange.setCount(100);
                predicate.setSlice_range(sliceRange);
                
                List<Column> columns = client.get_slice(
                    userId.getBytes(), 
                    parent, 
                    predicate, 
                    ConsistencyLevel.ONE
                );
                
                if (columns.isEmpty()) {
                    break;
                }
                
                allColumns.addAll(columns);
                lastColumn = columns.get(columns.size() - 1).getName();
            }
            
            // User activity analysis based on complete data
            boolean hasAnomalousActivity = allColumns.stream()
                .anyMatch(col -> "ANOMALOUS".equals(new String(col.getValue())));
                
            if (!hasAnomalousActivity) {
                clearUserSuspicion(userId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13(HttpServletRequest request) {
        // HBase - Scanning all rows without limit
        String rowPrefix = request.getParameter("rowPrefix");
        Table table = null; // Assume this is initialized
        
        try {
            // ok: java-paginatedlistperformancerule
            Scan scan = new Scan();
            scan.setRowPrefixFilter(Bytes.toBytes(rowPrefix));
            scan.setCaching(1000); // Larger cache size for efficiency
            
            ResultScanner scanner = table.getScanner(scan);
            
            List<org.apache.hadoop.hbase.client.Result> allResults = new ArrayList<>();
            for (org.apache.hadoop.hbase.client.Result result : scanner) {
                allResults.add(result);
            }
            
            // Security analysis based on complete data
            boolean allRowsSecure = allResults.stream()
                .allMatch(result -> isSecureRow(result));
                
            if (allRowsSecure) {
                approveDataAccess(rowPrefix);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14(HttpServletRequest request) {
        // Firestore - Processing all documents with pagination
        String organizationId = request.getParameter("orgId");
        Firestore firestore = null; // Assume this is initialized
        
        try {
            // ok: java-paginatedlistperformancerule
            List<QueryDocumentSnapshot> allDocuments = new ArrayList<>();
            Query query = firestore.collection("users")
                .whereEqualTo("organizationId", organizationId);
                
            // Get the first batch
            ApiFuture<QuerySnapshot> future = query.get();
            QuerySnapshot snapshot = future.get();
            
            // Process results and continue if there are more
            while (!snapshot.isEmpty()) {
                allDocuments.addAll(snapshot.getDocuments());
                
                // Get the last document
                DocumentSnapshot lastDoc = snapshot.getDocuments()
                    .get(snapshot.size() - 1);
                
                // Construct a new query starting after the last document
                future = query.startAfter(lastDoc).get();
                snapshot = future.get();
            }
            
            // Access control based on complete user list
            boolean allUsersVerified = allDocuments.stream()
                .allMatch(doc -> doc.getBoolean("isVerified"));
                
            if (allUsersVerified) {
                grantOrganizationAccess(organizationId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15(HttpServletRequest request) {
        // Custom API client with Retrofit - Processing all pages
        String apiKey = request.getParameter("apiKey");
        String query = request.getParameter("query");
        
        Retrofit retrofit = null; // Assume this is initialized
        SecurityApiService service = retrofit.create(SecurityApiService.class);
        
        try {
            // ok: java-paginatedlistperformancerule
            List<SecurityEvent> allEvents = new ArrayList<>();
            int currentPage = 1;
            SecurityEventsResponse response;
            
            do {
                Call<SecurityEventsResponse> call = service.getSecurityEvents(apiKey, query, currentPage, 100);
                response = call.execute().body();
                
                if (response != null && response.getEvents() != null) {
                    allEvents.addAll(response.getEvents());
                }
                
                currentPage++;
            } while (response != null && response.hasMorePages());
            
            // Security analysis based on complete events
            boolean hasHighSeverityEvents = allEvents.stream()
                .anyMatch(event -> event.getSeverity() >= 8);
                
            if (!hasHighSeverityEvents) {
                approveSystemAccess(query);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper methods and classes (stubs)
    private void grantAdminAccess() {}
    private void markAccountAsVerified(String userId) {}
    private void issueComplianceCertificate(String companyId) {}
    private void approveProductCategory(String category) {}
    private void grantDepartmentAccess(String departmentId) {}
    private void downgradeSecurityAlert(String threat) {}
    private void grantTenantAccess(String tenantId) {}
    private void markBucketAsSecure(String bucketName) {}
    private boolean validateKey(String key) { return true; }
    private void approveKeyPattern(String pattern) {}
    private void grantDataAccess(String userId) {}
    private void approveProjectDeployment(String projectId) {}
    private void clearUserSuspicion(String userId) {}
    private boolean isSecureRow(org.apache.hadoop.hbase.client.Result result) { return true; }
    private void approveDataAccess(String rowPrefix) {}
    private void grantOrganizationAccess(String organizationId) {}
    private void approveSystemAccess(String query) {}
    private boolean scanObject(String key) { return true; }
    
    private static class User {
        private String role;
        public String getRole() { return role; }
    }
    
    private static class Employee {
        private int securityClearance;
        public int getSecurityClearance() { return securityClearance; }
    }
    
    private static class Document {
        public boolean getBoolean(String field) { return true; }
    }
    
    private static class SecurityEvent {
        private int severity;
        public int getSeverity() { return severity; }
    }
    
    private static class SecurityEventsResponse {
        private List<SecurityEvent> events;
        private boolean hasMorePages;
        
        public List<SecurityEvent> getEvents() { return events; }
        public boolean hasMorePages() { return hasMorePages; }
    }
    
    private interface SecurityApiService {
        @GET("security/events")
        Call<SecurityEventsResponse> getSecurityEvents(
            @Query("apiKey") String apiKey,
            @Query("query") String query,
            @Query("page") int page,
            @Query("pageSize") int pageSize
        );
    }
}
// {/fact}