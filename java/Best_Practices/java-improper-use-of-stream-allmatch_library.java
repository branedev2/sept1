import java.util.*;
import java.util.stream.*;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.google.common.collect.*;
import org.apache.commons.collections4.*;
import org.apache.commons.io.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.commons.lang3.*;
import retrofit2.*;
import retrofit2.http.*;
import okhttp3.*;
import org.hibernate.*;
import javax.persistence.*;
import org.mongodb.*;
import com.mongodb.*;
import com.mongodb.client.*;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.*;
import spark.*;
import io.javalin.*;
import io.vertx.core.*;
import io.vertx.ext.web.*;
import play.mvc.*;
import ratpack.server.*;
import ratpack.handling.*;
import com.fasterxml.jackson.databind.*;
import org.json.*;

// Security Issue: Improper use of Stream.allMatch() with potentially empty streams can lead to false positives
// when the stream is empty, as allMatch returns true by default for empty streams.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring Framework - User validation with potentially empty list
    String username = request.getParameter("username");
    List<String> userRoles = getUserRoles(username); // Could be empty
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean hasAdminAccess = userRoles.stream().allMatch(role -> role.contains("ADMIN"));
    
    if (hasAdminAccess) {
        // Grant admin privileges - security risk if userRoles is empty!
        System.out.println("Admin access granted to: " + username);
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Apache Commons Collections - Validating file extensions
    String[] uploadedFiles = request.getParameterValues("files");
    List<String> fileNames = Arrays.asList(uploadedFiles);
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allFilesAreSafe = fileNames.stream().allMatch(name -> !name.endsWith(".exe") && !name.endsWith(".bat"));
    
    if (allFilesAreSafe) {
        // Process files - security risk if fileNames is empty!
        System.out.println("Processing files...");
    }
}

public void bad_case_3(@RequestParam("ids") List<String> ids) {
    // Hibernate ORM - Checking database records
    Session session = getHibernateSession();
    List<User> users = new ArrayList<>();
    
    for (String id : ids) {
        User user = session.get(User.class, id);
        if (user != null) {
            users.add(user);
        }
    }
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allUsersActive = users.stream().allMatch(user -> user.isActive());
    
    if (allUsersActive) {
        // Perform operation for active users - security risk if users is empty!
        System.out.println("All users are active");
    }
}

public void bad_case_4(HttpServletRequest request) {
    // MongoDB Java Driver - Validating document fields
    String collectionName = request.getParameter("collection");
    MongoCollection<Document> collection = getMongoDatabase().getCollection(collectionName);
    
    FindIterable<Document> documents = collection.find();
    List<Document> docList = new ArrayList<>();
    documents.into(docList);
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allDocumentsValid = docList.stream().allMatch(doc -> doc.containsKey("requiredField"));
    
    if (allDocumentsValid) {
        // Process documents - security risk if docList is empty!
        System.out.println("All documents are valid");
    }
}

public void bad_case_5(HttpServletRequest request) {
    // AWS SDK - S3 object validation
    String bucketName = request.getParameter("bucket");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    List<S3ObjectSummary> objects = s3Client.listObjects(bucketName).getObjectSummaries();
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allObjectsArePublic = objects.stream().allMatch(obj -> isPublicObject(obj));
    
    if (allObjectsArePublic) {
        // Process public objects - security risk if objects is empty!
        System.out.println("All objects are public");
    }
}

public void bad_case_6(Request request, Response response) {
    // Spark Framework - Input validation
    String jsonBody = request.body();
    JSONArray jsonArray = new JSONArray(jsonBody);
    List<String> inputs = new ArrayList<>();
    
    for (int i = 0; i < jsonArray.length(); i++) {
        inputs.add(jsonArray.getString(i));
    }
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allInputsValid = inputs.stream().allMatch(input -> input.length() <= 100);
    
    if (allInputsValid) {
        // Process inputs - security risk if inputs is empty!
        response.status(200);
    }
}

public void bad_case_7(HttpServletRequest request) {
    // OkHttp - API response validation
    String apiUrl = request.getParameter("apiUrl");
    OkHttpClient client = new OkHttpClient();
    okhttp3.Request okRequest = new okhttp3.Request.Builder().url(apiUrl).build();
    
    try {
        okhttp3.Response okResponse = client.newCall(okRequest).execute();
        JSONArray results = new JSONArray(okResponse.body().string());
        List<JSONObject> resultObjects = new ArrayList<>();
        
        for (int i = 0; i < results.length(); i++) {
            resultObjects.add(results.getJSONObject(i));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allResultsHaveId = resultObjects.stream().allMatch(obj -> obj.has("id"));
        
        if (allResultsHaveId) {
            // Process results - security risk if resultObjects is empty!
            System.out.println("All results have ID");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    // Jackson ObjectMapper - JSON validation
    String jsonData = request.getParameter("data");
    ObjectMapper mapper = new ObjectMapper();
    
    try {
        List<Map<String, Object>> dataList = mapper.readValue(jsonData, 
                mapper.getTypeFactory().constructCollectionType(List.class, Map.class));
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allDataValid = dataList.stream().allMatch(map -> map.containsKey("name") && map.containsKey("value"));
        
        if (allDataValid) {
            // Process data - security risk if dataList is empty!
            System.out.println("All data entries are valid");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // JDBC - Database record validation
    String tableName = request.getParameter("table");
    List<Map<String, Object>> records = new ArrayList<>();
    
    try (Connection conn = getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT * FROM " + tableName)) {
        
        while (rs.next()) {
            Map<String, Object> record = new HashMap<>();
            ResultSetMetaData metaData = rs.getMetaData();
            for (int i = 1; i <= metaData.getColumnCount(); i++) {
                record.put(metaData.getColumnName(i), rs.getObject(i));
            }
            records.add(record);
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allRecordsHaveId = records.stream().allMatch(r -> r.containsKey("id"));
        
        if (allRecordsHaveId) {
            // Process records - security risk if records is empty!
            System.out.println("All records have ID");
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Retrofit - API client validation
    String userId = request.getParameter("userId");
    UserApiService service = createRetrofitService();
    
    try {
        List<Post> userPosts = service.getUserPosts(userId).execute().body();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allPostsPublished = userPosts.stream().allMatch(post -> "published".equals(post.getStatus()));
        
        if (allPostsPublished) {
            // Process posts - security risk if userPosts is empty!
            System.out.println("All posts are published");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Jetty Server - Request validation
    String pathParam = request.getParameter("paths");
    String[] paths = pathParam.split(",");
    List<File> files = Arrays.stream(paths).map(path -> new File(path)).collect(Collectors.toList());
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allFilesExist = files.stream().allMatch(file -> file.exists());
    
    if (allFilesExist) {
        // Process files - security risk if files is empty!
        System.out.println("All files exist");
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Guava Collections - Input validation
    String inputData = request.getParameter("data");
    List<String> dataItems = Splitter.on(',').splitToList(inputData);
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allItemsValid = dataItems.stream().allMatch(item -> item.matches("[a-zA-Z0-9]+"));
    
    if (allItemsValid) {
        // Process items - security risk if dataItems is empty!
        System.out.println("All items are valid");
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Vert.x - HTTP request validation
    String headerValues = request.getParameter("headers");
    List<String> headers = Arrays.asList(headerValues.split(","));
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allHeadersValid = headers.stream().allMatch(header -> !header.contains("injection"));
    
    if (allHeadersValid) {
        // Process headers - security risk if headers is empty!
        System.out.println("All headers are valid");
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Play Framework - Form validation
    String formData = request.getParameter("formFields");
    List<String> formFields = Arrays.asList(formData.split(","));
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allFieldsValid = formFields.stream().allMatch(field -> field.length() > 0 && field.length() <= 100);
    
    if (allFieldsValid) {
        // Process form fields - security risk if formFields is empty!
        System.out.println("All form fields are valid");
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Ratpack - Request parameter validation
    String[] paramValues = request.getParameterValues("values");
    List<String> values = paramValues != null ? Arrays.asList(paramValues) : Collections.emptyList();
    
    // ruleid: java-improper-use-of-stream-allmatch
    boolean allValuesNumeric = values.stream().allMatch(value -> value.matches("\\d+"));
    
    if (allValuesNumeric) {
        // Process numeric values - security risk if values is empty!
        System.out.println("All values are numeric");
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring Framework - User validation with empty check
    String username = request.getParameter("username");
    List<String> userRoles = getUserRoles(username); // Could be empty
    
    // ok: java-improper-use-of-stream-allmatch
    boolean hasAdminAccess = !userRoles.isEmpty() && userRoles.stream().allMatch(role -> role.contains("ADMIN"));
    
    if (hasAdminAccess) {
        // Grant admin privileges - safe because we check if userRoles is empty
        System.out.println("Admin access granted to: " + username);
    }
}

public void good_case_2(HttpServletRequest request) {
    // Apache Commons Collections - Validating file extensions with empty check
    String[] uploadedFiles = request.getParameterValues("files");
    List<String> fileNames = Arrays.asList(uploadedFiles);
    
    // ok: java-improper-use-of-stream-allmatch
    boolean allFilesAreSafe = !fileNames.isEmpty() && fileNames.stream().allMatch(name -> !name.endsWith(".exe") && !name.endsWith(".bat"));
    
    if (allFilesAreSafe) {
        // Process files - safe because we check if fileNames is empty
        System.out.println("Processing files...");
    }
}

public void good_case_3(@RequestParam("ids") List<String> ids) {
    // Hibernate ORM - Checking database records with findAny check
    Session session = getHibernateSession();
    List<User> users = new ArrayList<>();
    
    for (String id : ids) {
        User user = session.get(User.class, id);
        if (user != null) {
            users.add(user);
        }
    }
    
    // ok: java-improper-use-of-stream-allmatch
    boolean allUsersActive = users.stream().findAny().isPresent() && 
                            users.stream().allMatch(user -> user.isActive());
    
    if (allUsersActive) {
        // Perform operation for active users - safe because we check if users has any elements
        System.out.println("All users are active");
    }
}

public void good_case_4(HttpServletRequest request) {
    // MongoDB Java Driver - Validating document fields with size check
    String collectionName = request.getParameter("collection");
    MongoCollection<Document> collection = getMongoDatabase().getCollection(collectionName);
    
    FindIterable<Document> documents = collection.find();
    List<Document> docList = new ArrayList<>();
    documents.into(docList);
    
    // ok: java-improper-use-of-stream-allmatch
    boolean allDocumentsValid = docList.size() > 0 && 
                               docList.stream().allMatch(doc -> doc.containsKey("requiredField"));
    
    if (allDocumentsValid) {
        // Process documents - safe because we check if docList has elements
        System.out.println("All documents are valid");
    }
}

public void good_case_5(HttpServletRequest request) {
    // AWS SDK - S3 object validation with noneMatch check
    String bucketName = request.getParameter("bucket");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    List<S3ObjectSummary> objects = s3Client.listObjects(bucketName).getObjectSummaries();
    
    // ok: java-improper-use-of-stream-allmatch
    boolean allObjectsArePublic = !objects.stream().noneMatch(obj -> true) && 
                                 objects.stream().allMatch(obj -> isPublicObject(obj));
    
    if (allObjectsArePublic) {
        // Process public objects - safe because we check if objects has any elements
        System.out.println("All objects are public");
    }
}

public void good_case_6(Request request, Response response) {
    // Spark Framework - Input validation with alternative approach
    String jsonBody = request.body();
    JSONArray jsonArray = new JSONArray(jsonBody);
    List<String> inputs = new ArrayList<>();
    
    for (int i = 0; i < jsonArray.length(); i++) {
        inputs.add(jsonArray.getString(i));
    }
    
    // ok: java-improper-use-of-stream-allmatch
    if (inputs.isEmpty()) {
        response.status(400);
        return;
    }
    
    boolean allInputsValid = inputs.stream().allMatch(input -> input.length() <= 100);
    
    if (allInputsValid) {
        // Process inputs - safe because we explicitly handle empty inputs
        response.status(200);
    }
}

public void good_case_7(HttpServletRequest request) {
    // OkHttp - API response validation with explicit empty handling
    String apiUrl = request.getParameter("apiUrl");
    OkHttpClient client = new OkHttpClient();
    okhttp3.Request okRequest = new okhttp3.Request.Builder().url(apiUrl).build();
    
    try {
        okhttp3.Response okResponse = client.newCall(okRequest).execute();
        JSONArray results = new JSONArray(okResponse.body().string());
        List<JSONObject> resultObjects = new ArrayList<>();
        
        for (int i = 0; i < results.length(); i++) {
            resultObjects.add(results.getJSONObject(i));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (resultObjects.isEmpty()) {
            System.out.println("No results to process");
            return;
        }
        
        boolean allResultsHaveId = resultObjects.stream().allMatch(obj -> obj.has("id"));
        
        if (allResultsHaveId) {
            // Process results - safe because we explicitly handle empty resultObjects
            System.out.println("All results have ID");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // Jackson ObjectMapper - JSON validation with count check
    String jsonData = request.getParameter("data");
    ObjectMapper mapper = new ObjectMapper();
    
    try {
        List<Map<String, Object>> dataList = mapper.readValue(jsonData, 
                mapper.getTypeFactory().constructCollectionType(List.class, Map.class));
        
        // ok: java-improper-use-of-stream-allmatch
        long count = dataList.stream().count();
        boolean allDataValid = count > 0 && dataList.stream().allMatch(map -> map.containsKey("name") && map.containsKey("value"));
        
        if (allDataValid) {
            // Process data - safe because we check if dataList has elements
            System.out.println("All data entries are valid");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    // JDBC - Database record validation with isEmpty check
    String tableName = request.getParameter("table");
    List<Map<String, Object>> records = new ArrayList<>();
    
    try (Connection conn = getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT * FROM " + tableName)) {
        
        while (rs.next()) {
            Map<String, Object> record = new HashMap<>();
            ResultSetMetaData metaData = rs.getMetaData();
            for (int i = 1; i <= metaData.getColumnCount(); i++) {
                record.put(metaData.getColumnName(i), rs.getObject(i));
            }
            records.add(record);
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean allRecordsHaveId = !records.isEmpty() && records.stream().allMatch(r -> r.containsKey("id"));
        
        if (allRecordsHaveId) {
            // Process records - safe because we check if records is empty
            System.out.println("All records have ID");
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // Retrofit - API client validation with alternative approach
    String userId = request.getParameter("userId");
    UserApiService service = createRetrofitService();
    
    try {
        List<Post> userPosts = service.getUserPosts(userId).execute().body();
        
        // ok: java-improper-use-of-stream-allmatch
        if (userPosts == null || userPosts.isEmpty()) {
            System.out.println("No posts found for user");
            return;
        }
        
        boolean allPostsPublished = userPosts.stream().allMatch(post -> "published".equals(post.getStatus()));
        
        if (allPostsPublished) {
            // Process posts - safe because we explicitly handle empty userPosts
            System.out.println("All posts are published");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // Jetty Server - Request validation with explicit check
    String pathParam = request.getParameter("paths");
    String[] paths = pathParam.split(",");
    List<File> files = Arrays.stream(paths).map(path -> new File(path)).collect(Collectors.toList());
    
    // ok: java-improper-use-of-stream-allmatch
    if (files.isEmpty()) {
        System.out.println("No files to process");
        return;
    }
    
    boolean allFilesExist = files.stream().allMatch(file -> file.exists());
    
    if (allFilesExist) {
        // Process files - safe because we explicitly handle empty files list
        System.out.println("All files exist");
    }
}

public void good_case_12(HttpServletRequest request) {
    // Guava Collections - Input validation with findFirst check
    String inputData = request.getParameter("data");
    List<String> dataItems = Splitter.on(',').splitToList(inputData);
    
    // ok: java-improper-use-of-stream-allmatch
    Optional<String> firstItem = dataItems.stream().findFirst();
    boolean allItemsValid = firstItem.isPresent() && dataItems.stream().allMatch(item -> item.matches("[a-zA-Z0-9]+"));
    
    if (allItemsValid) {
        // Process items - safe because we check if dataItems has at least one element
        System.out.println("All items are valid");
    }
}

public void good_case_13(HttpServletRequest request) {
    // Vert.x - HTTP request validation with explicit handling
    String headerValues = request.getParameter("headers");
    List<String> headers = Arrays.asList(headerValues.split(","));
    
    // ok: java-improper-use-of-stream-allmatch
    boolean hasHeaders = !headers.stream().noneMatch(x -> true);
    boolean allHeadersValid = hasHeaders && headers.stream().allMatch(header -> !header.contains("injection"));
    
    if (allHeadersValid) {
        // Process headers - safe because we check if headers has elements
        System.out.println("All headers are valid");
    }
}

public void good_case_14(HttpServletRequest request) {
    // Play Framework - Form validation with explicit empty handling
    String formData = request.getParameter("formFields");
    List<String> formFields = Arrays.asList(formData.split(","));
    
    // ok: java-improper-use-of-stream-allmatch
    if (formFields.isEmpty() || formFields.get(0).isEmpty()) {
        System.out.println("No form fields to process");
        return;
    }
    
    boolean allFieldsValid = formFields.stream().allMatch(field -> field.length() > 0 && field.length() <= 100);
    
    if (allFieldsValid) {
        // Process form fields - safe because we explicitly handle empty formFields
        System.out.println("All form fields are valid");
    }
}

public void good_case_15(HttpServletRequest request) {
    // Ratpack - Request parameter validation with findAny check
    String[] paramValues = request.getParameterValues("values");
    List<String> values = paramValues != null ? Arrays.asList(paramValues) : Collections.emptyList();
    
    // ok: java-improper-use-of-stream-allmatch
    boolean hasValues = values.stream().findAny().isPresent();
    boolean allValuesNumeric = hasValues && values.stream().allMatch(value -> value.matches("\\d+"));
    
    if (allValuesNumeric) {
        // Process numeric values - safe because we check if values has any elements
        System.out.println("All values are numeric");
    }
}

// Helper methods to make the examples compile
private List<String> getUserRoles(String username) { return new ArrayList<>(); }
private Session getHibernateSession() { return null; }
private MongoDatabase getMongoDatabase() { return null; }
private boolean isPublicObject(S3ObjectSummary obj) { return true; }
private Connection getConnection() { return null; }
private UserApiService createRetrofitService() { return null; }

// Helper interfaces for examples
interface UserApiService {
    Call<List<Post>> getUserPosts(String userId);
}

class User {
    public boolean isActive() { return true; }
}

class Post {
    public String getStatus() { return ""; }
}