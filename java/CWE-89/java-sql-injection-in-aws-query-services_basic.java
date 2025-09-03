import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;

import software.amazon.awssdk.services.athena.AthenaClient;
import software.amazon.awssdk.services.athena.model.StartQueryExecutionRequest;
import software.amazon.awssdk.services.athena.model.StartQueryExecutionResponse;

import software.amazon.awssdk.services.timestream.TimestreamQueryClient;
import software.amazon.awssdk.services.timestream.model.QueryRequest;
import software.amazon.awssdk.services.timestream.model.QueryResponse;

import software.amazon.awssdk.services.redshiftdata.RedshiftDataClient;
import software.amazon.awssdk.services.redshiftdata.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.redshiftdata.model.ExecuteStatementResponse;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementResponse;

import software.amazon.awssdk.services.rdsdata.RdsDataClient;
import software.amazon.awssdk.services.rdsdata.model.ExecuteStatementRequest.Builder;
import software.amazon.awssdk.services.rdsdata.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.rdsdata.model.ExecuteStatementResponse;
import software.amazon.awssdk.services.rdsdata.model.SqlParameter;

public class AwsSqlInjectionExamples extends HttpServlet {

    // True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        String query = "SELECT * FROM users WHERE user_id = '" + userId + "'";
        
        StartQueryExecutionRequest startQueryExecutionRequest = StartQueryExecutionRequest.builder()
            .queryString(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse result = athenaClient.startQueryExecution(startQueryExecutionRequest);
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        String column = request.getParameter("column");
        
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        String query = "SELECT * FROM " + tableName + " ORDER BY " + column;
        
        QueryRequest queryRequest = QueryRequest.builder()
            .queryString(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        QueryResponse queryResponse = timestreamClient.query(queryRequest);
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String limit = request.getParameter("limit");
        
        RedshiftDataClient redshiftClient = RedshiftDataClient.builder().build();
        
        String query = "SELECT * FROM products WHERE product_id > " + productId + " LIMIT " + limit;
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .clusterIdentifier("my-cluster")
            .database("my-database")
            .sql(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = redshiftClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        String statement = "SELECT * FROM Users WHERE username = '" + username + "'";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .statement(statement)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = dynamoDbClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String orderId = request.getParameter("orderId");
        String status = request.getHeader("X-Status");
        
        RdsDataClient rdsDataClient = RdsDataClient.builder().build();
        
        String sql = "UPDATE orders SET status = '" + status + "' WHERE order_id = " + orderId;
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .resourceArn("arn:aws:rds:us-east-1:123456789012:cluster:my-cluster")
            .secretArn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret")
            .sql(sql)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse result = rdsDataClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String category = request.getParameter("category");
        String minPrice = request.getParameter("minPrice");
        
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        StringBuilder queryBuilder = new StringBuilder();
        queryBuilder.append("SELECT * FROM products WHERE category = '");
        queryBuilder.append(category);
        queryBuilder.append("' AND price > ");
        queryBuilder.append(minPrice);
        
        StartQueryExecutionRequest startQueryExecutionRequest = StartQueryExecutionRequest.builder()
            .queryString(queryBuilder.toString())
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse result = athenaClient.startQueryExecution(startQueryExecutionRequest);
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String dateFrom = request.getParameter("dateFrom");
        String dateTo = request.getParameter("dateTo");
        
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        String query = String.format("SELECT * FROM metrics WHERE time BETWEEN '%s' AND '%s'", dateFrom, dateTo);
        
        QueryRequest queryRequest = QueryRequest.builder()
            .queryString(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        QueryResponse queryResponse = timestreamClient.query(queryRequest);
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String region = request.getParameter("region");
        String[] productIds = request.getParameterValues("productIds");
        
        StringBuilder idList = new StringBuilder();
        for (int i = 0; i < productIds.length; i++) {
            if (i > 0) {
                idList.append(", ");
            }
            idList.append(productIds[i]);
        }
        
        RedshiftDataClient redshiftClient = RedshiftDataClient.builder().build();
        
        String query = "SELECT * FROM inventory WHERE region = '" + region + "' AND product_id IN (" + idList.toString() + ")";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .clusterIdentifier("my-cluster")
            .database("my-database")
            .sql(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = redshiftClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        String statement = "SELECT * FROM Products WHERE contains(description, '" + searchTerm + "')";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .statement(statement)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = dynamoDbClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String customerId = request.getParameter("customerId");
        String orderField = request.getParameter("orderBy");
        String direction = request.getParameter("direction");
        
        RdsDataClient rdsDataClient = RdsDataClient.builder().build();
        
        String sql = "SELECT * FROM customers WHERE customer_id = " + customerId + " ORDER BY " + orderField + " " + direction;
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .resourceArn("arn:aws:rds:us-east-1:123456789012:cluster:my-cluster")
            .secretArn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret")
            .sql(sql)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse result = rdsDataClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("query");
        
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        // The user input is directly used in the query
        StartQueryExecutionRequest startQueryExecutionRequest = StartQueryExecutionRequest.builder()
            .queryString(userInput)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse result = athenaClient.startQueryExecution(startQueryExecutionRequest);
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        String whereClause = request.getParameter("where");
        
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        String query = "SELECT * FROM " + tableName + " WHERE " + whereClause;
        
        QueryRequest queryRequest = QueryRequest.builder()
            .queryString(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        QueryResponse queryResponse = timestreamClient.query(queryRequest);
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String cookie = request.getHeader("Cookie");
        
        RedshiftDataClient redshiftClient = RedshiftDataClient.builder().build();
        
        String query = "INSERT INTO user_sessions (user_id, cookie) VALUES (" + userId + ", '" + cookie + "')";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .clusterIdentifier("my-cluster")
            .database("my-database")
            .sql(query)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = redshiftClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        String statement = "DELETE FROM Users WHERE email = '" + email + "'";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .statement(statement)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = dynamoDbClient.executeStatement(executeStatementRequest);
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String startDate = request.getParameter("startDate");
        String endDate = request.getParameter("endDate");
        String userType = request.getParameter("userType");
        
        RdsDataClient rdsDataClient = RdsDataClient.builder().build();
        
        String sql = "SELECT COUNT(*) FROM user_logins WHERE login_date BETWEEN '" + 
                     startDate + "' AND '" + endDate + "' AND user_type = '" + userType + "'";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .resourceArn("arn:aws:rds:us-east-1:123456789012:cluster:my-cluster")
            .secretArn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret")
            .sql(sql)
            .build();
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse result = rdsDataClient.executeStatement(executeStatementRequest);
    }

    // True Negatives (Secure Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        // Using parameterized query with prepared statement style
        Map<String, String> params = new HashMap<>();
        params.put("userId", userId);
        
        String query = "SELECT * FROM users WHERE user_id = :userId";
        
        StartQueryExecutionRequest startQueryExecutionRequest = StartQueryExecutionRequest.builder()
            .queryString(query)
            .executionParameters(List.of(userId))
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse result = athenaClient.startQueryExecution(startQueryExecutionRequest);
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        String column = request.getParameter("column");
        
        // Validate input against whitelist
        List<String> validTables = List.of("metrics", "events", "logs");
        List<String> validColumns = List.of("timestamp", "value", "name", "id");
        
        if (!validTables.contains(tableName) || !validColumns.contains(column)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid table or column name");
            return;
        }
        
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        String query = "SELECT * FROM " + tableName + " ORDER BY " + column;
        
        QueryRequest queryRequest = QueryRequest.builder()
            .queryString(query)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        QueryResponse queryResponse = timestreamClient.query(queryRequest);
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productIdStr = request.getParameter("productId");
        String limitStr = request.getParameter("limit");
        
        // Validate and convert to appropriate types
        int productId;
        int limit;
        
        try {
            productId = Integer.parseInt(productIdStr);
            limit = Integer.parseInt(limitStr);
            
            if (limit <= 0 || limit > 1000) {
                limit = 100; // Default safe limit
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameters");
            return;
        }
        
        RedshiftDataClient redshiftClient = RedshiftDataClient.builder().build();
        
        // Using parameterized query
        String query = "SELECT * FROM products WHERE product_id > ? LIMIT ?";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .clusterIdentifier("my-cluster")
            .database("my-database")
            .sql(query)
            .parameters(productId, limit)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = redshiftClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        // Using parameterized query
        String statement = "SELECT * FROM Users WHERE username = ?";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .statement(statement)
            .parameters(username)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = dynamoDbClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String orderId = request.getParameter("orderId");
        String status = request.getHeader("X-Status");
        
        RdsDataClient rdsDataClient = RdsDataClient.builder().build();
        
        List<SqlParameter> parameters = new ArrayList<>();
        parameters.add(SqlParameter.builder().name("status").value(status).build());
        parameters.add(SqlParameter.builder().name("orderId").value(orderId).build());
        
        String sql = "UPDATE orders SET status = :status WHERE order_id = :orderId";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .resourceArn("arn:aws:rds:us-east-1:123456789012:cluster:my-cluster")
            .secretArn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret")
            .sql(sql)
            .parameters(parameters)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse result = rdsDataClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String category = request.getParameter("category");
        String minPriceStr = request.getParameter("minPrice");
        
        // Validate and sanitize inputs
        if (category == null || !category.matches("[a-zA-Z0-9_-]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid category");
            return;
        }
        
        double minPrice;
        try {
            minPrice = Double.parseDouble(minPriceStr);
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid price");
            return;
        }
        
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        String query = "SELECT * FROM products WHERE category = ? AND price > ?";
        
        StartQueryExecutionRequest startQueryExecutionRequest = StartQueryExecutionRequest.builder()
            .queryString(query)
            .executionParameters(List.of(category, String.valueOf(minPrice)))
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse result = athenaClient.startQueryExecution(startQueryExecutionRequest);
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String dateFrom = request.getParameter("dateFrom");
        String dateTo = request.getParameter("dateTo");
        
        // Validate date format
        if (!dateFrom.matches("\\d{4}-\\d{2}-\\d{2}") || !dateTo.matches("\\d{4}-\\d{2}-\\d{2}")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid date format. Use YYYY-MM-DD");
            return;
        }
        
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        // Using parameterized query
        String query = "SELECT * FROM metrics WHERE time BETWEEN ? AND ?";
        
        QueryRequest queryRequest = QueryRequest.builder()
            .queryString(query)
            .parameters(List.of(dateFrom, dateTo))
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        QueryResponse queryResponse = timestreamClient.query(queryRequest);
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String region = request.getParameter("region");
        String[] productIds = request.getParameterValues("productIds");
        
        // Validate region
        List<String> validRegions = List.of("us-east", "us-west", "eu-central", "ap-south");
        if (!validRegions.contains(region)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid region");
            return;
        }
        
        // Validate product IDs
        List<Integer> validatedIds = new ArrayList<>();
        for (String idStr : productIds) {
            try {
                int id = Integer.parseInt(idStr);
                if (id > 0) {
                    validatedIds.add(id);
                }
            } catch (NumberFormatException e) {
                // Skip invalid IDs
            }
        }
        
        if (validatedIds.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid product IDs");
            return;
        }
        
        RedshiftDataClient redshiftClient = RedshiftDataClient.builder().build();
        
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < validatedIds.size(); i++) {
            if (i > 0) {
                placeholders.append(", ");
            }
            placeholders.append("?");
        }
        
        String query = "SELECT * FROM inventory WHERE region = ? AND product_id IN (" + placeholders.toString() + ")";
        
        List<Object> params = new ArrayList<>();
        params.add(region);
        params.addAll(validatedIds);
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .clusterIdentifier("my-cluster")
            .database("my-database")
            .sql(query)
            .parameters(params)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = redshiftClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        
        // Escape special characters for PartiQL
        searchTerm = searchTerm.replace("'", "''");
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        // Using parameterized query
        String statement = "SELECT * FROM Products WHERE contains(description, ?)";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .statement(statement)
            .parameters(searchTerm)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = dynamoDbClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String customerIdStr = request.getParameter("customerId");
        String orderField = request.getParameter("orderBy");
        String direction = request.getParameter("direction");
        
        // Validate customer ID
        int customerId;
        try {
            customerId = Integer.parseInt(customerIdStr);
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid customer ID");
            return;
        }
        
        // Validate order field against whitelist
        List<String> validOrderFields = List.of("name", "email", "created_at", "status");
        if (!validOrderFields.contains(orderField)) {
            orderField = "created_at"; // Default safe value
        }
        
        // Validate direction
        if (!direction.equalsIgnoreCase("ASC") && !direction.equalsIgnoreCase("DESC")) {
            direction = "ASC"; // Default safe value
        }
        
        RdsDataClient rdsDataClient = RdsDataClient.builder().build();
        
        String sql = "SELECT * FROM customers WHERE customer_id = :customerId ORDER BY " + orderField + " " + direction;
        
        List<SqlParameter> parameters = new ArrayList<>();
        parameters.add(SqlParameter.builder().name("customerId").value(String.valueOf(customerId)).build());
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .resourceArn("arn:aws:rds:us-east-1:123456789012:cluster:my-cluster")
            .secretArn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret")
            .sql(sql)
            .parameters(parameters)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse result = rdsDataClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("query");
        
        // Validate that the query only contains allowed operations
        if (!isValidQuery(userInput)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid query");
            return;
        }
        
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        // Using a predefined query template with parameters
        String safeQuery = "SELECT * FROM logs WHERE timestamp > ? AND level = ?";
        
        StartQueryExecutionRequest startQueryExecutionRequest = StartQueryExecutionRequest.builder()
            .queryString(safeQuery)
            .executionParameters(List.of("2023-01-01", "ERROR"))
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse result = athenaClient.startQueryExecution(startQueryExecutionRequest);
    }
    
    private boolean isValidQuery(String query) {
        // Implementation of query validation logic
        return query != null && query.toLowerCase().startsWith("select") && !query.toLowerCase().contains("drop") 
            && !query.toLowerCase().contains("delete") && !query.toLowerCase().contains("update");
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        String field = request.getParameter("field");
        String value = request.getParameter("value");
        
        // Validate table name against whitelist
        List<String> validTables = List.of("metrics", "events", "logs");
        if (!validTables.contains(tableName)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid table name");
            return;
        }
        
        // Validate field name against whitelist
        List<String> validFields = List.of("id", "name", "timestamp", "value");
        if (!validFields.contains(field)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid field name");
            return;
        }
        
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        // Using parameterized query
        String query = "SELECT * FROM " + tableName + " WHERE " + field + " = ?";
        
        QueryRequest queryRequest = QueryRequest.builder()
            .queryString(query)
            .parameters(List.of(value))
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        QueryResponse queryResponse = timestreamClient.query(queryRequest);
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userIdStr = request.getParameter("userId");
        String cookie = request.getHeader("Cookie");
        
        // Validate and convert userId
        int userId;
        try {
            userId = Integer.parseInt(userIdStr);
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
            return;
        }
        
        RedshiftDataClient redshiftClient = RedshiftDataClient.builder().build();
        
        // Using parameterized query
        String query = "INSERT INTO user_sessions (user_id, cookie) VALUES (?, ?)";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .clusterIdentifier("my-cluster")
            .database("my-database")
            .sql(query)
            .parameters(userId, cookie)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = redshiftClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        
        // Validate email format
        if (!email.matches("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid email format");
            return;
        }
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        // Using parameterized query
        String statement = "DELETE FROM Users WHERE email = ?";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .statement(statement)
            .parameters(email)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse executeStatementResponse = dynamoDbClient.executeStatement(executeStatementRequest);
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String startDate = request.getParameter("startDate");
        String endDate = request.getParameter("endDate");
        String userType = request.getParameter("userType");
        
        // Validate date format
        if (!startDate.matches("\\d{4}-\\d{2}-\\d{2}") || !endDate.matches("\\d{4}-\\d{2}-\\d{2}")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid date format. Use YYYY-MM-DD");
            return;
        }
        
        // Validate user type against whitelist
        List<String> validUserTypes = List.of("admin", "user", "guest");
        if (!validUserTypes.contains(userType)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user type");
            return;
        }
        
        RdsDataClient rdsDataClient = RdsDataClient.builder().build();
        
        List<SqlParameter> parameters = new ArrayList<>();
        parameters.add(SqlParameter.builder().name("startDate").value(startDate).build());
        parameters.add(SqlParameter.builder().name("endDate").value(endDate).build());
        parameters.add(SqlParameter.builder().name("userType").value(userType).build());
        
        String sql = "SELECT COUNT(*) FROM user_logins WHERE login_date BETWEEN :startDate AND :endDate AND user_type = :userType";
        
        ExecuteStatementRequest executeStatementRequest = ExecuteStatementRequest.builder()
            .resourceArn("arn:aws:rds:us-east-1:123456789012:cluster:my-cluster")
            .secretArn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret")
            .sql(sql)
            .parameters(parameters)
            .build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse result = rdsDataClient.executeStatement(executeStatementRequest);
    }
}
// {/fact}