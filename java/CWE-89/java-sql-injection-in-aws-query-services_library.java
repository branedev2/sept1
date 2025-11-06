import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import software.amazon.awssdk.services.athena.AthenaClient;
import software.amazon.awssdk.services.athena.model.*;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.redshift.RedshiftClient;
import software.amazon.awssdk.services.redshift.model.*;
import software.amazon.awssdk.services.redshiftdata.RedshiftDataClient;
import software.amazon.awssdk.services.redshiftdata.model.*;
import software.amazon.awssdk.services.timestream.TimestreamQueryClient;
import software.amazon.awssdk.services.timestream.model.*;
import software.amazon.awssdk.services.qldb.QldbSessionClient;
import software.amazon.awssdk.services.qldb.model.*;
import software.amazon.awssdk.services.neptune.NeptuneClient;
import software.amazon.awssdk.services.neptune.model.*;
import com.amazonaws.services.athena.AmazonAthena;
import com.amazonaws.services.athena.AmazonAthenaClientBuilder;
import com.amazonaws.services.athena.model.StartQueryExecutionRequest;
import com.amazonaws.services.athena.model.StartQueryExecutionResult;
import com.amazonaws.services.redshift.AmazonRedshift;
import com.amazonaws.services.redshift.AmazonRedshiftClientBuilder;
import com.amazonaws.services.redshiftdata.AmazonRedshiftData;
import com.amazonaws.services.redshiftdata.AmazonRedshiftDataClientBuilder;
import com.amazonaws.services.redshiftdata.model.ExecuteStatementRequest;
import com.amazonaws.services.timestreamquery.AmazonTimestreamQuery;
import com.amazonaws.services.timestreamquery.AmazonTimestreamQueryClientBuilder;
import com.amazonaws.services.timestreamquery.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Table;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import spark.Request;
import spark.Response;
import spark.Spark;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.container.ContainerRequestContext;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.quarkus.vertx.web.Route;
import io.vertx.ext.web.RoutingContext;
import ratpack.handling.Handler;
import ratpack.handling.Context;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http.Request;

// Security Issue: SQL Injection in AWS Query Services

// True Positive Examples (Vulnerable/Insecure Code)
class SqlInjectionInAwsQueryServices {

// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Using AWS SDK v2 Athena client with user input directly in query
        String userId = request.getParameter("userId");
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        String query = "SELECT * FROM user_data WHERE user_id = '" + userId + "'";
        
        // ruleid: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse response = athenaClient.startQueryExecution(
            StartQueryExecutionRequest.builder()
                .queryString(query)
                .build());
    }

    public void bad_case_2(HttpServletRequest request) {
        // Using AWS SDK v1 Athena client with user input directly in query
        String tableName = request.getParameter("table");
        AmazonAthena athenaClient = AmazonAthenaClientBuilder.standard().build();
        
        String query = "SELECT * FROM " + tableName + " LIMIT 10";
        
        // ruleid: java-sql-injection-in-aws-query-services
        StartQueryExecutionResult result = athenaClient.startQueryExecution(
            new StartQueryExecutionRequest()
                .withQueryString(query));
    }

    public void bad_case_3(HttpServletRequest request) {
        // Using AWS SDK v2 Redshift Data API with user input directly in query
        String columnName = request.getParameter("column");
        RedshiftDataClient redshiftDataClient = RedshiftDataClient.builder().build();
        
        String sql = "SELECT " + columnName + " FROM customers";
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse response = redshiftDataClient.executeStatement(
            ExecuteStatementRequest.builder()
                .clusterIdentifier("my-cluster")
                .database("dev")
                .sql(sql)
                .build());
    }

    public void bad_case_4(HttpServletRequest request) {
        // Using AWS SDK v1 Redshift Data API with user input directly in query
        String condition = request.getParameter("condition");
        AmazonRedshiftData redshiftDataClient = AmazonRedshiftDataClientBuilder.standard().build();
        
        String sql = "SELECT * FROM orders WHERE " + condition;
        
        // ruleid: java-sql-injection-in-aws-query-services
        redshiftDataClient.executeStatement(new ExecuteStatementRequest()
            .withClusterIdentifier("my-cluster")
            .withDatabase("dev")
            .withSql(sql));
    }

    public void bad_case_5(@Context ContainerRequestContext requestContext) {
        // Using AWS SDK v2 Timestream Query with user input directly in query
        String userFilter = requestContext.getUriInfo().getQueryParameters().getFirst("filter");
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        String query = "SELECT * FROM metrics WHERE " + userFilter;
        
        // ruleid: java-sql-injection-in-aws-query-services
        QueryResponse response = timestreamClient.query(
            QueryRequest.builder()
                .queryString(query)
                .build());
    }

    public void bad_case_6(org.springframework.web.bind.annotation.RequestParam String whereClause) {
        // Using AWS SDK v1 Timestream Query with Spring MVC RequestParam
        AmazonTimestreamQuery timestreamClient = AmazonTimestreamQueryClientBuilder.standard().build();
        
        String query = "SELECT time, measure_value FROM metrics WHERE " + whereClause;
        
        // ruleid: java-sql-injection-in-aws-query-services
        timestreamClient.query(new QueryRequest().withQueryString(query));
    }

    public void bad_case_7(spark.Request request) {
        // Using AWS SDK v2 DynamoDB PartiQL with Spark framework
        String userValue = request.queryParams("value");
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        String statement = "SELECT * FROM Products WHERE price > " + userValue;
        
        // ruleid: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse response = dynamoDbClient.executeStatement(
            ExecuteStatementRequest.builder()
                .statement(statement)
                .build());
    }

    public void bad_case_8(HttpExchange exchange) throws IOException {
        // Using AWS SDK v2 Neptune with Java's built-in HttpServer
        String query = exchange.getRequestURI().getQuery();
        String gremlinQuery = "g.V().has('name', '" + query + "').out()";
        
        // ruleid: java-sql-injection-in-aws-query-services
        NeptuneClient neptuneClient = NeptuneClient.builder().build();
        neptuneClient.executeGremlinQuery(b -> b.queryString(gremlinQuery));
    }

    public void bad_case_9(io.javalin.http.Context ctx) {
        // Using AWS SDK v2 QLDB with Javalin framework
        String documentId = ctx.queryParam("docId");
        QldbSessionClient qldbClient = QldbSessionClient.builder().build();
        
        String query = "SELECT * FROM Vehicle WHERE VIN = '" + documentId + "'";
        
        // ruleid: java-sql-injection-in-aws-query-services
        SendCommandResponse response = qldbClient.sendCommand(
            SendCommandRequest.builder()
                .startSession(StartSessionRequest.builder().build())
                .executeStatement(ExecuteStatementRequest.builder()
                    .statement(query)
                    .build())
                .build());
    }

    public void bad_case_10(io.micronaut.http.HttpRequest<?> request) {
        // Using AWS SDK v1 Redshift with Micronaut framework
        String tableName = request.getParameters().get("table");
        AmazonRedshift redshiftClient = AmazonRedshiftClientBuilder.standard().build();
        
        String query = "CREATE TABLE " + tableName + " (id INT, name VARCHAR(100))";
        
        // ruleid: java-sql-injection-in-aws-query-services
        redshiftClient.executeQuery(new com.amazonaws.services.redshift.model.ExecuteQueryRequest()
            .withClusterIdentifier("my-cluster")
            .withQuery(query));
    }

    @Route(path = "/query")
    public void bad_case_11(RoutingContext routingContext) {
        // Using AWS SDK v2 Athena with Quarkus Vert.x
        String column = routingContext.request().getParam("column");
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        String query = "SELECT " + column + " FROM users GROUP BY " + column;
        
        // ruleid: java-sql-injection-in-aws-query-services
        athenaClient.startQueryExecution(b -> b.queryString(query));
    }

    public void bad_case_12(ratpack.handling.Context ctx) {
        // Using AWS SDK v1 Athena with Ratpack framework
        String orderBy = ctx.getRequest().getQueryParams().get("orderBy");
        AmazonAthena athenaClient = AmazonAthenaClientBuilder.standard().build();
        
        String query = "SELECT * FROM sales ORDER BY " + orderBy;
        
        // ruleid: java-sql-injection-in-aws-query-services
        athenaClient.startQueryExecution(
            new StartQueryExecutionRequest().withQueryString(query));
    }

    public Result bad_case_13(play.mvc.Http.Request request) {
        // Using AWS SDK v2 Redshift Data API with Play framework
        String joinCondition = request.getQueryString("join");
        RedshiftDataClient redshiftDataClient = RedshiftDataClient.builder().build();
        
        String sql = "SELECT * FROM orders o JOIN customers c ON " + joinCondition;
        
        // ruleid: java-sql-injection-in-aws-query-services
        redshiftDataClient.executeStatement(b -> b
            .clusterIdentifier("my-cluster")
            .database("dev")
            .sql(sql));
        
        return play.mvc.Results.ok("Query executed");
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        // Using AWS SDK v1 DynamoDB PartiQL with servlet API
        String userInput = request.getHeader("X-Search-Term");
        AmazonDynamoDB amazonDynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(amazonDynamoDB);
        
        String statement = "SELECT * FROM Movies WHERE title LIKE '%" + userInput + "%'";
        
        // ruleid: java-sql-injection-in-aws-query-services
        dynamoDB.getTable("Movies").executeQuery(statement);
    }

    public void bad_case_15(HttpServletRequest request) {
        // Using AWS SDK v2 Timestream Query with servlet API and request body
        BufferedReader reader;
        StringBuilder requestBody = new StringBuilder();
        try {
            reader = request.getReader();
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        String userCondition = requestBody.toString();
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        String query = "SELECT * FROM metrics WHERE " + userCondition;
        
        // ruleid: java-sql-injection-in-aws-query-services
        timestreamClient.query(QueryRequest.builder().queryString(query).build());
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        // Using AWS SDK v2 Athena with parameterized query
        String userId = request.getParameter("userId");
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        Map<String, String> parameters = new HashMap<>();
        parameters.put("userId", userId);
        
        // ok: java-sql-injection-in-aws-query-services
        StartQueryExecutionResponse response = athenaClient.startQueryExecution(
            StartQueryExecutionRequest.builder()
                .queryString("SELECT * FROM user_data WHERE user_id = :userId")
                .executionParameters(Arrays.asList(userId))
                .build());
    }

    public void good_case_2(HttpServletRequest request) {
        // Using AWS SDK v1 Athena with input validation
        String tableName = request.getParameter("table");
        AmazonAthena athenaClient = AmazonAthenaClientBuilder.standard().build();
        
        // Validate table name against whitelist
        List<String> allowedTables = Arrays.asList("users", "orders", "products");
        if (!allowedTables.contains(tableName)) {
            tableName = "users"; // Default to safe value
        }
        
        // ok: java-sql-injection-in-aws-query-services
        StartQueryExecutionResult result = athenaClient.startQueryExecution(
            new StartQueryExecutionRequest()
                .withQueryString("SELECT * FROM " + tableName + " LIMIT 10"));
    }

    public void good_case_3(HttpServletRequest request) {
        // Using AWS SDK v2 Redshift Data API with prepared statements
        String userId = request.getParameter("userId");
        RedshiftDataClient redshiftDataClient = RedshiftDataClient.builder().build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse response = redshiftDataClient.executeStatement(
            ExecuteStatementRequest.builder()
                .clusterIdentifier("my-cluster")
                .database("dev")
                .sql("SELECT * FROM customers WHERE customer_id = ?")
                .parameters(Arrays.asList(userId))
                .build());
    }

    public void good_case_4(HttpServletRequest request) {
        // Using AWS SDK v1 Redshift Data API with prepared statements
        String orderId = request.getParameter("orderId");
        AmazonRedshiftData redshiftDataClient = AmazonRedshiftDataClientBuilder.standard().build();
        
        // ok: java-sql-injection-in-aws-query-services
        redshiftDataClient.executeStatement(new ExecuteStatementRequest()
            .withClusterIdentifier("my-cluster")
            .withDatabase("dev")
            .withSql("SELECT * FROM orders WHERE order_id = ?")
            .withParameters(Arrays.asList(orderId)));
    }

    public void good_case_5(@Context ContainerRequestContext requestContext) {
        // Using AWS SDK v2 Timestream Query with input sanitization
        String userFilter = requestContext.getUriInfo().getQueryParameters().getFirst("filter");
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        // Sanitize input by only allowing specific patterns
        if (!userFilter.matches("^[a-zA-Z0-9_]+$")) {
            userFilter = "default_metric";
        }
        
        // ok: java-sql-injection-in-aws-query-services
        QueryResponse response = timestreamClient.query(
            QueryRequest.builder()
                .queryString("SELECT * FROM metrics WHERE metric_name = '" + userFilter + "'")
                .build());
    }

    public void good_case_6(@org.springframework.web.bind.annotation.RequestParam String metricType) {
        // Using AWS SDK v1 Timestream Query with Spring MVC and input validation
        AmazonTimestreamQuery timestreamClient = AmazonTimestreamQueryClientBuilder.standard().build();
        
        // Validate against allowed values
        Set<String> allowedMetrics = new HashSet<>(Arrays.asList("cpu", "memory", "disk", "network"));
        if (!allowedMetrics.contains(metricType)) {
            metricType = "cpu"; // Default to safe value
        }
        
        // ok: java-sql-injection-in-aws-query-services
        timestreamClient.query(new QueryRequest()
            .withQueryString("SELECT time, measure_value FROM metrics WHERE metric_type = '" + metricType + "'"));
    }

    public void good_case_7(spark.Request request) {
        // Using AWS SDK v2 DynamoDB PartiQL with prepared statements
        String userValue = request.queryParams("value");
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        // ok: java-sql-injection-in-aws-query-services
        ExecuteStatementResponse response = dynamoDbClient.executeStatement(
            ExecuteStatementRequest.builder()
                .statement("SELECT * FROM Products WHERE price > ?")
                .parameters(Collections.singletonList(
                    AttributeValue.builder().n(userValue).build()))
                .build());
    }

    public void good_case_8(HttpExchange exchange) throws IOException {
        // Using AWS SDK v2 Neptune with input sanitization
        String query = exchange.getRequestURI().getQuery();
        
        // Sanitize input
        query = query.replaceAll("[^a-zA-Z0-9]", "");
        
        // ok: java-sql-injection-in-aws-query-services
        NeptuneClient neptuneClient = NeptuneClient.builder().build();
        neptuneClient.executeGremlinQuery(b -> b.queryString("g.V().has('name', '" + query + "').out()"));
    }

    public void good_case_9(io.javalin.http.Context ctx) {
        // Using AWS SDK v2 QLDB with prepared statements
        String documentId = ctx.queryParam("docId");
        QldbSessionClient qldbClient = QldbSessionClient.builder().build();
        
        // ok: java-sql-injection-in-aws-query-services
        SendCommandResponse response = qldbClient.sendCommand(
            SendCommandRequest.builder()
                .startSession(StartSessionRequest.builder().build())
                .executeStatement(ExecuteStatementRequest.builder()
                    .statement("SELECT * FROM Vehicle WHERE VIN = ?")
                    .parameters(Collections.singletonList(
                        software.amazon.awssdk.services.qldb.model.Value.builder()
                            .stringValue(documentId)
                            .build()))
                    .build())
                .build());
    }

    public void good_case_10(io.micronaut.http.HttpRequest<?> request) {
        // Using AWS SDK v1 Redshift with input validation
        String tableName = request.getParameters().get("table");
        AmazonRedshift redshiftClient = AmazonRedshiftClientBuilder.standard().build();
        
        // Validate table name format
        if (!tableName.matches("^[a-zA-Z][a-zA-Z0-9_]*$")) {
            tableName = "default_table";
        }
        
        // ok: java-sql-injection-in-aws-query-services
        redshiftClient.executeQuery(new com.amazonaws.services.redshift.model.ExecuteQueryRequest()
            .withClusterIdentifier("my-cluster")
            .withQuery("CREATE TABLE " + tableName + " (id INT, name VARCHAR(100))"));
    }

    @Route(path = "/query")
    public void good_case_11(RoutingContext routingContext) {
        // Using AWS SDK v2 Athena with whitelist validation
        String column = routingContext.request().getParam("column");
        AthenaClient athenaClient = AthenaClient.builder().build();
        
        // Validate column against whitelist
        Set<String> allowedColumns = new HashSet<>(Arrays.asList("user_id", "username", "email", "created_at"));
        if (!allowedColumns.contains(column)) {
            column = "user_id"; // Default to safe value
        }
        
        // ok: java-sql-injection-in-aws-query-services
        athenaClient.startQueryExecution(b -> b.queryString("SELECT " + column + " FROM users GROUP BY " + column));
    }

    public void good_case_12(ratpack.handling.Context ctx) {
        // Using AWS SDK v1 Athena with input validation
        String orderBy = ctx.getRequest().getQueryParams().get("orderBy");
        AmazonAthena athenaClient = AmazonAthenaClientBuilder.standard().build();
        
        // Validate orderBy column
        Map<String, String> allowedOrderByColumns = new HashMap<>();
        allowedOrderByColumns.put("date", "sale_date");
        allowedOrderByColumns.put("amount", "sale_amount");
        allowedOrderByColumns.put("region", "sale_region");
        
        String validatedColumn = allowedOrderByColumns.getOrDefault(orderBy, "sale_date");
        
        // ok: java-sql-injection-in-aws-query-services
        athenaClient.startQueryExecution(
            new StartQueryExecutionRequest().withQueryString("SELECT * FROM sales ORDER BY " + validatedColumn));
    }

    public Result good_case_13(play.mvc.Http.Request request) {
        // Using AWS SDK v2 Redshift Data API with Play framework and prepared statements
        String customerId = request.getQueryString("customerId");
        RedshiftDataClient redshiftDataClient = RedshiftDataClient.builder().build();
        
        // ok: java-sql-injection-in-aws-query-services
        redshiftDataClient.executeStatement(b -> b
            .clusterIdentifier("my-cluster")
            .database("dev")
            .sql("SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id WHERE c.id = ?")
            .parameters(Arrays.asList(customerId)));
        
        return play.mvc.Results.ok("Query executed");
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        // Using AWS SDK v1 DynamoDB PartiQL with prepared statements
        String userInput = request.getHeader("X-Search-Term");
        AmazonDynamoDB amazonDynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(amazonDynamoDB);
        
        // ok: java-sql-injection-in-aws-query-services
        dynamoDB.getTable("Movies").executeQuery(
            "SELECT * FROM Movies WHERE title LIKE ?",
            Collections.singletonList("%" + userInput + "%"));
    }

    public void good_case_15(HttpServletRequest request) {
        // Using AWS SDK v2 Timestream Query with parameterized queries
        BufferedReader reader;
        StringBuilder requestBody = new StringBuilder();
        try {
            reader = request.getReader();
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        String metricValue = requestBody.toString();
        TimestreamQueryClient timestreamClient = TimestreamQueryClient.builder().build();
        
        // ok: java-sql-injection-in-aws-query-services
        timestreamClient.query(QueryRequest.builder()
            .queryString("SELECT * FROM metrics WHERE value > ?")
            .parameters(Collections.singletonList(
                software.amazon.awssdk.services.timestream.model.QueryParameter.builder()
                    .name("param1")
                    .value(software.amazon.awssdk.services.timestream.model.Datum.builder()
                        .scalarValue(metricValue)
                        .build())
                    .type("DOUBLE")
                    .build()))
            .build());
    }
}
// {/fact}