import com.amazonaws.services.stepfunctions.AWSStepFunctions;
import com.amazonaws.services.stepfunctions.AWSStepFunctionsClientBuilder;
import com.amazonaws.services.stepfunctions.model.*;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.*;
import software.amazon.awssdk.services.sfn.SfnClient;
import software.amazon.awssdk.services.sfn.model.*;
import software.amazon.awssdk.regions.Region;
import org.json.JSONObject;
import org.json.simple.JSONValue;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import spark.Request;
import spark.Response;
import io.javalin.http.Context;
import io.vertx.ext.web.RoutingContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.quarkus.vertx.web.Route;
import ratpack.handling.Context;
import java.util.HashMap;
import java.util.Map;

// Security Issue: Improper file reference in AWS Step Functions input where key names should end with ".$" for file references

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Create input for state machine with improper file reference
    String input = "{\"fileReference\": {\"filePath\": \"" + filePath + "\"}}";
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startExecutionRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine")
        .withInput(input);
    
    stepFunctionsClient.startExecution(startExecutionRequest);
}

public void bad_case_2(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using AWS SDK v2 with improper file reference
    String inputJson = "{\"document\": {\"path\": \"" + filePath + "\"}}";
    
    // ruleid: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DocumentProcessor")
            .input(inputJson)
            .build();
    
    sfnClient.startExecution(request);
}

public void bad_case_3(@RequestBody Map<String, String> payload) {
    String filePath = payload.get("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using org.json library with improper file reference
    JSONObject inputJson = new JSONObject();
    JSONObject fileRef = new JSONObject();
    fileRef.put("location", filePath);
    inputJson.put("inputFile", fileRef);
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

public void bad_case_4(spark.Request request) {
    String filePath = request.queryParams("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using Gson library with improper file reference
    Gson gson = new Gson();
    Map<String, Object> inputMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    fileMap.put("s3Location", filePath);
    inputMap.put("sourceFile", fileMap);
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:S3Processor")
        .withInput(gson.toJson(inputMap));
    
    stepFunctionsClient.startExecution(startRequest);
}

public void bad_case_5(io.javalin.http.Context ctx) {
    String filePath = ctx.queryParam("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using Jackson library with improper file reference
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode rootNode = mapper.createObjectNode();
    ObjectNode fileNode = mapper.createObjectNode();
    fileNode.put("uri", filePath);
    rootNode.set("configFile", fileNode);
    
    try {
        // ruleid: java-step-function-input-file
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
            software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
                .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ConfigProcessor")
                .input(mapper.writeValueAsString(rootNode))
                .build();
        
        sfnClient.startExecution(request);
    } catch (Exception e) {
        ctx.status(500);
    }
}

public void bad_case_6(io.vertx.ext.web.RoutingContext routingContext) {
    String filePath = routingContext.request().getParam("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using simple string concatenation with improper file reference
    String input = "{"
        + "\"dataFile\": {"
        + "\"location\": \"" + filePath + "\""
        + "}"
        + "}";
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataProcessor")
        .withInput(input);
    
    stepFunctionsClient.startExecution(startRequest);
}

public void bad_case_7(io.micronaut.http.HttpRequest<?> request) {
    String filePath = request.getParameters().get("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using org.json.simple with improper file reference
    Map<String, Object> inputMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    fileMap.put("path", filePath);
    inputMap.put("inputDocument", fileMap);
    
    // ruleid: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DocumentProcessor")
            .input(JSONValue.toJSONString(inputMap))
            .build();
    
    sfnClient.startExecution(request);
}

public void bad_case_8(ratpack.handling.Context ctx) {
    ctx.getRequest().getQueryParams().get("filePath").then(filePath -> {
        AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
        
        // Using StringBuilder with improper file reference
        StringBuilder inputBuilder = new StringBuilder();
        inputBuilder.append("{\"reportFile\": {\"s3Key\": \"");
        inputBuilder.append(filePath);
        inputBuilder.append("\"}}");
        
        // ruleid: java-step-function-input-file
        StartExecutionRequest startRequest = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ReportGenerator")
            .withInput(inputBuilder.toString());
        
        stepFunctionsClient.startExecution(startRequest);
    });
}

public void bad_case_9(@RequestParam String filePath) {
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using JsonObject with improper file reference
    JsonObject inputJson = new JsonObject();
    JsonObject fileJson = new JsonObject();
    fileJson.addProperty("location", filePath);
    inputJson.add("archiveFile", fileJson);
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ArchiveProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

public void bad_case_10(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using Map and ObjectMapper with improper file reference
    Map<String, Object> inputMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    fileMap.put("key", filePath);
    inputMap.put("imageFile", fileMap);
    
    try {
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-step-function-input-file
        StartExecutionRequest startRequest = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ImageProcessor")
            .withInput(mapper.writeValueAsString(inputMap));
        
        stepFunctionsClient.startExecution(startRequest);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(spark.Request request) {
    String filePath = request.queryParams("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using nested maps with improper file reference
    Map<String, Object> rootMap = new HashMap<>();
    Map<String, Object> configMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    
    fileMap.put("path", filePath);
    configMap.put("settings", fileMap);
    rootMap.put("configuration", configMap);
    
    Gson gson = new Gson();
    // ruleid: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest sfnRequest = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ConfigurationProcessor")
            .input(gson.toJson(rootMap))
            .build();
    
    sfnClient.startExecution(sfnRequest);
}

public void bad_case_12(@RequestBody Map<String, String> payload) {
    String filePath = payload.get("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using String.format with improper file reference
    String input = String.format(
        "{\"logFile\": {\"location\": \"%s\"}}",
        filePath
    );
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:LogProcessor")
        .withInput(input);
    
    stepFunctionsClient.startExecution(startRequest);
}

public void bad_case_13(io.javalin.http.Context ctx) {
    String filePath = ctx.formParam("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using template literals with improper file reference
    String inputTemplate = """
        {
          "dataSource": {
            "filePath": "%s"
          }
        }
        """;
    
    String input = String.format(inputTemplate, filePath);
    
    // ruleid: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataSourceProcessor")
            .input(input)
            .build();
    
    sfnClient.startExecution(request);
}

public void bad_case_14(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using JSONObject chaining with improper file reference
    JSONObject inputJson = new JSONObject()
        .put("mediaFile", new JSONObject()
            .put("location", filePath));
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:MediaProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

public void bad_case_15(io.vertx.ext.web.RoutingContext routingContext) {
    String filePath = routingContext.request().getParam("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using multiple file references, all improper
    JSONObject inputJson = new JSONObject();
    JSONObject sourceFile = new JSONObject();
    JSONObject targetFile = new JSONObject();
    
    sourceFile.put("path", filePath + "/source");
    targetFile.put("path", filePath + "/target");
    
    inputJson.put("source", sourceFile);
    inputJson.put("target", targetFile);
    
    // ruleid: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileTransferProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Create input for state machine with proper file reference (ending with .$)
    String input = "{\"fileReference\": {\"filePath.$\": \"" + filePath + "\"}}";
    
    // ok: java-step-function-input-file
    StartExecutionRequest startExecutionRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine")
        .withInput(input);
    
    stepFunctionsClient.startExecution(startExecutionRequest);
}

public void good_case_2(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using AWS SDK v2 with proper file reference
    String inputJson = "{\"document\": {\"path.$\": \"" + filePath + "\"}}";
    
    // ok: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DocumentProcessor")
            .input(inputJson)
            .build();
    
    sfnClient.startExecution(request);
}

public void good_case_3(@RequestBody Map<String, String> payload) {
    String filePath = payload.get("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using org.json library with proper file reference
    JSONObject inputJson = new JSONObject();
    JSONObject fileRef = new JSONObject();
    fileRef.put("location.$", filePath);
    inputJson.put("inputFile", fileRef);
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

public void good_case_4(spark.Request request) {
    String filePath = request.queryParams("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using Gson library with proper file reference
    Gson gson = new Gson();
    Map<String, Object> inputMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    fileMap.put("s3Location.$", filePath);
    inputMap.put("sourceFile", fileMap);
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:S3Processor")
        .withInput(gson.toJson(inputMap));
    
    stepFunctionsClient.startExecution(startRequest);
}

public void good_case_5(io.javalin.http.Context ctx) {
    String filePath = ctx.queryParam("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using Jackson library with proper file reference
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode rootNode = mapper.createObjectNode();
    ObjectNode fileNode = mapper.createObjectNode();
    fileNode.put("uri.$", filePath);
    rootNode.set("configFile", fileNode);
    
    try {
        // ok: java-step-function-input-file
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
            software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
                .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ConfigProcessor")
                .input(mapper.writeValueAsString(rootNode))
                .build();
        
        sfnClient.startExecution(request);
    } catch (Exception e) {
        ctx.status(500);
    }
}

public void good_case_6(io.vertx.ext.web.RoutingContext routingContext) {
    String filePath = routingContext.request().getParam("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using simple string concatenation with proper file reference
    String input = "{"
        + "\"dataFile\": {"
        + "\"location.$\": \"" + filePath + "\""
        + "}"
        + "}";
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataProcessor")
        .withInput(input);
    
    stepFunctionsClient.startExecution(startRequest);
}

public void good_case_7(io.micronaut.http.HttpRequest<?> request) {
    String filePath = request.getParameters().get("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using org.json.simple with proper file reference
    Map<String, Object> inputMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    fileMap.put("path.$", filePath);
    inputMap.put("inputDocument", fileMap);
    
    // ok: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DocumentProcessor")
            .input(JSONValue.toJSONString(inputMap))
            .build();
    
    sfnClient.startExecution(request);
}

public void good_case_8(ratpack.handling.Context ctx) {
    ctx.getRequest().getQueryParams().get("filePath").then(filePath -> {
        AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
        
        // Using StringBuilder with proper file reference
        StringBuilder inputBuilder = new StringBuilder();
        inputBuilder.append("{\"reportFile\": {\"s3Key.$\": \"");
        inputBuilder.append(filePath);
        inputBuilder.append("\"}}");
        
        // ok: java-step-function-input-file
        StartExecutionRequest startRequest = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ReportGenerator")
            .withInput(inputBuilder.toString());
        
        stepFunctionsClient.startExecution(startRequest);
    });
}

public void good_case_9(@RequestParam String filePath) {
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using JsonObject with proper file reference
    JsonObject inputJson = new JsonObject();
    JsonObject fileJson = new JsonObject();
    fileJson.addProperty("location.$", filePath);
    inputJson.add("archiveFile", fileJson);
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ArchiveProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

public void good_case_10(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using Map and ObjectMapper with proper file reference
    Map<String, Object> inputMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    fileMap.put("key.$", filePath);
    inputMap.put("imageFile", fileMap);
    
    try {
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-step-function-input-file
        StartExecutionRequest startRequest = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ImageProcessor")
            .withInput(mapper.writeValueAsString(inputMap));
        
        stepFunctionsClient.startExecution(startRequest);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(spark.Request request) {
    String filePath = request.queryParams("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using nested maps with proper file reference
    Map<String, Object> rootMap = new HashMap<>();
    Map<String, Object> configMap = new HashMap<>();
    Map<String, String> fileMap = new HashMap<>();
    
    fileMap.put("path.$", filePath);
    configMap.put("settings", fileMap);
    rootMap.put("configuration", configMap);
    
    Gson gson = new Gson();
    // ok: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest sfnRequest = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ConfigurationProcessor")
            .input(gson.toJson(rootMap))
            .build();
    
    sfnClient.startExecution(sfnRequest);
}

public void good_case_12(@RequestBody Map<String, String> payload) {
    String filePath = payload.get("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using String.format with proper file reference
    String input = String.format(
        "{\"logFile\": {\"location.$\": \"%s\"}}",
        filePath
    );
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:LogProcessor")
        .withInput(input);
    
    stepFunctionsClient.startExecution(startRequest);
}

public void good_case_13(io.javalin.http.Context ctx) {
    String filePath = ctx.formParam("filePath");
    SfnClient sfnClient = SfnClient.builder().region(Region.US_EAST_1).build();
    
    // Using template literals with proper file reference
    String inputTemplate = """
        {
          "dataSource": {
            "filePath.$": "%s"
          }
        }
        """;
    
    String input = String.format(inputTemplate, filePath);
    
    // ok: java-step-function-input-file
    software.amazon.awssdk.services.sfn.model.StartExecutionRequest request = 
        software.amazon.awssdk.services.sfn.model.StartExecutionRequest.builder()
            .stateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataSourceProcessor")
            .input(input)
            .build();
    
    sfnClient.startExecution(request);
}

public void good_case_14(HttpServletRequest request) {
    String filePath = request.getParameter("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using JSONObject chaining with proper file reference
    JSONObject inputJson = new JSONObject()
        .put("mediaFile", new JSONObject()
            .put("location.$", filePath));
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:MediaProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}

public void good_case_15(io.vertx.ext.web.RoutingContext routingContext) {
    String filePath = routingContext.request().getParam("filePath");
    AWSStepFunctions stepFunctionsClient = AWSStepFunctionsClientBuilder.standard().build();
    
    // Using multiple file references, all proper
    JSONObject inputJson = new JSONObject();
    JSONObject sourceFile = new JSONObject();
    JSONObject targetFile = new JSONObject();
    
    sourceFile.put("path.$", filePath + "/source");
    targetFile.put("path.$", filePath + "/target");
    
    inputJson.put("source", sourceFile);
    inputJson.put("target", targetFile);
    
    // ok: java-step-function-input-file
    StartExecutionRequest startRequest = new StartExecutionRequest()
        .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileTransferProcessor")
        .withInput(inputJson.toString());
    
    stepFunctionsClient.startExecution(startRequest);
}