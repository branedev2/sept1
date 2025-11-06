import com.amazonaws.services.stepfunctions.AmazonStepFunctions;
import com.amazonaws.services.stepfunctions.AmazonStepFunctionsClientBuilder;
import com.amazonaws.services.stepfunctions.model.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.HashMap;
import java.util.Map;
import java.io.File;
import java.nio.file.Paths;

public class StepFunctionInputFileExamples {

    // True Positive Examples (Vulnerable)

// {fact rule=improper-input-validation@v1.0 defects=1}
    public void bad_case_1() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        input.put("inputFile", "s3://my-bucket/input.json");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine")
            .withInput(input.toString());
        
        client.startExecution(request);
    }

    public void bad_case_2() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        Map<String, String> inputMap = new HashMap<>();
        // ruleid: java-step-function-input-file
        inputMap.put("configFile", "file:///tmp/config.json");
        
        String input = new ObjectMapper().writeValueAsString(inputMap);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataProcessor")
            .withInput(input);
        
        client.startExecution(request);
    }

    public void bad_case_3() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode payload = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        payload.put("dataPath", "s3://data-bucket/users/data.csv");
        payload.put("processType", "full");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-west-2:123456789012:stateMachine:DataProcessor")
            .withInput(payload.toString());
        
        sfn.startExecution(request);
    }

    public void bad_case_4() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        String filePath = "s3://analytics-bucket/reports/daily-report.json";
        Map<String, Object> inputMap = new HashMap<>();
        // ruleid: java-step-function-input-file
        inputMap.put("reportFile", filePath);
        inputMap.put("generateSummary", true);
        
        String input = new ObjectMapper().writeValueAsString(inputMap);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ReportGenerator")
            .withInput(input);
        
        stepFunctions.startExecution(request);
    }

    public void bad_case_5() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        ObjectNode fileConfig = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        fileConfig.put("source", "file:///app/data/source.json");
        input.set("fileConfig", fileConfig);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileProcessor")
            .withInput(input.toString());
        
        client.startExecution(request);
    }

    public void bad_case_6() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        Map<String, Object> inputData = new HashMap<>();
        Map<String, String> fileInfo = new HashMap<>();
        // ruleid: java-step-function-input-file
        fileInfo.put("inputPath", "s3://input-bucket/data.json");
        fileInfo.put("format", "json");
        inputData.put("fileInfo", fileInfo);
        
        String input = new ObjectMapper().writeValueAsString(inputData);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataTransformer")
            .withInput(input);
        
        sfn.startExecution(request);
    }

    public void bad_case_7() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        input.put("templateFile", "s3://templates/email-template.html");
        input.put("sendTo", "user@example.com");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:EmailSender")
            .withInput(input.toString());
        
        stepFunctions.startExecution(request);
    }

    public void bad_case_8() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        String s3Path = "s3://config-bucket/app-config.yaml";
        Map<String, Object> params = new HashMap<>();
        // ruleid: java-step-function-input-file
        params.put("configurationFile", s3Path);
        params.put("environment", "production");
        
        String input = new ObjectMapper().writeValueAsString(params);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ConfigDeployer")
            .withInput(input);
        
        client.startExecution(request);
    }

    public void bad_case_9() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ObjectNode files = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        files.put("schema", "file:///app/schemas/customer.json");
        // ruleid: java-step-function-input-file
        files.put("data", "s3://customer-data/latest.csv");
        rootNode.set("files", files);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataValidator")
            .withInput(rootNode.toString());
        
        sfn.startExecution(request);
    }

    public void bad_case_10() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        Map<String, Object> input = new HashMap<>();
        // ruleid: java-step-function-input-file
        input.put("imageFile", "s3://images/profile.jpg");
        input.put("width", 300);
        input.put("height", 300);
        
        String inputJson = new ObjectMapper().writeValueAsString(input);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ImageResizer")
            .withInput(inputJson);
        
        stepFunctions.startExecution(request);
    }

    public void bad_case_11() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        ObjectNode processingConfig = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        processingConfig.put("logFile", "file:///var/log/app.log");
        input.set("processingConfig", processingConfig);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:LogProcessor")
            .withInput(input.toString());
        
        client.startExecution(request);
    }

    public void bad_case_12() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> fileParams = new HashMap<>();
        // ruleid: java-step-function-input-file
        fileParams.put("inputFile", "s3://data-lake/raw/2023-01-01.json");
        fileParams.put("outputFormat", "parquet");
        params.put("fileParams", fileParams);
        
        String input = new ObjectMapper().writeValueAsString(params);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataConverter")
            .withInput(input);
        
        sfn.startExecution(request);
    }

    public void bad_case_13() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        input.put("backupFile", "s3://backups/database-2023-01-01.bak");
        input.put("restoreTarget", "prod-db-instance");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DatabaseRestorer")
            .withInput(input.toString());
        
        stepFunctions.startExecution(request);
    }

    public void bad_case_14() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        Map<String, String> inputMap = new HashMap<>();
        // ruleid: java-step-function-input-file
        inputMap.put("scriptPath", "file:///app/scripts/process.py");
        inputMap.put("arguments", "--verbose --no-cache");
        
        String input = new ObjectMapper().writeValueAsString(inputMap);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ScriptRunner")
            .withInput(input);
        
        client.startExecution(request);
    }

    public void bad_case_15() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        ObjectNode sources = mapper.createObjectNode();
        // ruleid: java-step-function-input-file
        sources.put("primary", "s3://primary-data/latest.csv");
        // ruleid: java-step-function-input-file
        sources.put("reference", "s3://reference-data/lookup.json");
        input.set("dataSources", sources);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataMerger")
            .withInput(input.toString());
        
        sfn.startExecution(request);
    }

    // True Negative Examples (Safe)

    public void good_case_1() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        // ok: java-step-function-input-file
        input.put("inputFile.$", "s3://my-bucket/input.json");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine")
            .withInput(input.toString());
        
        client.startExecution(request);
    }

    public void good_case_2() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        Map<String, String> inputMap = new HashMap<>();
        // ok: java-step-function-input-file
        inputMap.put("configFile.$", "file:///tmp/config.json");
        
        String input = new ObjectMapper().writeValueAsString(inputMap);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataProcessor")
            .withInput(input);
        
        client.startExecution(request);
    }

    public void good_case_3() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode payload = mapper.createObjectNode();
        // ok: java-step-function-input-file
        payload.put("dataPath.$", "s3://data-bucket/users/data.csv");
        payload.put("processType", "full");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-west-2:123456789012:stateMachine:DataProcessor")
            .withInput(payload.toString());
        
        sfn.startExecution(request);
    }

    public void good_case_4() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        String filePath = "s3://analytics-bucket/reports/daily-report.json";
        Map<String, Object> inputMap = new HashMap<>();
        // ok: java-step-function-input-file
        inputMap.put("reportFile.$", filePath);
        inputMap.put("generateSummary", true);
        
        String input = new ObjectMapper().writeValueAsString(inputMap);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ReportGenerator")
            .withInput(input);
        
        stepFunctions.startExecution(request);
    }

    public void good_case_5() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        ObjectNode fileConfig = mapper.createObjectNode();
        // ok: java-step-function-input-file
        fileConfig.put("source.$", "file:///app/data/source.json");
        input.set("fileConfig", fileConfig);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileProcessor")
            .withInput(input.toString());
        
        client.startExecution(request);
    }

    public void good_case_6() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        Map<String, Object> inputData = new HashMap<>();
        Map<String, String> fileInfo = new HashMap<>();
        // ok: java-step-function-input-file
        fileInfo.put("inputPath.$", "s3://input-bucket/data.json");
        fileInfo.put("format", "json");
        inputData.put("fileInfo", fileInfo);
        
        String input = new ObjectMapper().writeValueAsString(inputData);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataTransformer")
            .withInput(input);
        
        sfn.startExecution(request);
    }

    public void good_case_7() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        // ok: java-step-function-input-file
        input.put("templateFile.$", "s3://templates/email-template.html");
        input.put("sendTo", "user@example.com");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:EmailSender")
            .withInput(input.toString());
        
        stepFunctions.startExecution(request);
    }

    public void good_case_8() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        String s3Path = "s3://config-bucket/app-config.yaml";
        Map<String, Object> params = new HashMap<>();
        // ok: java-step-function-input-file
        params.put("configurationFile.$", s3Path);
        params.put("environment", "production");
        
        String input = new ObjectMapper().writeValueAsString(params);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ConfigDeployer")
            .withInput(input);
        
        client.startExecution(request);
    }

    public void good_case_9() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ObjectNode files = mapper.createObjectNode();
        // ok: java-step-function-input-file
        files.put("schema.$", "file:///app/schemas/customer.json");
        // ok: java-step-function-input-file
        files.put("data.$", "s3://customer-data/latest.csv");
        rootNode.set("files", files);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataValidator")
            .withInput(rootNode.toString());
        
        sfn.startExecution(request);
    }

    public void good_case_10() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        Map<String, Object> input = new HashMap<>();
        // ok: java-step-function-input-file
        input.put("imageFile.$", "s3://images/profile.jpg");
        input.put("width", 300);
        input.put("height", 300);
        
        String inputJson = new ObjectMapper().writeValueAsString(input);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:ImageResizer")
            .withInput(inputJson);
        
        stepFunctions.startExecution(request);
    }

    public void good_case_11() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        // This is a safe case because we're not using a file reference
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        input.put("userId", "12345");
        input.put("action", "process");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:UserProcessor")
            .withInput(input.toString());
        
        client.startExecution(request);
    }

    public void good_case_12() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> fileParams = new HashMap<>();
        // ok: java-step-function-input-file
        fileParams.put("inputFile.$", "s3://data-lake/raw/2023-01-01.json");
        fileParams.put("outputFormat", "parquet");
        params.put("fileParams", fileParams);
        
        String input = new ObjectMapper().writeValueAsString(params);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DataConverter")
            .withInput(input);
        
        sfn.startExecution(request);
    }

    public void good_case_13() {
        AmazonStepFunctions stepFunctions = AmazonStepFunctionsClientBuilder.standard().build();
        
        // Using a reference to a state input rather than a direct file path
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        input.put("fileRef", "$.taskInput.filePath");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:FileProcessor")
            .withInput(input.toString());
        
        stepFunctions.startExecution(request);
    }

    public void good_case_14() {
        AmazonStepFunctions client = AmazonStepFunctionsClientBuilder.standard().build();
        
        // Using a dynamic reference instead of a direct file path
        Map<String, String> inputMap = new HashMap<>();
        inputMap.put("filePathRef", "$.execution.input.filePath");
        
        String input = new ObjectMapper().writeValueAsString(inputMap);
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:DynamicProcessor")
            .withInput(input);
        
        client.startExecution(request);
    }

    public void good_case_15() {
        AmazonStepFunctions sfn = AmazonStepFunctionsClientBuilder.defaultClient();
        
        // This is safe because we're using a non-file value
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode input = mapper.createObjectNode();
        input.put("inputValue", "some-string-value");
        input.put("processType", "standard");
        
        StartExecutionRequest request = new StartExecutionRequest()
            .withStateMachineArn("arn:aws:states:us-east-1:123456789012:stateMachine:StringProcessor")
            .withInput(input.toString());
        
        sfn.startExecution(request);
    }
}
// {/fact}