import software.amazon.ion.*;
import software.amazon.ion.system.*;
import software.amazon.ion.reader.*;
import software.amazon.ion.impl.*;
import software.amazon.ion.streaming.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;
import com.amazonaws.services.lambda.runtime.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.dynamodbv2.*;
import com.amazonaws.services.sqs.*;
import com.amazonaws.services.sns.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.boot.web.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.util.*;
import com.fasterxml.jackson.databind.*;
import javax.servlet.http.*;
import okhttp3.*;
import retrofit2.*;
import com.google.gson.*;
import java.net.http.*;
import com.amazonaws.services.lambda.runtime.events.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.dynamodb.*;
import software.amazon.awssdk.services.sqs.*;

// Security Issue: Using IonSystem.singleValue() is less efficient than IonReader for memory, performance, and resource management

// True Positive Examples (Vulnerable/Insecure Code)

public class IonSystemUsageExamples {

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            // Processing Ion data from a request parameter
            String ionData = request.getParameter("ionData");
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = system.singleValue(ionData);
            
            // Process the value
            if (value.isStruct()) {
                IonStruct struct = (IonStruct) value;
                // Do something with the struct
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // AWS Lambda handler processing Ion data
            IonSystem system = IonSystemBuilder.standard().build();
            String ionText = "{name:\"John\", age:30}";
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = system.singleValue(ionText);
            
            // Extract data
            IonStruct person = (IonStruct) value;
            String name = person.get("name").stringValue();
            int age = person.get("age").intValue();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3(APIGatewayProxyRequestEvent request) {
        // AWS API Gateway integration with Ion
        try {
            String body = request.getBody();
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue requestData = system.singleValue(body);
            
            // Process API request data
            if (requestData.isStruct()) {
                // Extract fields and process
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4(@RequestBody String requestBody) {
        // Spring Boot REST controller handling Ion data
        try {
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue data = system.singleValue(requestBody);
            
            // Process the data
            if (data.isSequence()) {
                IonSequence sequence = (IonSequence) data;
                for (IonValue item : sequence) {
                    // Process each item
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        // Processing Ion data from a file uploaded via HTTP
        try {
            Part filePart = request.getPart("ionFile");
            InputStream fileContent = filePart.getInputStream();
            byte[] bytes = fileContent.readAllBytes();
            String ionContent = new String(bytes);
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue fileData = system.singleValue(ionContent);
            
            // Process the file data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(OkHttpClient client) {
        // OkHttp client processing Ion data from a response
        try {
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
                
            Response response = client.newCall(request).execute();
            String ionData = response.body().string();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue responseData = system.singleValue(ionData);
            
            // Process the response data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpClient httpClient) {
        // Java 11 HttpClient processing Ion data
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(new java.net.URI("https://api.example.com/data"))
                .GET()
                .build();
                
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String ionData = response.body();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue data = system.singleValue(ionData);
            
            // Process the data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(AmazonS3 s3Client) {
        // AWS S3 client retrieving and processing Ion data
        try {
            S3Object s3Object = s3Client.getObject("bucket-name", "ion-data.ion");
            InputStream objectData = s3Object.getObjectContent();
            byte[] bytes = objectData.readAllBytes();
            String ionContent = new String(bytes);
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue s3Data = system.singleValue(ionContent);
            
            // Process S3 data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(AmazonDynamoDB dynamoDBClient) {
        // AWS DynamoDB client processing Ion data
        try {
            // Retrieve item from DynamoDB
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue("123"));
            
            GetItemResult result = dynamoDBClient.getItem("table-name", key);
            String ionData = result.getItem().get("ionData").getS();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue dynamoData = system.singleValue(ionData);
            
            // Process DynamoDB data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(AmazonSQS sqsClient) {
        // AWS SQS client processing Ion messages
        try {
            ReceiveMessageResult result = sqsClient.receiveMessage("queue-url");
            for (Message message : result.getMessages()) {
                String ionData = message.getBody();
                
                IonSystem system = IonSystemBuilder.standard().build();
                
                // ruleid: java-avoid-use-of-ionsystem-singlevalue
                IonValue messageData = system.singleValue(ionData);
                
                // Process SQS message data
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11(RestTemplate restTemplate) {
        // Spring RestTemplate processing Ion data
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(
                "https://api.example.com/data", String.class);
            String ionData = response.getBody();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue data = system.singleValue(ionData);
            
            // Process the data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(CloseableHttpClient httpClient) {
        // Apache HttpClient processing Ion data
        try {
            HttpGet request = new HttpGet("https://api.example.com/data");
            CloseableHttpResponse response = httpClient.execute(request);
            String ionData = EntityUtils.toString(response.getEntity());
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue data = system.singleValue(ionData);
            
            // Process the data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(Retrofit retrofit) {
        // Retrofit client processing Ion data
        try {
            Call<ResponseBody> call = retrofit.create(ApiService.class).getData();
            Response<ResponseBody> response = call.execute();
            String ionData = response.body().string();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue data = system.singleValue(ionData);
            
            // Process the data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14(AmazonSNS snsClient) {
        // AWS SNS client processing Ion notifications
        try {
            PublishResult result = snsClient.publish("topic-arn", "message");
            String messageId = result.getMessageId();
            
            // Get message content from another source
            String ionData = "{id:\"" + messageId + "\", status:\"sent\"}";
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue notificationData = system.singleValue(ionData);
            
            // Process notification data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(ObjectMapper objectMapper) {
        // Jackson ObjectMapper with Ion data
        try {
            // Get JSON from a source and convert to Ion
            String jsonData = "{\"name\":\"John\",\"age\":30}";
            JsonNode jsonNode = objectMapper.readTree(jsonData);
            String ionData = jsonNode.toString();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue data = system.singleValue(ionData);
            
            // Process the data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1(HttpServletRequest request) {
        try {
            // Processing Ion data from a request parameter using IonReader
            String ionData = request.getParameter("ionData");
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process the data using the reader
            IonType type;
            while ((type = reader.next()) != null) {
                if (type == IonType.STRUCT) {
                    reader.stepIn();
                    while (reader.next() != null) {
                        // Process each field
                        String fieldName = reader.getFieldName();
                        // Process field value based on its type
                    }
                    reader.stepOut();
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // AWS Lambda handler processing Ion data with IonReader
            IonSystem system = IonSystemBuilder.standard().build();
            String ionText = "{name:\"John\", age:30}";
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionText);
            
            // Extract data using reader
            String name = null;
            Integer age = null;
            
            reader.next(); // Move to the struct
            reader.stepIn(); // Step into the struct
            
            while (reader.next() != null) {
                String fieldName = reader.getFieldName();
                if ("name".equals(fieldName) && reader.getType() == IonType.STRING) {
                    name = reader.stringValue();
                } else if ("age".equals(fieldName) && reader.getType() == IonType.INT) {
                    age = reader.intValue();
                }
            }
            
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3(APIGatewayProxyRequestEvent request) {
        // AWS API Gateway integration with Ion using IonReader
        try {
            String body = request.getBody();
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(body);
            
            // Process API request data
            IonType type;
            while ((type = reader.next()) != null) {
                if (type == IonType.STRUCT) {
                    // Process struct fields
                    reader.stepIn();
                    while (reader.next() != null) {
                        // Process each field
                    }
                    reader.stepOut();
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(@RequestBody String requestBody) {
        // Spring Boot REST controller handling Ion data with IonReader
        try {
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(requestBody);
            
            // Process the data
            IonType type;
            while ((type = reader.next()) != null) {
                if (type == IonType.LIST || type == IonType.SEXP) {
                    reader.stepIn();
                    while (reader.next() != null) {
                        // Process each item in the sequence
                    }
                    reader.stepOut();
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request) {
        // Processing Ion data from a file uploaded via HTTP using IonReader
        try {
            Part filePart = request.getPart("ionFile");
            InputStream fileContent = filePart.getInputStream();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(fileContent);
            
            // Process the file data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(OkHttpClient client) {
        // OkHttp client processing Ion data from a response using IonReader
        try {
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
                
            Response response = client.newCall(request).execute();
            String ionData = response.body().string();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process the response data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpClient httpClient) {
        // Java 11 HttpClient processing Ion data with IonReader
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(new java.net.URI("https://api.example.com/data"))
                .GET()
                .build();
                
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String ionData = response.body();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process the data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(AmazonS3 s3Client) {
        // AWS S3 client retrieving and processing Ion data with IonReader
        try {
            S3Object s3Object = s3Client.getObject("bucket-name", "ion-data.ion");
            InputStream objectData = s3Object.getObjectContent();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(objectData);
            
            // Process S3 data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(AmazonDynamoDB dynamoDBClient) {
        // AWS DynamoDB client processing Ion data with IonReader
        try {
            // Retrieve item from DynamoDB
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue("123"));
            
            GetItemResult result = dynamoDBClient.getItem("table-name", key);
            String ionData = result.getItem().get("ionData").getS();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process DynamoDB data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(AmazonSQS sqsClient) {
        // AWS SQS client processing Ion messages with IonReader
        try {
            ReceiveMessageResult result = sqsClient.receiveMessage("queue-url");
            for (Message message : result.getMessages()) {
                String ionData = message.getBody();
                
                IonSystem system = IonSystemBuilder.standard().build();
                
                // ok: java-avoid-use-of-ionsystem-singlevalue
                IonReader reader = system.newReader(ionData);
                
                // Process SQS message data
                IonType type;
                while ((type = reader.next()) != null) {
                    // Process each top-level value
                }
                reader.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11(RestTemplate restTemplate) {
        // Spring RestTemplate processing Ion data with IonReader
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(
                "https://api.example.com/data", String.class);
            String ionData = response.getBody();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process the data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(CloseableHttpClient httpClient) {
        // Apache HttpClient processing Ion data with IonReader
        try {
            HttpGet request = new HttpGet("https://api.example.com/data");
            CloseableHttpResponse response = httpClient.execute(request);
            String ionData = EntityUtils.toString(response.getEntity());
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process the data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(Retrofit retrofit) {
        // Retrofit client processing Ion data with IonReader
        try {
            Call<ResponseBody> call = retrofit.create(ApiService.class).getData();
            Response<ResponseBody> response = call.execute();
            InputStream inputStream = response.body().byteStream();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(inputStream);
            
            // Process the data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14(AmazonSNS snsClient) {
        // AWS SNS client processing Ion notifications with IonReader
        try {
            PublishResult result = snsClient.publish("topic-arn", "message");
            String messageId = result.getMessageId();
            
            // Get message content from another source
            String ionData = "{id:\"" + messageId + "\", status:\"sent\"}";
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process notification data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(ObjectMapper objectMapper) {
        // Jackson ObjectMapper with Ion data using IonReader
        try {
            // Get JSON from a source and convert to Ion
            String jsonData = "{\"name\":\"John\",\"age\":30}";
            JsonNode jsonNode = objectMapper.readTree(jsonData);
            String ionData = jsonNode.toString();
            
            IonSystem system = IonSystemBuilder.standard().build();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = system.newReader(ionData);
            
            // Process the data
            IonType type;
            while ((type = reader.next()) != null) {
                // Process each top-level value
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper interface for Retrofit example
    interface ApiService {
        @GET("data")
        Call<ResponseBody> getData();
    }
}
// {/fact}