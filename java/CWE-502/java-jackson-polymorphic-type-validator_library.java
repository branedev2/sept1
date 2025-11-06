import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORMapper;
import com.fasterxml.jackson.dataformat.smile.SmileMapper;
import com.fasterxml.jackson.dataformat.avro.AvroMapper;
import com.fasterxml.jackson.dataformat.protobuf.ProtobufMapper;
import com.fasterxml.jackson.dataformat.ion.IonObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.properties.JavaPropsMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;
import io.javalin.Javalin;
import io.javalin.http.Context;
import spark.Spark;
import ratpack.server.RatpackServer;
import ratpack.handling.Context;
import ratpack.http.Request;
import ratpack.jackson.Jackson;
import kong.unirest.Unirest;
import kong.unirest.HttpResponse;
import feign.Feign;
import feign.jackson.JacksonDecoder;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Body;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.helidon.webserver.Routing;
import io.helidon.webserver.ServerRequest;
import io.helidon.webserver.ServerResponse;
import io.helidon.webserver.Service;

// Security Issue: Jackson Polymorphic Type Validation Vulnerability (CWE-502)
// This rule detects insecure deserialization of untrusted data using Jackson,
// which can lead to remote code execution or denial of service attacks.

// Base classes for polymorphic deserialization examples
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat")
})
abstract class Animal {
    public String name;
}

@JsonTypeName("dog")
class Dog extends Animal {
    public String breed;
}

@JsonTypeName("cat")
class Cat extends Animal {
    public boolean likesCream;
}

// True Positive Examples (Vulnerable/Insecure Code)

// Bad case 1: Standard ObjectMapper without polymorphic type validation
@RestController
class BadCase1Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @PostMapping("/api/animals")
    public ResponseEntity<String> bad_case_1(@RequestBody String requestBody) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(); // Deprecated but still used in legacy code
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(requestBody, Animal.class);
        
        return ResponseEntity.ok("Processed: " + animal.name);
    }
}
// {/fact}

// Bad case 2: XML deserialization without type validation
@RestController
class BadCase2Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @PostMapping("/api/xml-animals")
    public ResponseEntity<String> bad_case_2(@RequestBody String xmlData) throws IOException {
        XmlMapper xmlMapper = new XmlMapper();
        xmlMapper.enableDefaultTyping();
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = xmlMapper.readValue(xmlData, Animal.class);
        
        return ResponseEntity.ok("Processed XML: " + animal.name);
    }
}
// {/fact}

// Bad case 3: YAML deserialization with Spring RestTemplate
@RestController
class BadCase3Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @PostMapping("/api/yaml-animals")
    public ResponseEntity<String> bad_case_3(@RequestBody String yamlData) throws IOException {
        YAMLMapper yamlMapper = new YAMLMapper();
        yamlMapper.activateDefaultTyping(yamlMapper.getPolymorphicTypeValidator());
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = yamlMapper.readValue(yamlData, Animal.class);
        
        return ResponseEntity.ok("Processed YAML: " + animal.name);
    }
}
// {/fact}

// Bad case 4: CBOR deserialization with Apache HttpClient
class BadCase4Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_4() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://example.com/api/data");
        httpPost.setHeader("Content-Type", "application/cbor");
        
        HttpResponse response = httpClient.execute(httpPost);
        byte[] responseBytes = EntityUtils.toByteArray(response.getEntity());
        
        CBORMapper cborMapper = new CBORMapper();
        cborMapper.enableDefaultTyping();
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = cborMapper.readValue(responseBytes, Animal.class);
        
        System.out.println("Processed CBOR: " + animal.name);
    }
}
// {/fact}

// Bad case 5: Smile format deserialization with Java HttpClient
class BadCase5Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_5() throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://example.com/api/smile-data"))
                .build();
        
        java.net.http.HttpResponse<byte[]> response = client.send(request, 
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        
        SmileMapper smileMapper = new SmileMapper();
        smileMapper.enableDefaultTyping();
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = smileMapper.readValue(response.body(), Animal.class);
        
        System.out.println("Processed Smile: " + animal.name);
    }
}
// {/fact}

// Bad case 6: Avro deserialization with OkHttp
class BadCase6Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_6() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url("https://example.com/api/avro-data")
                .build();
        
        try (Response response = client.newCall(request).execute()) {
            byte[] responseBytes = response.body().bytes();
            
            AvroMapper avroMapper = new AvroMapper();
            avroMapper.activateDefaultTyping(avroMapper.getPolymorphicTypeValidator());
            
            // ruleid: java-jackson-polymorphic-type-validator
            Animal animal = avroMapper.readValue(responseBytes, Animal.class);
            
            System.out.println("Processed Avro: " + animal.name);
        }
    }
}
// {/fact}

// Bad case 7: Protobuf deserialization with Retrofit
interface AnimalService {
    @POST("animals")
    retrofit2.Call<String> postAnimal(@retrofit2.http.Body String body);
}

class BadCase7Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_7() throws IOException {
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://example.com/api/")
                .addConverterFactory(JacksonConverterFactory.create())
                .build();
        
        AnimalService service = retrofit.create(AnimalService.class);
        retrofit2.Response<String> response = service.postAnimal("{}").execute();
        String responseBody = response.body();
        
        ProtobufMapper protobufMapper = new ProtobufMapper();
        protobufMapper.enableDefaultTyping();
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = protobufMapper.readValue(responseBody, Animal.class);
        
        System.out.println("Processed Protobuf: " + animal.name);
    }
}
// {/fact}

// Bad case 8: Ion deserialization with Javalin
class BadCase8Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_8() {
        Javalin app = Javalin.create().start(7000);
        
        app.post("/api/ion-animals", ctx -> {
            String requestBody = ctx.body();
            
            IonObjectMapper ionMapper = new IonObjectMapper();
            ionMapper.enableDefaultTyping();
            
            // ruleid: java-jackson-polymorphic-type-validator
            Animal animal = ionMapper.readValue(requestBody, Animal.class);
            
            ctx.result("Processed Ion: " + animal.name);
        });
    }
}
// {/fact}

// Bad case 9: CSV deserialization with Spark
class BadCase9Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_9() {
        Spark.post("/api/csv-animals", (req, res) -> {
            String requestBody = req.body();
            
            CsvMapper csvMapper = new CsvMapper();
            csvMapper.enableDefaultTyping();
            
            // ruleid: java-jackson-polymorphic-type-validator
            Animal animal = csvMapper.readValue(requestBody, Animal.class);
            
            return "Processed CSV: " + animal.name;
        });
    }
}
// {/fact}

// Bad case 10: Properties deserialization with Ratpack
class BadCase10Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_10() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .post("api/props-animals", ctx -> {
                    String requestBody = ctx.getRequest().getBody().getText();
                    
                    JavaPropsMapper propsMapper = new JavaPropsMapper();
                    propsMapper.enableDefaultTyping();
                    
                    // ruleid: java-jackson-polymorphic-type-validator
                    Animal animal = propsMapper.readValue(requestBody, Animal.class);
                    
                    ctx.render("Processed Properties: " + animal.name);
                })
            )
        );
    }
}
// {/fact}

// Bad case 11: JSON deserialization with Kong Unirest
class BadCase11Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_11() throws IOException {
        kong.unirest.HttpResponse<String> response = Unirest.get("https://example.com/api/animals")
                .asString();
        
        String responseBody = response.getBody();
        
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(responseBody, Animal.class);
        
        System.out.println("Processed with Unirest: " + animal.name);
    }
}
// {/fact}

// Bad case 12: JSON deserialization with Feign
interface AnimalClient {
    @feign.RequestLine("POST /animals")
    String createAnimal(String animal);
}

class BadCase12Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_12() throws IOException {
        AnimalClient client = Feign.builder()
                .decoder(new JacksonDecoder())
                .target(AnimalClient.class, "https://example.com/api");
        
        String response = client.createAnimal("{}");
        
        ObjectMapper mapper = JsonMapper.builder()
                .activateDefaultTyping(mapper.getPolymorphicTypeValidator())
                .build();
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(response, Animal.class);
        
        System.out.println("Processed with Feign: " + animal.name);
    }
}
// {/fact}

// Bad case 13: JSON deserialization with Vert.x
class BadCase13Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_13() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/api/animals").handler(ctx -> {
            String body = ctx.getBodyAsString();
            
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping();
            
            try {
                // ruleid: java-jackson-polymorphic-type-validator
                Animal animal = mapper.readValue(body, Animal.class);
                ctx.response().end("Processed with Vert.x: " + animal.name);
            } catch (IOException e) {
                ctx.response().setStatusCode(400).end("Error processing request");
            }
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }
}
// {/fact}

// Bad case 14: JSON deserialization with Micronaut
@Controller("/api")
class BadCase14Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @Post("/animals")
    public String bad_case_14(@Body String requestBody) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());
        
        // ruleid: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(requestBody, Animal.class);
        
        return "Processed with Micronaut: " + animal.name;
    }
}
// {/fact}

// Bad case 15: JSON deserialization with Helidon
class BadCase15Service implements Service {
    @Override
    public void update(Routing.Rules rules) {
        rules.post("/api/animals", this::processRequest);
    }
    
    private void processRequest(ServerRequest request, ServerResponse response) {
        request.content().as(String.class).thenAccept(body -> {
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enableDefaultTyping();
                
                // ruleid: java-jackson-polymorphic-type-validator
                Animal animal = mapper.readValue(body, Animal.class);
                
                response.send("Processed with Helidon: " + animal.name);
            } catch (IOException e) {
                response.status(400).send("Error processing request");
            }
        });
    }
}

// True Negative Examples (Safe/Secure Code)

// Good case 1: Standard ObjectMapper with polymorphic type validation
@RestController
class GoodCase1Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    @PostMapping("/api/safe-animals")
    public ResponseEntity<String> good_case_1(@RequestBody String requestBody) throws IOException {
        // Create a secure polymorphic type validator that only allows specific base classes
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        ObjectMapper mapper = JsonMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(requestBody, Animal.class);
        
        return ResponseEntity.ok("Safely processed: " + animal.name);
    }
}
// {/fact}

// Good case 2: XML deserialization with type validation
@RestController
class GoodCase2Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    @PostMapping("/api/safe-xml-animals")
    public ResponseEntity<String> good_case_2(@RequestBody String xmlData) throws IOException {
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        XmlMapper xmlMapper = XmlMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = xmlMapper.readValue(xmlData, Animal.class);
        
        return ResponseEntity.ok("Safely processed XML: " + animal.name);
    }
}
// {/fact}

// Good case 3: YAML deserialization with Spring RestTemplate and type validation
@RestController
class GoodCase3Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    @PostMapping("/api/safe-yaml-animals")
    public ResponseEntity<String> good_case_3(@RequestBody String yamlData) throws IOException {
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        YAMLMapper yamlMapper = YAMLMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = yamlMapper.readValue(yamlData, Animal.class);
        
        return ResponseEntity.ok("Safely processed YAML: " + animal.name);
    }
}
// {/fact}

// Good case 4: CBOR deserialization with Apache HttpClient and type validation
class GoodCase4Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_4() throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://example.com/api/data");
        httpPost.setHeader("Content-Type", "application/cbor");
        
        org.apache.http.HttpResponse response = httpClient.execute(httpPost);
        byte[] responseBytes = EntityUtils.toByteArray(response.getEntity());
        
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        CBORMapper cborMapper = CBORMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = cborMapper.readValue(responseBytes, Animal.class);
        
        System.out.println("Safely processed CBOR: " + animal.name);
    }
}
// {/fact}

// Good case 5: Smile format deserialization with Java HttpClient and type validation
class GoodCase5Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_5() throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://example.com/api/smile-data"))
                .build();
        
        java.net.http.HttpResponse<byte[]> response = client.send(request, 
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        SmileMapper smileMapper = SmileMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = smileMapper.readValue(response.body(), Animal.class);
        
        System.out.println("Safely processed Smile: " + animal.name);
    }
}
// {/fact}

// Good case 6: Avro deserialization with OkHttp and type validation
class GoodCase6Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_6() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url("https://example.com/api/avro-data")
                .build();
        
        try (Response response = client.newCall(request).execute()) {
            byte[] responseBytes = response.body().bytes();
            
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                    .allowIfBaseType(Animal.class)
                    .build();
            
            AvroMapper avroMapper = AvroMapper.builder()
                    .polymorphicTypeValidator(ptv)
                    .build();
            
            // ok: java-jackson-polymorphic-type-validator
            Animal animal = avroMapper.readValue(responseBytes, Animal.class);
            
            System.out.println("Safely processed Avro: " + animal.name);
        }
    }
}
// {/fact}

// Good case 7: Protobuf deserialization with Retrofit and type validation
class GoodCase7Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_7() throws IOException {
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://example.com/api/")
                .addConverterFactory(JacksonConverterFactory.create())
                .build();
        
        AnimalService service = retrofit.create(AnimalService.class);
        retrofit2.Response<String> response = service.postAnimal("{}").execute();
        String responseBody = response.body();
        
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        ProtobufMapper protobufMapper = ProtobufMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = protobufMapper.readValue(responseBody, Animal.class);
        
        System.out.println("Safely processed Protobuf: " + animal.name);
    }
}
// {/fact}

// Good case 8: Ion deserialization with Javalin and type validation
class GoodCase8Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_8() {
        Javalin app = Javalin.create().start(7000);
        
        app.post("/api/safe-ion-animals", ctx -> {
            String requestBody = ctx.body();
            
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                    .allowIfBaseType(Animal.class)
                    .build();
            
            IonObjectMapper ionMapper = new IonObjectMapper();
            ionMapper.setPolymorphicTypeValidator(ptv);
            
            // ok: java-jackson-polymorphic-type-validator
            Animal animal = ionMapper.readValue(requestBody, Animal.class);
            
            ctx.result("Safely processed Ion: " + animal.name);
        });
    }
}
// {/fact}

// Good case 9: CSV deserialization with Spark and type validation
class GoodCase9Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_9() {
        Spark.post("/api/safe-csv-animals", (req, res) -> {
            String requestBody = req.body();
            
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                    .allowIfBaseType(Animal.class)
                    .build();
            
            CsvMapper csvMapper = CsvMapper.builder()
                    .polymorphicTypeValidator(ptv)
                    .build();
            
            // ok: java-jackson-polymorphic-type-validator
            Animal animal = csvMapper.readValue(requestBody, Animal.class);
            
            return "Safely processed CSV: " + animal.name;
        });
    }
}
// {/fact}

// Good case 10: Properties deserialization with Ratpack and type validation
class GoodCase10Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_10() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .post("api/safe-props-animals", ctx -> {
                    String requestBody = ctx.getRequest().getBody().getText();
                    
                    PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                            .allowIfBaseType(Animal.class)
                            .build();
                    
                    JavaPropsMapper propsMapper = JavaPropsMapper.builder()
                            .polymorphicTypeValidator(ptv)
                            .build();
                    
                    // ok: java-jackson-polymorphic-type-validator
                    Animal animal = propsMapper.readValue(requestBody, Animal.class);
                    
                    ctx.render("Safely processed Properties: " + animal.name);
                })
            )
        );
    }
}
// {/fact}

// Good case 11: JSON deserialization with Kong Unirest and type validation
class GoodCase11Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_11() throws IOException {
        kong.unirest.HttpResponse<String> response = Unirest.get("https://example.com/api/animals")
                .asString();
        
        String responseBody = response.getBody();
        
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        ObjectMapper mapper = JsonMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(responseBody, Animal.class);
        
        System.out.println("Safely processed with Unirest: " + animal.name);
    }
}
// {/fact}

// Good case 12: JSON deserialization with Feign and type validation
class GoodCase12Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_12() throws IOException {
        AnimalClient client = Feign.builder()
                .decoder(new JacksonDecoder())
                .target(AnimalClient.class, "https://example.com/api");
        
        String response = client.createAnimal("{}");
        
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        ObjectMapper mapper = JsonMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(response, Animal.class);
        
        System.out.println("Safely processed with Feign: " + animal.name);
    }
}
// {/fact}

// Good case 13: JSON deserialization with Vert.x and type validation
class GoodCase13Service {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    public void good_case_13() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/api/safe-animals").handler(ctx -> {
            String body = ctx.getBodyAsString();
            
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                    .allowIfBaseType(Animal.class)
                    .build();
            
            ObjectMapper mapper = JsonMapper.builder()
                    .polymorphicTypeValidator(ptv)
                    .build();
            
            try {
                // ok: java-jackson-polymorphic-type-validator
                Animal animal = mapper.readValue(body, Animal.class);
                ctx.response().end("Safely processed with Vert.x: " + animal.name);
            } catch (IOException e) {
                ctx.response().setStatusCode(400).end("Error processing request");
            }
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }
}
// {/fact}

// Good case 14: JSON deserialization with Micronaut and type validation
@Controller("/api")
class GoodCase14Controller {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
    @Post("/safe-animals")
    public String good_case_14(@Body String requestBody) throws IOException {
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Animal.class)
                .build();
        
        ObjectMapper mapper = JsonMapper.builder()
                .polymorphicTypeValidator(ptv)
                .build();
        
        // ok: java-jackson-polymorphic-type-validator
        Animal animal = mapper.readValue(requestBody, Animal.class);
        
        return "Safely processed with Micronaut: " + animal.name;
    }
}
// {/fact}

// Good case 15: JSON deserialization with Helidon and type validation
class GoodCase15Service implements Service {
    @Override
    public void update(Routing.Rules rules) {
        rules.post("/api/safe-animals", this::processRequest);
    }
    
    private void processRequest(ServerRequest request, ServerResponse response) {
        request.content().as(String.class).thenAccept(body -> {
            try {
                PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Animal.class)
                        .build();
                
                ObjectMapper mapper = JsonMapper.builder()
                        .polymorphicTypeValidator(ptv)
                        .build();
                
                // ok: java-jackson-polymorphic-type-validator
                Animal animal = mapper.readValue(body, Animal.class);
                
                response.send("Safely processed with Helidon: " + animal.name);
            } catch (IOException e) {
                response.status(400).send("Error processing request");
            }
        });
    }
}