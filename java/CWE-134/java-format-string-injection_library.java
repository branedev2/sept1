import java.util.Scanner;
import java.util.Formatter;
import java.io.PrintWriter;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import retrofit2.http.Query;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import spark.Request;
import spark.Response;
import spark.Spark;
import io.javalin.Javalin;
import io.javalin.http.Context;
import com.microsoft.azure.functions.*;
import com.azure.storage.blob.*;
import org.apache.commons.lang3.StringUtils;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import javax.ws.rs.*;
import org.glassfish.jersey.server.ResourceConfig;
import javax.ws.rs.core.MediaType;
import org.apache.commons.io.IOUtils;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.HashMap;

// Security Issue: Format String Injection in Java where untrusted input from HTTP requests is used directly as a format string

// True Positive Examples (Vulnerable/Insecure Code)

class FormatStringInjectionExamples {

    // Spring MVC example
    @RestController
    public class bad_case_1 {
        @GetMapping("/format-string")
        public String formatString(HttpServletRequest request) {
            String userInput = request.getParameter("format");
            
            // ruleid: java-format-string-injection
            return String.format(userInput, "sensitive data", 42, Math.PI);
        }
    }

    // OkHttp client example
// {fact rule=untrusted-format-strings@v1.0 defects=1}
    public void bad_case_2() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/api/format")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String formatPattern = response.body().string();
            
            // ruleid: java-format-string-injection
            System.out.println(String.format(formatPattern, "sensitive data", 42, Math.PI));
        }
    }

    // Apache HttpClient example
    public void bad_case_3() throws Exception {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://example.com/api/format");
            String formatPattern = EntityUtils.toString(httpClient.execute(request).getEntity());
            
            // ruleid: java-format-string-injection
            Formatter formatter = new Formatter();
            formatter.format(formatPattern, "sensitive data", 42, Math.PI);
            System.out.println(formatter.toString());
        }
    }

    // Retrofit API client example
    public void bad_case_4() {
        interface FormatApi {
            @GET("/api/format")
            retrofit2.Call<String> getFormat(@Query("id") String id);
        }
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com")
            .build();
            
        FormatApi api = retrofit.create(FormatApi.class);
        try {
            String formatPattern = api.getFormat("123").execute().body();
            
            // ruleid: java-format-string-injection
            System.out.printf(formatPattern, "sensitive data", 42, Math.PI);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // JSch (SSH) example
    public void bad_case_5() {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("user", "host", 22);
            session.setPassword("password");
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            Channel channel = session.openChannel("exec");
            ((ChannelExec)channel).setCommand("echo 'format pattern'");
            
            InputStream in = channel.getInputStream();
            channel.connect();
            
            String formatPattern = IOUtils.toString(in, StandardCharsets.UTF_8);
            channel.disconnect();
            session.disconnect();
            
            // ruleid: java-format-string-injection
            String result = String.format(formatPattern, "sensitive data", 42, Math.PI);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Apache Commons Configuration example
    public void bad_case_6() {
        try {
            Configuration config = new PropertiesConfiguration("config.properties");
            String formatPattern = config.getString("format.pattern");
            
            // This pattern could be controlled by an attacker who modified the config file
            // ruleid: java-format-string-injection
            System.out.println(String.format(formatPattern, "sensitive data", 42, Math.PI));
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    // AWS Lambda example
    public void bad_case_7() {
        AWSLambda awsLambda = AWSLambdaClientBuilder.defaultClient();
        InvokeRequest request = new InvokeRequest()
            .withFunctionName("getFormatPattern")
            .withPayload("{\"source\":\"http\"}");
            
        try {
            String formatPattern = new String(awsLambda.invoke(request).getPayload().array(), StandardCharsets.UTF_8);
            
            // ruleid: java-format-string-injection
            String result = String.format(formatPattern, "sensitive data", 42, Math.PI);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Google Cloud Functions example
    public class bad_case_8 implements HttpFunction {
        @Override
        public void service(HttpRequest request, HttpResponse response) throws IOException {
            String formatPattern = request.getFirstQueryParameter("format").orElse("%s default");
            
            // ruleid: java-format-string-injection
            String result = String.format(formatPattern, "sensitive data", 42, Math.PI);
            response.getWriter().write(result);
        }
    }

    // Log4j2 example
    public void bad_case_9(HttpServletRequest request) {
        String formatPattern = request.getParameter("format");
        Logger logger = LogManager.getLogger(FormatStringInjectionExamples.class);
        
        // ruleid: java-format-string-injection
        logger.info(String.format(formatPattern, "sensitive data", 42, Math.PI));
    }

    // Spark framework example
    public void bad_case_10() {
        Spark.get("/format", (Request req, Response res) -> {
            String formatPattern = req.queryParams("format");
            
            // ruleid: java-format-string-injection
            return String.format(formatPattern, "sensitive data", 42, Math.PI);
        });
    }

    // Javalin framework example
    public void bad_case_11() {
        Javalin app = Javalin.create().start(7000);
        app.get("/format", ctx -> {
            String formatPattern = ctx.queryParam("format");
            
            // ruleid: java-format-string-injection
            ctx.result(String.format(formatPattern, "sensitive data", 42, Math.PI));
        });
    }

    // Azure Functions example
    public class bad_case_12 {
        @FunctionName("formatString")
        public HttpResponseMessage run(
                @HttpTrigger(name = "req", methods = {"get"}, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
                final ExecutionContext context) {
            
            String formatPattern = request.getQueryParameters().get("format");
            
            // ruleid: java-format-string-injection
            String result = String.format(formatPattern, "sensitive data", 42, Math.PI);
            return request.createResponseBuilder(HttpStatus.OK).body(result).build();
        }
    }

    // Vert.x example
    public void bad_case_13() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/format").handler(ctx -> {
            String formatPattern = ctx.request().getParam("format");
            
            // ruleid: java-format-string-injection
            String result = String.format(formatPattern, "sensitive data", 42, Math.PI);
            ctx.response().end(result);
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

    // Quarkus example
    @RouteBase(path = "/api")
    public class bad_case_14 {
        @Route(path = "format", methods = Route.HttpMethod.GET)
        public void format(RoutingContext rc) {
            String formatPattern = rc.request().getParam("format");
            
            // ruleid: java-format-string-injection
            String result = String.format(formatPattern, "sensitive data", 42, Math.PI);
            rc.response().end(result);
        }
    }

    // JAX-RS (Jersey) example
    @Path("/api")
    public class bad_case_15 {
        @GET
        @Path("/format")
        @Produces(MediaType.TEXT_PLAIN)
        public String getFormat(@QueryParam("format") String formatPattern) {
            // ruleid: java-format-string-injection
            return String.format(formatPattern, "sensitive data", 42, Math.PI);
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring MVC example - safe
    @RestController
    public class good_case_1 {
        @GetMapping("/format-string")
        public String formatString(HttpServletRequest request) {
            String userInput = request.getParameter("data");
            
            // ok: java-format-string-injection
            return String.format("User input: %s", userInput);
        }
    }

    // OkHttp client example - safe
    public void good_case_2() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/api/data")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String userData = response.body().string();
            
            // ok: java-format-string-injection
            System.out.println(String.format("API response: %s", userData));
        }
    }

    // Apache HttpClient example - safe
    public void good_case_3() throws Exception {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://example.com/api/data");
            String userData = EntityUtils.toString(httpClient.execute(request).getEntity());
            
            // ok: java-format-string-injection
            Formatter formatter = new Formatter();
            formatter.format("User data: %s", userData);
            System.out.println(formatter.toString());
        }
    }

    // Retrofit API client example - safe
    public void good_case_4() {
        interface DataApi {
            @GET("/api/data")
            retrofit2.Call<String> getData(@Query("id") String id);
        }
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com")
            .build();
            
        DataApi api = retrofit.create(DataApi.class);
        try {
            String userData = api.getData("123").execute().body();
            
            // ok: java-format-string-injection
            System.out.printf("API data: %s", userData);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // JSch (SSH) example - safe
    public void good_case_5() {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("user", "host", 22);
            session.setPassword("password");
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            Channel channel = session.openChannel("exec");
            ((ChannelExec)channel).setCommand("echo 'data'");
            
            InputStream in = channel.getInputStream();
            channel.connect();
            
            String userData = IOUtils.toString(in, StandardCharsets.UTF_8);
            channel.disconnect();
            session.disconnect();
            
            // ok: java-format-string-injection
            String result = String.format("SSH command output: %s", userData);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Apache Commons Configuration example - safe
    public void good_case_6() {
        try {
            Configuration config = new PropertiesConfiguration("config.properties");
            String userData = config.getString("user.data");
            
            // ok: java-format-string-injection
            System.out.println(String.format("Config value: %s", userData));
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    // AWS Lambda example - safe
    public void good_case_7() {
        AWSLambda awsLambda = AWSLambdaClientBuilder.defaultClient();
        InvokeRequest request = new InvokeRequest()
            .withFunctionName("getUserData")
            .withPayload("{\"source\":\"http\"}");
            
        try {
            String userData = new String(awsLambda.invoke(request).getPayload().array(), StandardCharsets.UTF_8);
            
            // ok: java-format-string-injection
            String result = String.format("Lambda result: %s", userData);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Google Cloud Functions example - safe
    public class good_case_8 implements HttpFunction {
        @Override
        public void service(HttpRequest request, HttpResponse response) throws IOException {
            String userData = request.getFirstQueryParameter("data").orElse("default");
            
            // ok: java-format-string-injection
            String result = String.format("User provided: %s", userData);
            response.getWriter().write(result);
        }
    }

    // Log4j2 example - safe
    public void good_case_9(HttpServletRequest request) {
        String userData = request.getParameter("data");
        Logger logger = LogManager.getLogger(FormatStringInjectionExamples.class);
        
        // ok: java-format-string-injection
        logger.info("User input: {}", userData); // Using Log4j's built-in formatting
    }

    // Spark framework example - safe
    public void good_case_10() {
        Spark.get("/format", (Request req, Response res) -> {
            String userData = req.queryParams("data");
            
            // ok: java-format-string-injection
            return String.format("You entered: %s", userData);
        });
    }

    // Javalin framework example - safe
    public void good_case_11() {
        Javalin app = Javalin.create().start(7000);
        app.get("/format", ctx -> {
            String userData = ctx.queryParam("data");
            
            // ok: java-format-string-injection
            ctx.result(String.format("Data received: %s", userData));
        });
    }

    // Azure Functions example - safe
    public class good_case_12 {
        @FunctionName("formatString")
        public HttpResponseMessage run(
                @HttpTrigger(name = "req", methods = {"get"}, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
                final ExecutionContext context) {
            
            String userData = request.getQueryParameters().get("data");
            
            // ok: java-format-string-injection
            String result = String.format("Azure function received: %s", userData);
            return request.createResponseBuilder(HttpStatus.OK).body(result).build();
        }
    }

    // Vert.x example - safe
    public void good_case_13() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/format").handler(ctx -> {
            String userData = ctx.request().getParam("data");
            
            // ok: java-format-string-injection
            String result = String.format("Vert.x received: %s", userData);
            ctx.response().end(result);
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

    // Quarkus example - safe
    @RouteBase(path = "/api")
    public class good_case_14 {
        @Route(path = "format", methods = Route.HttpMethod.GET)
        public void format(RoutingContext rc) {
            String userData = rc.request().getParam("data");
            
            // ok: java-format-string-injection
            String result = String.format("Quarkus received: %s", userData);
            rc.response().end(result);
        }
    }

    // JAX-RS (Jersey) example - safe
    @Path("/api")
    public class good_case_15 {
        @GET
        @Path("/format")
        @Produces(MediaType.TEXT_PLAIN)
        public String getFormat(@QueryParam("data") String userData) {
            // ok: java-format-string-injection
            return String.format("JAX-RS received: %s", userData);
        }
    }
}
// {/fact}