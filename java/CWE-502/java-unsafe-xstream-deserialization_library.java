import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import com.thoughtworks.xstream.*;
import com.thoughtworks.xstream.security.*;
import com.thoughtworks.xstream.io.xml.*;
import org.apache.struts2.dispatcher.*;
import org.apache.cxf.jaxrs.client.*;
import org.glassfish.jersey.client.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.util.*;
import com.fasterxml.jackson.databind.*;
import com.google.gson.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.converter.gson.*;
import retrofit2.http.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;
import com.azure.storage.blob.*;
import com.google.cloud.storage.*;
import io.vertx.core.*;
import io.vertx.ext.web.*;
import io.vertx.ext.web.client.*;
import io.micronaut.http.annotation.*;
import io.micronaut.http.*;
import io.quarkus.vertx.web.*;
import spark.*;
import ratpack.server.*;
import ratpack.handling.*;
import play.mvc.*;
import akka.http.javadsl.server.*;
import akka.http.javadsl.model.*;

// Security Issue: Unsafe XStream Deserialization

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("data");
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(xmlData);
        System.out.println("Deserialized object: " + obj);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_2(@RequestBody String requestBody) {
    try {
        XStream xstream = new XStream(new DomDriver());
        // ruleid: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(requestBody);
        System.out.println("Processed: " + result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
    try {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String xmlInput = sb.toString();
        
        XStream xstream = new XStream(new StaxDriver());
        // ruleid: java-unsafe-xstream-deserialization
        Object data = xstream.fromXML(xmlInput);
        response.getWriter().write("Processed: " + data.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Controller
public void bad_case_4(@RequestParam("xml") String xmlContent) {
    try {
        XStream xstream = new XStream();
        xstream.alias("user", User.class);
        // ruleid: java-unsafe-xstream-deserialization
        User user = (User) xstream.fromXML(xmlContent);
        System.out.println("User: " + user.getName());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    try {
        InputStream inputStream = request.getInputStream();
        XStream xstream = new XStream(new JettisonMappedXmlDriver());
        // ruleid: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(inputStream);
        System.out.println("Processed object: " + obj);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6(Route route) {
    // Using Spark framework
    route.post("/process", (req, res) -> {
        String xmlBody = req.body();
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(xmlBody);
        return "Processed: " + result.toString();
    });
}

public void bad_case_7() {
    // Using Vert.x framework
    Vertx.vertx().createHttpServer().requestHandler(req -> {
        req.bodyHandler(body -> {
            String xmlData = body.toString();
            XStream xstream = new XStream();
            // ruleid: java-unsafe-xstream-deserialization
            Object obj = xstream.fromXML(xmlData);
            req.response().end("Processed: " + obj.toString());
        });
    }).listen(8080);
}

public void bad_case_8() {
    // Using Ratpack framework
    RatpackServer.start(server -> server
        .handlers(chain -> chain
            .post("api", ctx -> {
                ctx.getRequest().getBody().then(body -> {
                    String xmlData = body.getText();
                    XStream xstream = new XStream();
                    // ruleid: java-unsafe-xstream-deserialization
                    Object result = xstream.fromXML(xmlData);
                    ctx.render("Processed: " + result.toString());
                });
            })
        )
    );
}

@io.micronaut.http.annotation.Controller("/api")
public void bad_case_9(@Body String requestBody) {
    // Using Micronaut framework
    XStream xstream = new XStream();
    // ruleid: java-unsafe-xstream-deserialization
    Object result = xstream.fromXML(requestBody);
    return "Processed: " + result.toString();
}

public void bad_case_10() {
    // Using OkHttp client to receive and process XML
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
    
    try (Response response = client.newCall(request).execute()) {
        String xmlResponse = response.body().string();
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object data = xstream.fromXML(xmlResponse);
        System.out.println("Processed: " + data);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Using Apache HttpClient
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data.xml");
        CloseableHttpResponse response = httpClient.execute(request);
        
        String xmlContent = EntityUtils.toString(response.getEntity());
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(xmlContent);
        System.out.println("Processed: " + result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Using Play Framework
    play.mvc.Result handleXmlRequest(play.mvc.Http.Request request) {
        String xmlBody = request.body().asText();
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object data = xstream.fromXML(xmlBody);
        return ok("Processed: " + data.toString());
    }
}

public void bad_case_13() {
    // Using Akka HTTP
    Route route = 
        post(() -> 
            entity(Unmarshaller.entityToString(), xmlData -> {
                XStream xstream = new XStream();
                // ruleid: java-unsafe-xstream-deserialization
                Object result = xstream.fromXML(xmlData);
                return complete("Processed: " + result.toString());
            })
        );
}

public void bad_case_14() {
    // Using Jersey Client
    Client client = ClientBuilder.newClient();
    WebTarget target = client.target("https://api.example.com/data");
    String xmlResponse = target.request().get(String.class);
    
    XStream xstream = new XStream();
    // ruleid: java-unsafe-xstream-deserialization
    Object data = xstream.fromXML(xmlResponse);
    System.out.println("Processed: " + data);
}

public void bad_case_15() {
    // Using Apache CXF
    WebClient client = WebClient.create("https://api.example.com");
    String xmlResponse = client.path("/data").accept("application/xml").get(String.class);
    
    XStream xstream = new XStream();
    // ruleid: java-unsafe-xstream-deserialization
    Object result = xstream.fromXML(xmlResponse);
    System.out.println("Processed: " + result);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("data");
        XStream xstream = new XStream();
        // Set up security framework
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(new WildcardTypePermission(new String[] {"com.example.model.*"}));
        // ok: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(xmlData);
        System.out.println("Deserialized object: " + obj);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_2(@RequestBody String requestBody) {
    try {
        XStream xstream = new XStream(new DomDriver());
        // Configure XStream security
        xstream.setMode(XStream.NO_REFERENCES);
        xstream.allowTypesByWildcard(new String[] {
            "com.mycompany.app.**"
        });
        // ok: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(requestBody);
        System.out.println("Processed: " + result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
    try {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String xmlInput = sb.toString();
        
        XStream xstream = new XStream(new StaxDriver());
        // Configure XStream with explicit class permissions
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[] {
            String.class,
            Integer.class,
            ArrayList.class,
            HashMap.class
        });
        // ok: java-unsafe-xstream-deserialization
        Object data = xstream.fromXML(xmlInput);
        response.getWriter().write("Processed: " + data.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Controller
public void good_case_4(@RequestParam("xml") String xmlContent) {
    try {
        XStream xstream = new XStream();
        // Configure XStream with TypeHierarchyPermission
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(new TypeHierarchyPermission(new Class[] {
            User.class
        }));
        xstream.alias("user", User.class);
        // ok: java-unsafe-xstream-deserialization
        User user = (User) xstream.fromXML(xmlContent);
        System.out.println("User: " + user.getName());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    try {
        InputStream inputStream = request.getInputStream();
        XStream xstream = new XStream(new JettisonMappedXmlDriver());
        // Configure XStream with AnyTypePermission but only for specific packages
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {
            "java.lang.**",
            "java.util.**",
            "com.example.model.**"
        });
        // ok: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(inputStream);
        System.out.println("Processed object: " + obj);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(Route route) {
    // Using Spark framework with secure XStream
    route.post("/process", (req, res) -> {
        String xmlBody = req.body();
        XStream xstream = new XStream();
        // Configure XStream security
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {
            "com.myapp.model.**"
        });
        // ok: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(xmlBody);
        return "Processed: " + result.toString();
    });
}

public void good_case_7() {
    // Using Vert.x framework with secure XStream
    Vertx.vertx().createHttpServer().requestHandler(req -> {
        req.bodyHandler(body -> {
            String xmlData = body.toString();
            XStream xstream = new XStream();
            // Configure XStream security
            xstream.addPermission(NoTypePermission.NONE);
            xstream.allowTypes(new Class[] {
                String.class,
                Integer.class,
                List.class,
                Map.class
            });
            // ok: java-unsafe-xstream-deserialization
            Object obj = xstream.fromXML(xmlData);
            req.response().end("Processed: " + obj.toString());
        });
    }).listen(8080);
}

public void good_case_8() {
    // Using Ratpack framework with secure XStream
    RatpackServer.start(server -> server
        .handlers(chain -> chain
            .post("api", ctx -> {
                ctx.getRequest().getBody().then(body -> {
                    String xmlData = body.getText();
                    XStream xstream = new XStream();
                    // Configure XStream security
                    xstream.addPermission(NoTypePermission.NONE);
                    xstream.allowTypesByWildcard(new String[] {
                        "com.example.dto.**"
                    });
                    // ok: java-unsafe-xstream-deserialization
                    Object result = xstream.fromXML(xmlData);
                    ctx.render("Processed: " + result.toString());
                });
            })
        )
    );
}

@io.micronaut.http.annotation.Controller("/api")
public void good_case_9(@Body String requestBody) {
    // Using Micronaut framework with secure XStream
    XStream xstream = new XStream();
    // Configure XStream security
    xstream.addPermission(NoTypePermission.NONE);
    xstream.allowTypesByWildcard(new String[] {
        "io.micronaut.dto.**",
        "java.util.**"
    });
    // ok: java-unsafe-xstream-deserialization
    Object result = xstream.fromXML(requestBody);
    return "Processed: " + result.toString();
}

public void good_case_10() {
    // Using OkHttp client with secure XStream
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
    
    try (Response response = client.newCall(request).execute()) {
        String xmlResponse = response.body().string();
        XStream xstream = new XStream();
        // Configure XStream security
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[] {
            String.class,
            Integer.class,
            List.class
        });
        // ok: java-unsafe-xstream-deserialization
        Object data = xstream.fromXML(xmlResponse);
        System.out.println("Processed: " + data);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Using Apache HttpClient with secure XStream
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data.xml");
        CloseableHttpResponse response = httpClient.execute(request);
        
        String xmlContent = EntityUtils.toString(response.getEntity());
        XStream xstream = new XStream();
        // Configure XStream security
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {
            "org.apache.http.entity.**",
            "com.myapp.model.**"
        });
        // ok: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(xmlContent);
        System.out.println("Processed: " + result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Using Play Framework with secure XStream
    play.mvc.Result handleXmlRequest(play.mvc.Http.Request request) {
        String xmlBody = request.body().asText();
        XStream xstream = new XStream();
        // Configure XStream security
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {
            "play.api.data.model.**"
        });
        // ok: java-unsafe-xstream-deserialization
        Object data = xstream.fromXML(xmlBody);
        return ok("Processed: " + data.toString());
    }
}

public void good_case_13() {
    // Using Akka HTTP with secure XStream
    Route route = 
        post(() -> 
            entity(Unmarshaller.entityToString(), xmlData -> {
                XStream xstream = new XStream();
                // Configure XStream security
                xstream.addPermission(NoTypePermission.NONE);
                xstream.allowTypesByWildcard(new String[] {
                    "akka.http.model.**",
                    "com.example.dto.**"
                });
                // ok: java-unsafe-xstream-deserialization
                Object result = xstream.fromXML(xmlData);
                return complete("Processed: " + result.toString());
            })
        );
}

public void good_case_14() {
    // Using Jersey Client with secure XStream
    Client client = ClientBuilder.newClient();
    WebTarget target = client.target("https://api.example.com/data");
    String xmlResponse = target.request().get(String.class);
    
    XStream xstream = new XStream();
    // Configure XStream security
    xstream.addPermission(NoTypePermission.NONE);
    xstream.allowTypesByWildcard(new String[] {
        "javax.ws.rs.core.**",
        "com.example.model.**"
    });
    // ok: java-unsafe-xstream-deserialization
    Object data = xstream.fromXML(xmlResponse);
    System.out.println("Processed: " + data);
}

public void good_case_15() {
    // Using Apache CXF with secure XStream
    WebClient client = WebClient.create("https://api.example.com");
    String xmlResponse = client.path("/data").accept("application/xml").get(String.class);
    
    XStream xstream = new XStream();
    // Configure XStream security
    xstream.addPermission(NoTypePermission.NONE);
    xstream.allowTypesByWildcard(new String[] {
        "org.apache.cxf.model.**",
        "com.example.dto.**"
    });
    // ok: java-unsafe-xstream-deserialization
    Object result = xstream.fromXML(xmlResponse);
    System.out.println("Processed: " + result);
}