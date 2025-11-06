import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamException;
import java.io.StringReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.File;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import javax.ws.rs.core.Context;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.glassfish.jersey.server.ResourceConfig;
import spark.Request;
import spark.Response;
import spark.Spark;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.http.Request;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import java.util.Map;

// Security Issue: XML External Entity (XXE) Injection with XMLInputFactory

// True Positive Examples (Vulnerable/Insecure Code)
public class XXEVulnerabilities {

    // Using XMLInputFactory with default settings in a Spring MVC controller
    @RestController
    public static class bad_case_1 {
        @PostMapping("/parse-xml")
        public String parseXml(@RequestBody String xmlData) throws Exception {
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            
            // Process XML
            StringBuilder result = new StringBuilder();
            while (reader.hasNext()) {
                reader.next();
                if (reader.isStartElement()) {
                    result.append(reader.getLocalName()).append(": ");
                } else if (reader.isCharacters()) {
                    result.append(reader.getText()).append("\n");
                }
            }
            return result.toString();
        }
    }

    // Using XMLInputFactory with JAX-RS (Jersey)
    @Path("/xml")
    public static class bad_case_2 {
        @POST
        @Path("/process")
        @Produces(MediaType.TEXT_PLAIN)
        public String processXml(@Context javax.ws.rs.core.Request request, String xmlContent) throws Exception {
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
            StringReader stringReader = new StringReader(xmlContent);
            XMLStreamReader xmlReader = xmlInputFactory.createXMLStreamReader(stringReader);
            
            // Process XML data
            StringBuilder output = new StringBuilder();
            while (xmlReader.hasNext()) {
                xmlReader.next();
                if (xmlReader.isStartElement()) {
                    output.append("Element: ").append(xmlReader.getLocalName()).append("\n");
                }
            }
            return output.toString();
        }
    }

    // Using XMLInputFactory with Servlet API
    public static class bad_case_3 implements javax.servlet.http.HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
            String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            
            // Process XML
            response.getWriter().println("XML processed successfully");
        }
    }

    // Using XMLInputFactory with Apache Struts
    public static class bad_case_4 implements ServletRequestAware {
        private HttpServletRequest request;
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public String processXml() throws Exception {
            String xmlContent = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory inputFactory = XMLInputFactory.newInstance();
            XMLStreamReader reader = inputFactory.createXMLStreamReader(new ByteArrayInputStream(xmlContent.getBytes()));
            
            // Process XML
            return "success";
        }
    }

    // Using XMLInputFactory with Spark Framework
    public static class bad_case_5 {
        public void setupRoutes() {
            Spark.post("/xml", (spark.Request request, spark.Response response) -> {
                String xmlBody = request.body();
                
                // ruleid: java-xml-external-entity-injection-xml-input-factory
                XMLInputFactory factory = XMLInputFactory.newFactory();
                XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlBody));
                
                // Process XML
                return "XML processed with Spark";
            });
        }
    }

    // Using XMLInputFactory with Vert.x
    public static class bad_case_6 {
        public void handleRequest(Vertx vertx) {
            Router router = Router.router(vertx);
            
            router.post("/api/xml").handler(routingContext -> {
                HttpServerRequest request = routingContext.request();
                request.bodyHandler(buffer -> {
                    try {
                        String xmlContent = buffer.toString();
                        
                        // ruleid: java-xml-external-entity-injection-xml-input-factory
                        XMLInputFactory factory = XMLInputFactory.newInstance();
                        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
                        
                        // Process XML
                        routingContext.response().end("XML processed with Vert.x");
                    } catch (Exception e) {
                        routingContext.fail(e);
                    }
                });
            });
        }
    }

    // Using XMLInputFactory with Play Framework
    public static class bad_case_7 extends Controller {
        public Result processXml(Http.Request request) throws Exception {
            String xmlBody = request.body().asText();
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlBody));
            
            // Process XML
            return ok("XML processed with Play Framework");
        }
    }

    // Using XMLInputFactory with Ratpack
    public static class bad_case_8 implements Handler {
        @Override
        public void handle(Context ctx) throws Exception {
            ctx.getRequest().getBody().then(body -> {
                try {
                    String xmlContent = body.getText();
                    
                    // ruleid: java-xml-external-entity-injection-xml-input-factory
                    XMLInputFactory factory = XMLInputFactory.newInstance();
                    XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
                    
                    // Process XML
                    ctx.render("XML processed with Ratpack");
                } catch (Exception e) {
                    ctx.error(e);
                }
            });
        }
    }

    // Using XMLInputFactory with com.sun.net.httpserver
    public static class bad_case_9 implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws Exception {
            String requestBody = IOUtils.toString(exchange.getRequestBody(), "UTF-8");
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(requestBody));
            
            // Process XML
            String response = "XML processed with HttpServer";
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        }
    }

    // Using XMLInputFactory with RESTEasy multipart
    @Path("/upload")
    public static class bad_case_10 {
        @POST
        @Produces(MediaType.TEXT_PLAIN)
        public String uploadXml(MultipartFormDataInput input) throws Exception {
            Map<String, org.jboss.resteasy.plugins.providers.multipart.InputPart> uploadForm = input.getFormDataMap();
            org.jboss.resteasy.plugins.providers.multipart.InputPart inputPart = uploadForm.get("file").get(0);
            String xmlContent = inputPart.getBodyAsString();
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            // Process XML
            return "XML processed with RESTEasy";
        }
    }

    // Using XMLInputFactory with Jersey multipart
    @Path("/jersey")
    public static class bad_case_11 {
        @POST
        @Path("/upload")
        public String uploadFile(@FormDataParam("file") String xmlContent) throws Exception {
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            // Process XML
            return "XML processed with Jersey multipart";
        }
    }

    // Using XMLInputFactory with Apache HttpClient
    public static class bad_case_12 {
        public String fetchAndProcessXml(String url) throws Exception {
            HttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            HttpResponse response = client.execute(request);
            HttpEntity entity = response.getEntity();
            String xmlContent = IOUtils.toString(entity.getContent(), "UTF-8");
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            // Process XML
            return "XML processed from remote URL";
        }
    }

    // Using XMLInputFactory with Spring WebClient
    public static class bad_case_13 {
        public void processWebClientResponse() throws Exception {
            // Simulating WebClient response body as String
            String xmlResponse = getWebClientResponse();
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlResponse));
            
            // Process XML
        }
        
        private String getWebClientResponse() {
            // Simulated WebClient response
            return "<xml>data</xml>";
        }
    }

    // Using XMLInputFactory with URL connection
    public static class bad_case_14 {
        public void processXmlFromUrl(String urlString) throws Exception {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            InputStream inputStream = connection.getInputStream();
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
            
            // Process XML
        }
    }

    // Using XMLInputFactory with custom HTTP client
    public static class bad_case_15 {
        public void processXmlWithCustomClient(String endpoint) throws Exception {
            // Simulated custom HTTP client
            InputStream responseStream = makeHttpRequest(endpoint);
            
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(responseStream);
            
            // Process XML
        }
        
        private InputStream makeHttpRequest(String endpoint) {
            // Simulated HTTP request
            return new ByteArrayInputStream("<xml>data</xml>".getBytes());
        }
    }

    // True Negative Examples (Safe/Secure Code)
    
    // Using XMLInputFactory with Spring MVC controller - secure configuration
    @RestController
    public static class good_case_1 {
        @PostMapping("/parse-xml-secure")
        public String parseXmlSecurely(@RequestBody String xmlData) throws Exception {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            
            // Process XML
            StringBuilder result = new StringBuilder();
            while (reader.hasNext()) {
                reader.next();
                if (reader.isStartElement()) {
                    result.append(reader.getLocalName()).append(": ");
                } else if (reader.isCharacters()) {
                    result.append(reader.getText()).append("\n");
                }
            }
            return result.toString();
        }
    }

    // Using XMLInputFactory with JAX-RS (Jersey) - secure configuration
    @Path("/xml")
    public static class good_case_2 {
        @POST
        @Path("/process-secure")
        @Produces(MediaType.TEXT_PLAIN)
        public String processXmlSecurely(@Context javax.ws.rs.core.Request request, String xmlContent) throws Exception {
            XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
            // ok: java-xml-external-entity-injection-xml-input-factory
            xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            StringReader stringReader = new StringReader(xmlContent);
            XMLStreamReader xmlReader = xmlInputFactory.createXMLStreamReader(stringReader);
            
            // Process XML data
            StringBuilder output = new StringBuilder();
            while (xmlReader.hasNext()) {
                xmlReader.next();
                if (xmlReader.isStartElement()) {
                    output.append("Element: ").append(xmlReader.getLocalName()).append("\n");
                }
            }
            return output.toString();
        }
    }

    // Using XMLInputFactory with Servlet API - secure configuration
    public static class good_case_3 implements javax.servlet.http.HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
            String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            
            // Process XML
            response.getWriter().println("XML processed securely");
        }
    }

    // Using XMLInputFactory with Apache Struts - secure configuration
    public static class good_case_4 implements ServletRequestAware {
        private HttpServletRequest request;
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public String processXmlSecurely() throws Exception {
            String xmlContent = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            XMLInputFactory inputFactory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = inputFactory.createXMLStreamReader(new ByteArrayInputStream(xmlContent.getBytes()));
            
            // Process XML
            return "success";
        }
    }

    // Using XMLInputFactory with Spark Framework - secure configuration
    public static class good_case_5 {
        public void setupRoutes() {
            Spark.post("/xml-secure", (spark.Request request, spark.Response response) -> {
                String xmlBody = request.body();
                
                XMLInputFactory factory = XMLInputFactory.newFactory();
                // ok: java-xml-external-entity-injection-xml-input-factory
                factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
                factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
                XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlBody));
                
                // Process XML
                return "XML processed securely with Spark";
            });
        }
    }

    // Using XMLInputFactory with Vert.x - secure configuration
    public static class good_case_6 {
        public void handleRequest(Vertx vertx) {
            Router router = Router.router(vertx);
            
            router.post("/api/xml-secure").handler(routingContext -> {
                HttpServerRequest request = routingContext.request();
                request.bodyHandler(buffer -> {
                    try {
                        String xmlContent = buffer.toString();
                        
                        XMLInputFactory factory = XMLInputFactory.newInstance();
                        // ok: java-xml-external-entity-injection-xml-input-factory
                        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
                        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
                        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
                        
                        // Process XML
                        routingContext.response().end("XML processed securely with Vert.x");
                    } catch (Exception e) {
                        routingContext.fail(e);
                    }
                });
            });
        }
    }

    // Using XMLInputFactory with Play Framework - secure configuration
    public static class good_case_7 extends Controller {
        public Result processXmlSecurely(Http.Request request) throws Exception {
            String xmlBody = request.body().asText();
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlBody));
            
            // Process XML
            return ok("XML processed securely with Play Framework");
        }
    }

    // Using XMLInputFactory with Ratpack - secure configuration
    public static class good_case_8 implements Handler {
        @Override
        public void handle(Context ctx) throws Exception {
            ctx.getRequest().getBody().then(body -> {
                try {
                    String xmlContent = body.getText();
                    
                    XMLInputFactory factory = XMLInputFactory.newInstance();
                    // ok: java-xml-external-entity-injection-xml-input-factory
                    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
                    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
                    XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
                    
                    // Process XML
                    ctx.render("XML processed securely with Ratpack");
                } catch (Exception e) {
                    ctx.error(e);
                }
            });
        }
    }

    // Using XMLInputFactory with com.sun.net.httpserver - secure configuration
    public static class good_case_9 implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws Exception {
            String requestBody = IOUtils.toString(exchange.getRequestBody(), "UTF-8");
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(requestBody));
            
            // Process XML
            String response = "XML processed securely with HttpServer";
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        }
    }

    // Using XMLInputFactory with RESTEasy multipart - secure configuration
    @Path("/upload")
    public static class good_case_10 {
        @POST
        @Path("/secure")
        @Produces(MediaType.TEXT_PLAIN)
        public String uploadXmlSecurely(MultipartFormDataInput input) throws Exception {
            Map<String, org.jboss.resteasy.plugins.providers.multipart.InputPart> uploadForm = input.getFormDataMap();
            org.jboss.resteasy.plugins.providers.multipart.InputPart inputPart = uploadForm.get("file").get(0);
            String xmlContent = inputPart.getBodyAsString();
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            // Process XML
            return "XML processed securely with RESTEasy";
        }
    }

    // Using XMLInputFactory with Jersey multipart - secure configuration
    @Path("/jersey")
    public static class good_case_11 {
        @POST
        @Path("/upload-secure")
        public String uploadFileSecurely(@FormDataParam("file") String xmlContent) throws Exception {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            // Process XML
            return "XML processed securely with Jersey multipart";
        }
    }

    // Using XMLInputFactory with Apache HttpClient - secure configuration
    public static class good_case_12 {
        public String fetchAndProcessXmlSecurely(String url) throws Exception {
            HttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            HttpResponse response = client.execute(request);
            HttpEntity entity = response.getEntity();
            String xmlContent = IOUtils.toString(entity.getContent(), "UTF-8");
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            // Process XML
            return "XML processed securely from remote URL";
        }
    }

    // Using XMLInputFactory with Spring WebClient - secure configuration
    public static class good_case_13 {
        public void processWebClientResponseSecurely() throws Exception {
            // Simulating WebClient response body as String
            String xmlResponse = getWebClientResponse();
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlResponse));
            
            // Process XML
        }
        
        private String getWebClientResponse() {
            // Simulated WebClient response
            return "<xml>data</xml>";
        }
    }

    // Using XMLInputFactory with URL connection - secure configuration
    public static class good_case_14 {
        public void processXmlFromUrlSecurely(String urlString) throws Exception {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            InputStream inputStream = connection.getInputStream();
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
            
            // Process XML
        }
    }

    // Using XMLInputFactory with custom HTTP client - secure configuration
    public static class good_case_15 {
        public void processXmlWithCustomClientSecurely(String endpoint) throws Exception {
            // Simulated custom HTTP client
            InputStream responseStream = makeHttpRequest(endpoint);
            
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(responseStream);
            
            // Process XML
        }
        
        private InputStream makeHttpRequest(String endpoint) {
            // Simulated HTTP request
            return new ByteArrayInputStream("<xml>data</xml>".getBytes());
        }
    }
}