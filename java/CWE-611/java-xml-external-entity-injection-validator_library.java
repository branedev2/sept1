import javax.xml.XMLConstants;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.xml.sax.SAXException;
import java.io.IOException;
import java.io.StringReader;
import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.stream.StreamSource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.apache.commons.io.IOUtils;
import org.apache.struts2.ServletActionContext;
import org.glassfish.jersey.server.ResourceConfig;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.MultipartBody;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import spark.Request;
import spark.Response;
import play.mvc.Http;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

// Security Issue: XML External Entity Injection through improperly configured Validators

// True Positive Examples (Vulnerable/Insecure Code)
public class XXEVulnerableExamples {

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws SAXException, IOException {
        String xmlData = request.getParameter("xml");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema(new StreamSource(new StringReader("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'></xs:schema>")));
        
        // ruleid: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    @PostMapping("/validate-xml")
    public void bad_case_2(@RequestBody String xmlContent) throws SAXException, IOException {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            Schema schema = factory.newSchema(new StreamSource(new StringReader("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'></xs:schema>")));
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() throws SAXException, IOException {
        HttpServletRequest request = ServletActionContext.getRequest();
        String xmlData = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema();
        
        // ruleid: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        // Only setting one property but missing others
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    @Path("/xml")
    public static class bad_case_4 {
        @POST
        @Consumes(MediaType.APPLICATION_XML)
        public String processXml(String xmlContent) throws SAXException, IOException {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            try {
                Schema schema = factory.newSchema();
                
                // ruleid: java-xml-external-entity-injection-validator
                Validator validator = schema.newValidator();
                // Only setting one property but missing others
                validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                validator.validate(new StreamSource(new StringReader(xmlContent)));
                return "XML validated";
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    @Path("/multipart")
    public static class bad_case_5 {
        @POST
        @Consumes(MediaType.MULTIPART_FORM_DATA)
        public String processMultipart(MultipartBody body) throws SAXException, IOException {
            Attachment attachment = body.getAttachment("xml");
            String xmlContent = IOUtils.toString(attachment.getDataHandler().getInputStream(), StandardCharsets.UTF_8);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            // Setting FEATURE_SECURE_PROCESSING but missing other crucial settings
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "XML validated";
        }
    }

    public void bad_case_6(RoutingContext routingContext) throws SAXException, IOException {
        HttpServerRequest request = routingContext.request();
        request.bodyHandler(buffer -> {
            try {
                String xmlContent = buffer.toString();
                SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                Schema schema = factory.newSchema();
                
                // ruleid: java-xml-external-entity-injection-validator
                Validator validator = schema.newValidator();
                validator.validate(new StreamSource(new StringReader(xmlContent)));
            } catch (Exception e) {
                routingContext.fail(e);
            }
        });
    }

    @Controller("/api")
    public static class bad_case_7 {
        @Post("/validate")
        public String validateXml(HttpRequest<?> request) throws SAXException, IOException {
            String xmlContent = request.getBody().orElse("").toString();
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "Validation complete";
        }
    }

    @RouteBase(path = "/api")
    public static class bad_case_8 {
        @Route(path = "validate", methods = io.quarkus.vertx.web.Route.HttpMethod.POST)
        public void validateXml(io.vertx.ext.web.RoutingContext rc) {
            rc.request().bodyHandler(buffer -> {
                try {
                    String xmlContent = buffer.toString();
                    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    Schema schema = factory.newSchema();
                    
                    // ruleid: java-xml-external-entity-injection-validator
                    Validator validator = schema.newValidator();
                    validator.validate(new StreamSource(new StringReader(xmlContent)));
                    rc.response().end("Validation complete");
                } catch (Exception e) {
                    rc.fail(e);
                }
            });
        }
    }

    @RestController
    public static class bad_case_9 {
        @PostMapping("/upload-xml")
        public ResponseEntity<String> uploadXml(MultipartHttpServletRequest request) throws SAXException, IOException {
            MultipartFile file = request.getFile("xml");
            String xmlContent = new String(file.getBytes(), StandardCharsets.UTF_8);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return ResponseEntity.ok("XML validated");
        }
    }

    public static String bad_case_10(Request request, Response response) throws SAXException, IOException {
        String xmlContent = request.body();
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema();
        
        // ruleid: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader(xmlContent)));
        return "XML validated";
    }

    public static class bad_case_11 extends play.mvc.Controller {
        public play.mvc.Result validateXml() throws SAXException, IOException {
            Http.Request request = request();
            String xmlContent = request.body().asText();
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return ok("XML validated");
        }
    }

    public static class bad_case_12 implements Handler {
        @Override
        public void handle(Context context) throws Exception {
            context.getRequest().getBody().then(body -> {
                try {
                    String xmlContent = body.getText();
                    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    Schema schema = factory.newSchema();
                    
                    // ruleid: java-xml-external-entity-injection-validator
                    Validator validator = schema.newValidator();
                    validator.validate(new StreamSource(new StringReader(xmlContent)));
                    context.render("XML validated");
                } catch (Exception e) {
                    context.error(e);
                }
                return null;
            });
        }
    }

    @Path("/resteasy")
    public static class bad_case_13 {
        @POST
        @Consumes(MediaType.MULTIPART_FORM_DATA)
        public String processMultipart(MultipartFormDataInput input) throws SAXException, IOException {
            String xmlContent = input.getFormDataPart("xml", String.class, null);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "XML validated";
        }
    }

    public void bad_case_14(HttpServletRequest request) throws SAXException, IOException {
        String xmlData = request.getHeader("X-XML-Data");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema();
        
        // ruleid: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        // Incomplete security configuration - missing AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    public void bad_case_15(HttpServletRequest request) throws SAXException, IOException, ParserConfigurationException {
        String xmlData = request.getParameter("xml");
        
        // Creating a schema from an XML file
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        InputStream schemaStream = new ByteArrayInputStream("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'></xs:schema>".getBytes());
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema(new StreamSource(schemaStream));
        
        // ruleid: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        // Incomplete security configuration - missing AC_REDACTED_TWILIO_ID_EXTERNAL_DTD
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) throws SAXException, IOException {
        String xmlData = request.getParameter("xml");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'></xs:schema>")));
        
        // ok: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    @PostMapping("/validate-xml-secure")
    public void good_case_2(@RequestBody String xmlContent) throws SAXException, IOException {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'></xs:schema>")));
        
        // ok: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlContent)));
    }

    public void good_case_3() throws SAXException, IOException {
        HttpServletRequest request = ServletActionContext.getRequest();
        String xmlData = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema();
        
        // ok: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    @Path("/xml-secure")
    public static class good_case_4 {
        @POST
        @Consumes(MediaType.APPLICATION_XML)
        public String processXml(String xmlContent) throws SAXException, IOException {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ok: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "XML validated securely";
        }
    }

    @Path("/multipart-secure")
    public static class good_case_5 {
        @POST
        @Consumes(MediaType.MULTIPART_FORM_DATA)
        public String processMultipart(MultipartBody body) throws SAXException, IOException {
            Attachment attachment = body.getAttachment("xml");
            String xmlContent = IOUtils.toString(attachment.getDataHandler().getInputStream(), StandardCharsets.UTF_8);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ok: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "XML validated securely";
        }
    }

    public void good_case_6(RoutingContext routingContext) throws SAXException, IOException {
        HttpServerRequest request = routingContext.request();
        request.bodyHandler(buffer -> {
            try {
                String xmlContent = buffer.toString();
                SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                Schema schema = factory.newSchema();
                
                // ok: java-xml-external-entity-injection-validator
                Validator validator = schema.newValidator();
                validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                validator.validate(new StreamSource(new StringReader(xmlContent)));
            } catch (Exception e) {
                routingContext.fail(e);
            }
        });
    }

    @Controller("/api-secure")
    public static class good_case_7 {
        @Post("/validate")
        public String validateXml(HttpRequest<?> request) throws SAXException, IOException {
            String xmlContent = request.getBody().orElse("").toString();
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ok: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "Validation complete securely";
        }
    }

    @RouteBase(path = "/api-secure")
    public static class good_case_8 {
        @Route(path = "validate", methods = io.quarkus.vertx.web.Route.HttpMethod.POST)
        public void validateXml(io.vertx.ext.web.RoutingContext rc) {
            rc.request().bodyHandler(buffer -> {
                try {
                    String xmlContent = buffer.toString();
                    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                    factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                    Schema schema = factory.newSchema();
                    
                    // ok: java-xml-external-entity-injection-validator
                    Validator validator = schema.newValidator();
                    validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                    validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                    validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                    validator.validate(new StreamSource(new StringReader(xmlContent)));
                    rc.response().end("Validation complete securely");
                } catch (Exception e) {
                    rc.fail(e);
                }
            });
        }
    }

    @RestController
    public static class good_case_9 {
        @PostMapping("/upload-xml-secure")
        public ResponseEntity<String> uploadXml(MultipartHttpServletRequest request) throws SAXException, IOException {
            MultipartFile file = request.getFile("xml");
            String xmlContent = new String(file.getBytes(), StandardCharsets.UTF_8);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ok: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return ResponseEntity.ok("XML validated securely");
        }
    }

    public static String good_case_10(Request request, Response response) throws SAXException, IOException {
        String xmlContent = request.body();
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema();
        
        // ok: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlContent)));
        return "XML validated securely";
    }

    public static class good_case_11 extends play.mvc.Controller {
        public play.mvc.Result validateXml() throws SAXException, IOException {
            Http.Request request = request();
            String xmlContent = request.body().asText();
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ok: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return ok("XML validated securely");
        }
    }

    public static class good_case_12 implements Handler {
        @Override
        public void handle(Context context) throws Exception {
            context.getRequest().getBody().then(body -> {
                try {
                    String xmlContent = body.getText();
                    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                    factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                    Schema schema = factory.newSchema();
                    
                    // ok: java-xml-external-entity-injection-validator
                    Validator validator = schema.newValidator();
                    validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                    validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                    validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                    validator.validate(new StreamSource(new StringReader(xmlContent)));
                    context.render("XML validated securely");
                } catch (Exception e) {
                    context.error(e);
                }
                return null;
            });
        }
    }

    @Path("/resteasy-secure")
    public static class good_case_13 {
        @POST
        @Consumes(MediaType.MULTIPART_FORM_DATA)
        public String processMultipart(MultipartFormDataInput input) throws SAXException, IOException {
            String xmlContent = input.getFormDataPart("xml", String.class, null);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ok: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            return "XML validated securely";
        }
    }

    public void good_case_14(HttpServletRequest request) throws SAXException, IOException {
        String xmlData = request.getHeader("X-XML-Data");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema();
        
        // ok: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }

    public void good_case_15(HttpServletRequest request) throws SAXException, IOException, ParserConfigurationException {
        String xmlData = request.getParameter("xml");
        
        // Creating a schema from an XML file
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        DocumentBuilder db = dbf.newDocumentBuilder();
        InputStream schemaStream = new ByteArrayInputStream("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'></xs:schema>".getBytes());
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(schemaStream));
        
        // ok: java-xml-external-entity-injection-validator
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        validator.validate(new StreamSource(new StringReader(xmlData)));
    }
}
// {/fact}