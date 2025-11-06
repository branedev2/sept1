import javax.xml.XMLConstants;
import javax.xml.parsers.*;
import javax.xml.validation.*;
import javax.servlet.http.*;
import java.io.*;
import org.xml.sax.*;
import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.w3c.dom.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.xml.sax.helpers.DefaultHandler;
import org.apache.cxf.jaxrs.client.WebClient;
import org.glassfish.jersey.server.ContainerRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.jdom2.input.SAXBuilder;
import org.dom4j.io.SAXReader;
import nu.xom.Builder;
import org.jdom2.input.sax.XMLReaderJDOMFactory;
import org.jdom2.input.sax.XMLReaderSAX2Factory;
import javax.xml.stream.*;

// Security Issue: XML External Entity (XXE) Injection in Schema Factory

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("xml");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<root>test</root>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_2(@RequestBody String xmlContent) {
    try {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new File(xmlContent));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Controller
public void bad_case_3(HttpServletRequest request) {
    try {
        String schemaUrl = request.getParameter("schemaUrl");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new URL(schemaUrl));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public class bad_case_4 implements ServletRequestAware {
    private HttpServletRequest request;
    
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
    
    public void processXml() {
        try {
            String xmlData = request.getParameter("schema");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // ruleid: java-xml-injection-schema-factory
            Schema schema = factory.newSchema(new StreamSource(new ByteArrayInputStream(xmlData.getBytes())));
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader("<root>test</root>")));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

@Path("/api")
public void bad_case_5(@Context HttpServletRequest request) {
    try {
        InputStream inputStream = request.getInputStream();
        String xmlData = IOUtils.toString(inputStream, "UTF-8");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Path("/upload")
public void bad_case_6(MultipartFormDataInput input) {
    try {
        InputStream stream = input.getFormDataPart("schema", InputStream.class, null);
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(stream));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("http://example.com/api");
        CloseableHttpResponse response = httpClient.execute(httpPost);
        HttpEntity entity = response.getEntity();
        String xmlData = EntityUtils.toString(entity);
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if ("schema".equals(item.getFieldName())) {
                InputStream inputStream = item.getInputStream();
                SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                // ruleid: java-xml-injection-schema-factory
                Schema schema = factory.newSchema(new StreamSource(inputStream));
                Validator validator = schema.newValidator();
                validator.validate(new StreamSource(new StringReader("<data>test</data>")));
                break;
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    try {
        Client client = Client.create();
        WebResource webResource = client.resource("http://example.com/api/schema");
        String xmlData = webResource.get(String.class);
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(ContainerRequest request) {
    try {
        InputStream entityStream = request.getEntityStream();
        String xmlData = IOUtils.toString(entityStream, "UTF-8");
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    try {
        String xmlData = request.getHeader("X-Schema-Data");
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        XMLReader reader = parser.getXMLReader();
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        reader.setProperty("http://java.sun.com/xml/jaxp/properties/schemaSource", schema);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        XMLReaderJDOMFactory factory = new XMLReaderSAX2Factory(false);
        SAXBuilder builder = new SAXBuilder(factory);
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        builder.setSchema(schema);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        SAXReader reader = new SAXReader();
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        reader.setValidation(true);
        reader.setProperty("http://java.sun.com/xml/jaxp/properties/schemaSource", schema);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        Builder builder = new Builder();
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        // XOM doesn't directly support schema validation, but we're testing the schema creation
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        XMLInputFactory inputFactory = XMLInputFactory.newInstance();
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java-xml-injection-schema-factory
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        
        // Using StAX with schema validation
        XMLStreamReader reader = inputFactory.createXMLStreamReader(new StringReader("<root>test</root>"));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("xml");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<root>test</root>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_2(@RequestBody String xmlContent) {
    try {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new File(xmlContent));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Controller
public void good_case_3(HttpServletRequest request) {
    try {
        String schemaUrl = request.getParameter("schemaUrl");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Schema schema = factory.newSchema(new URL(schemaUrl));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public class good_case_4 implements ServletRequestAware {
    private HttpServletRequest request;
    
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
    
    public void processXml() {
        try {
            String xmlData = request.getParameter("schema");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // ok: java-xml-injection-schema-factory
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema(new StreamSource(new ByteArrayInputStream(xmlData.getBytes())));
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader("<root>test</root>")));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

@Path("/api")
public void good_case_5(@Context HttpServletRequest request) {
    try {
        InputStream inputStream = request.getInputStream();
        String xmlData = IOUtils.toString(inputStream, "UTF-8");
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Path("/upload")
public void good_case_6(MultipartFormDataInput input) {
    try {
        InputStream stream = input.getFormDataPart("schema", InputStream.class, null);
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(stream));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("http://example.com/api");
        CloseableHttpResponse response = httpClient.execute(httpPost);
        HttpEntity entity = response.getEntity();
        String xmlData = EntityUtils.toString(entity);
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if ("schema".equals(item.getFieldName())) {
                InputStream inputStream = item.getInputStream();
                SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                // ok: java-xml-injection-schema-factory
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                Schema schema = factory.newSchema(new StreamSource(inputStream));
                Validator validator = schema.newValidator();
                validator.validate(new StreamSource(new StringReader("<data>test</data>")));
                break;
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    try {
        Client client = Client.create();
        WebResource webResource = client.resource("http://example.com/api/schema");
        String xmlData = webResource.get(String.class);
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(ContainerRequest request) {
    try {
        InputStream entityStream = request.getEntityStream();
        String xmlData = IOUtils.toString(entityStream, "UTF-8");
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader("<data>test</data>")));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    try {
        String xmlData = request.getHeader("X-Schema-Data");
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        XMLReader reader = parser.getXMLReader();
        
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        reader.setProperty("http://java.sun.com/xml/jaxp/properties/schemaSource", schema);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        XMLReaderJDOMFactory factory = new XMLReaderSAX2Factory(false);
        SAXBuilder builder = new SAXBuilder(factory);
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        schemaFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        builder.setSchema(schema);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        SAXReader reader = new SAXReader();
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        reader.setValidation(true);
        reader.setProperty("http://java.sun.com/xml/jaxp/properties/schemaSource", schema);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        Builder builder = new Builder();
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        schemaFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        // XOM doesn't directly support schema validation, but we're testing the schema creation
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("schema");
        XMLInputFactory inputFactory = XMLInputFactory.newInstance();
        
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ok: java-xml-injection-schema-factory
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
        
        // Using StAX with schema validation
        XMLStreamReader reader = inputFactory.createXMLStreamReader(new StringReader("<root>test</root>"));
    } catch (Exception e) {
        e.printStackTrace();
    }
}