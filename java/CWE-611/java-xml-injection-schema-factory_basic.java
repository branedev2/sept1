import javax.xml.XMLConstants;
import javax.xml.validation.SchemaFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import org.xml.sax.SAXException;
import java.io.StringReader;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.io.BufferedReader;
import java.net.URL;
import java.net.HttpURLConnection;

// Vulnerable examples (bad cases)

@WebServlet("/bad1")
public class Bad_Case_1 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xmlContent = request.getParameter("xml");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            // Process schema...
        } catch (SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad2")
public class Bad_Case_2 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String schemaUrl = request.getParameter("schemaUrl");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = new URL(schemaUrl);
            Schema schema = factory.newSchema(new StreamSource(url.openStream()));
            response.getWriter().println("Schema loaded successfully");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad3")
public class Bad_Case_3 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String xmlData = sb.toString();
        
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
            // Use schema for validation...
        } catch (SAXException e) {
            response.getWriter().println("Schema error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad4")
public class Bad_Case_4 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new StreamSource(xmlStream));
            response.getWriter().println("Schema processed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad5")
public class Bad_Case_5 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String schemaUrl = request.getParameter("schema");
        URL url = new URL(schemaUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new StreamSource(conn.getInputStream()));
            response.getWriter().println("Remote schema loaded");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad6")
public class Bad_Case_6 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xsdContent = request.getParameter("xsd");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            // Still vulnerable because AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA is not set
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xsdContent)));
            response.getWriter().println("Schema created");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad7")
public class Bad_Case_7 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xmlHeader = request.getParameter("header");
        String xmlBody = request.getParameter("body");
        String xmlContent = xmlHeader + "<root>" + xmlBody + "</root>";
        
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlContent)));
            // Use schema...
        } catch (SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad8")
public class Bad_Case_8 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xsdPath = request.getParameter("xsdPath");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL resourceUrl = new URL(xsdPath);
            Schema schema = factory.newSchema(resourceUrl);
            response.getWriter().println("Schema loaded from: " + xsdPath);
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad9")
public class Bad_Case_9 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String schemaType = request.getParameter("type");
        String schemaContent = request.getParameter("content");
        
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(schemaType);
            Schema schema = factory.newSchema(new StreamSource(new StringReader(schemaContent)));
            response.getWriter().println("Custom schema type processed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad10")
public class Bad_Case_10 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xsdUrl = request.getParameter("xsdUrl");
        try {
            URL url = new URL(xsdUrl);
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // Still vulnerable to XXE through external schema references
            Schema schema = factory.newSchema(new StreamSource(url.openStream()));
            response.getWriter().println("Schema loaded");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad11")
public class Bad_Case_11 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xmlData = request.getHeader("X-XML-Data");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("Schema from header processed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad12")
public class Bad_Case_12 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] schemaUrls = request.getParameterValues("schemaUrls");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            StreamSource[] sources = new StreamSource[schemaUrls.length];
            for (int i = 0; i < schemaUrls.length; i++) {
                URL url = new URL(schemaUrls[i]);
                sources[i] = new StreamSource(url.openStream());
            }
            Schema schema = factory.newSchema(sources);
            response.getWriter().println("Multiple schemas loaded");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad13")
public class Bad_Case_13 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xsdContent = request.getParameter("xsd");
        boolean enableDtd = Boolean.parseBoolean(request.getParameter("enableDtd"));
        
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            if (!enableDtd) {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            }
            // Still vulnerable to XXE through external schema
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xsdContent)));
            response.getWriter().println("Schema processed with DTD " + (enableDtd ? "enabled" : "disabled"));
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad14")
public class Bad_Case_14 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String schemaUrl = request.getParameter("schema");
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "all");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "all");
            Schema schema = factory.newSchema(new URL(schemaUrl));
            response.getWriter().println("Schema loaded with external access enabled");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/bad15")
public class Bad_Case_15 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xmlContent = request.getParameter("xml");
        String schemaType = XMLConstants.W3C_XML_SCHEMA_NS_URI;
        
        try {
            // ruleid: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(schemaType);
            // No security features configured
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("Schema processed successfully");
        } catch (Exception e) {
            response.getWriter().println("Error processing schema: " + e.getMessage());
        }
    }
}

// Secure examples (good cases)

@WebServlet("/good1")
public class Good_Case_1 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xmlContent = request.getParameter("xml");
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            // Process schema...
        } catch (SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good2")
public class Good_Case_2 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String schemaUrl = request.getParameter("schemaUrl");
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            URL url = new URL(schemaUrl);
            Schema schema = factory.newSchema(new StreamSource(url.openStream()));
            response.getWriter().println("Schema loaded securely");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good3")
public class Good_Case_3 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String xmlData = sb.toString();
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schemaFactory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            schemaFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            schemaFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(xmlData)));
            // Use schema for validation...
        } catch (Exception e) {
            response.getWriter().println("Schema error: " + e.getMessage());
        }
    }
}

@WebServlet("/good4")
public class Good_Case_4 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Schema schema = factory.newSchema(new StreamSource(xmlStream));
            response.getWriter().println("Schema processed securely");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good5")
public class Good_Case_5 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Use a predefined schema from a trusted location instead of user input
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            // Using a trusted schema file from the classpath
            InputStream schemaStream = getClass().getResourceAsStream("/trusted-schema.xsd");
            Schema schema = factory.newSchema(new StreamSource(schemaStream));
            response.getWriter().println("Trusted schema loaded");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good6")
public class Good_Case_6 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xsdContent = request.getParameter("xsd");
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xsdContent)));
            response.getWriter().println("Schema created securely");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good7")
public class Good_Case_7 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Validate against an allowlist of known schema URLs
        String requestedSchema = request.getParameter("schema");
        String[] allowedSchemas = {
            "https://trusted-domain.com/schema1.xsd",
            "https://trusted-domain.com/schema2.xsd"
        };
        
        boolean isAllowed = false;
        for (String allowed : allowedSchemas) {
            if (allowed.equals(requestedSchema)) {
                isAllowed = true;
                break;
            }
        }
        
        if (!isAllowed) {
            response.getWriter().println("Requested schema not allowed");
            return;
        }
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            URL url = new URL(requestedSchema);
            Schema schema = factory.newSchema(new StreamSource(url.openStream()));
            response.getWriter().println("Allowed schema loaded securely");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good8")
public class Good_Case_8 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a pre-compiled schema instead of user input
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            // Using a hardcoded schema definition instead of user input
            String trustedSchema = "<?xml version=\"1.0\"?><xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"><xs:element name=\"root\" type=\"xs:string\"/></xs:schema>";
            Schema schema = factory.newSchema(new StreamSource(new StringReader(trustedSchema)));
            response.getWriter().println("Hardcoded schema loaded securely");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good9")
public class Good_Case_9 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String xmlContent = request.getParameter("xml");
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // Set all security properties
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("Schema processed with comprehensive security settings");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good10")
public class Good_Case_10 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a custom validator that sanitizes the XML content before processing
        String xmlContent = request.getParameter("xml");
        
        // Simple sanitization (in practice, use a more robust solution)
        if (xmlContent.contains("<!ENTITY") || xmlContent.contains("<!DOCTYPE")) {
            response.getWriter().println("Potentially malicious XML detected");
            return;
        }
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("Sanitized schema processed securely");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good11")
public class Good_Case_11 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a factory method that applies all security settings
        String xmlData = request.getParameter("xml");
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = createSecureSchemaFactory();
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("Schema processed using secure factory");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    private SchemaFactory createSecureSchemaFactory() throws SAXException {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        return factory;
    }
}

@WebServlet("/good12")
public class Good_Case_12 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a secure schema with limited permissions for external resources
        String xmlContent = request.getParameter("xml");
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // Allow only specific local resources if needed
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "file:///opt/app/trusted-dtds");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("Schema processed with limited permissions");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good13")
public class Good_Case_13 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a schema validator with custom error handling
        String xmlData = request.getParameter("xml");
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            // Set custom error handler
            factory.setErrorHandler(new org.xml.sax.ErrorHandler() {
                public void warning(org.xml.sax.SAXParseException e) {
                    // Log warning
                }
                public void error(org.xml.sax.SAXParseException e) {
                    // Log error
                }
                public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException {
                    throw e;
                }
            });
            
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("Schema processed with custom error handling");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good14")
public class Good_Case_14 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a secure schema with thread-local security settings
        final ThreadLocal<SchemaFactory> secureFactory = new ThreadLocal<SchemaFactory>() {
            @Override
            protected SchemaFactory initialValue() {
                try {
                    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                    factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                    return factory;
                } catch (Exception e) {
                    throw new RuntimeException("Failed to create secure SchemaFactory", e);
                }
            }
        };
        
        String xmlContent = request.getParameter("xml");
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = secureFactory.get();
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("Schema processed with thread-local secure factory");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}

@WebServlet("/good15")
public class Good_Case_15 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a secure schema with validation against a known schema
        String xmlContent = request.getParameter("xml");
        
        try {
            // ok: java-xml-injection-schema-factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            // First create a schema from a trusted source
            String trustedSchemaXml = "<?xml version=\"1.0\"?><xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"><xs:element name=\"data\" type=\"xs:string\"/></xs:schema>";
            Schema trustedSchema = factory.newSchema(new StreamSource(new StringReader(trustedSchemaXml)));
            
            // Then use this schema to validate the input
            javax.xml.validation.Validator validator = trustedSchema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            
            response.getWriter().println("XML validated against trusted schema");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}