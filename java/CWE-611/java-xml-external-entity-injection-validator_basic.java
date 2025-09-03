import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.xml.sax.SAXException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class XMLValidatorExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML is valid");
        } catch (SAXException e) {
            response.getWriter().println("XML is invalid: " + e.getMessage());
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlContent");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL schemaUrl = new URL("https://example.com/schema.xsd");
            Schema schema = factory.newSchema(schemaUrl);
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            Source source = new StreamSource(new StringReader(xmlData));
            validator.validate(source);
            response.getWriter().println("Validation successful");
        } catch (Exception e) {
            response.getWriter().println("Validation failed: " + e.getMessage());
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlStream));
            response.getWriter().println("XML validated successfully");
        } catch (SAXException e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    @WebServlet("/validate-xml")
    public class bad_case_4 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            try {
                String xmlData = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
                SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                
                // Enable secure processing but miss other important settings
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                Schema schema = factory.newSchema(new File("schema.xsd"));
                
                // ruleid: java-xml-external-entity-injection-validator
                Validator validator = schema.newValidator();
                validator.validate(new StreamSource(new StringReader(xmlData)));
                response.getWriter().println("XML is valid");
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Only set one property but miss others
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("XML validation passed");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            byte[] xmlBytes = request.getParameter("xmlData").getBytes(StandardCharsets.UTF_8);
            InputStream xmlStream = new ByteArrayInputStream(xmlBytes);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File("schema.xsd"));
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            // Missing security settings
            validator.validate(new StreamSource(xmlStream));
            response.getWriter().println("XML validation completed");
        } catch (Exception e) {
            response.getWriter().println("Error during validation: " + e.getMessage());
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getHeader("X-XML-Content");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Only set external schema property but miss others
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML is valid according to schema");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlDocument");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set feature but not properties
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Schema schema = factory.newSchema(new File("schema.xsd"));
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xml = request.getParameter("xmlInput");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            // Setting only one property on validator instead of schema
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.validate(new StreamSource(new StringReader(xml)));
            response.getWriter().println("XML validation successful");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Incomplete security configuration
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            Schema schema = factory.newSchema(new File("schema.xsd"));
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("XML is valid");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xml = request.getParameter("xmlData");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Setting incorrect empty value
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, null);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xml)));
            response.getWriter().println("XML validation passed");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Setting property with non-empty value (allowing access)
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "file,http");
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlStream));
            response.getWriter().println("XML validation successful");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Setting feature to false (insecure)
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML validation completed");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("xmlContent");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File("schema.xsd"));
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            // Setting property with non-empty value on validator (allowing access)
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "file,http");
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("XML is valid");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xml = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Setting only one property but missing others
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema();
            
            // ruleid: java-xml-external-entity-injection-validator
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xml)));
            response.getWriter().println("XML validation successful");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML is valid");
        } catch (SAXException e) {
            response.getWriter().println("XML is invalid: " + e.getMessage());
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlContent");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("Validation successful");
        } catch (Exception e) {
            response.getWriter().println("Validation failed: " + e.getMessage());
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlStream));
            response.getWriter().println("XML validated successfully");
        } catch (SAXException e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    @WebServlet("/validate-xml-secure")
    public class good_case_4 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            try {
                String xmlData = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
                SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                
                // Set secure processing
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                
                Schema schema = factory.newSchema(new File("schema.xsd"));
                // ok: java-xml-external-entity-injection-validator
                schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
                
                Validator validator = schema.newValidator();
                validator.validate(new StreamSource(new StringReader(xmlData)));
                response.getWriter().println("XML is valid");
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing with all necessary properties
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("XML validation passed");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            byte[] xmlBytes = request.getParameter("xmlData").getBytes(StandardCharsets.UTF_8);
            InputStream xmlStream = new ByteArrayInputStream(xmlBytes);
            
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlStream));
            response.getWriter().println("XML validation completed");
        } catch (Exception e) {
            response.getWriter().println("Error during validation: " + e.getMessage());
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getHeader("X-XML-Content");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set all security features and properties
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML is valid according to schema");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlDocument");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set all security features
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xml = request.getParameter("xmlInput");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            validator.validate(new StreamSource(new StringReader(xml)));
            response.getWriter().println("XML validation successful");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Complete security configuration
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            // Additional security settings on validator
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("XML is valid");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xml = request.getParameter("xmlData");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set all security properties with empty string (secure)
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xml)));
            response.getWriter().println("XML validation passed");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing with additional features
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlStream));
            response.getWriter().println("XML validation successful");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // Set secure processing
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            
            // Set resource constraints
            validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
            validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
            
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML validation completed");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("xmlContent");
            
            // Create a secure schema factory
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Schema schema = factory.newSchema(new File("schema.xsd"));
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlContent)));
            response.getWriter().println("XML is valid");
        } catch (Exception e) {
            response.getWriter().println("XML validation error: " + e.getMessage());
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xml = request.getParameter("xml");
            
            // Create schema factory with all security settings
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            // Additional security features
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            Schema schema = factory.newSchema();
            // ok: java-xml-external-entity-injection-validator
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            schema.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xml)));
            response.getWriter().println("XML validation successful");
        } catch (Exception e) {
            response.getWriter().println("XML validation failed: " + e.getMessage());
        }
    }
}
// {/fact}