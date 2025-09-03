import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import javax.servlet.annotation.WebServlet;
import javax.xml.XMLConstants;

@WebServlet("/xmlProcessor")
public class XXEVulnerabilityExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed successfully");
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlFilePath = request.getParameter("xmlPath");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setValidating(true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new File(xmlFilePath));
        
        response.getWriter().println("XML file processed successfully");
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        InputStream xmlStream = request.getInputStream();
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(xmlStream);
        
        response.getWriter().println("XML stream processed successfully");
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlUrl = request.getParameter("xmlUrl");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setCoalescing(true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(xmlUrl);
        
        response.getWriter().println("XML from URL processed successfully");
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlContent = request.getHeader("X-XML-Content");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setIgnoringElementContentWhitespace(true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
        
        response.getWriter().println("XML from header processed successfully");
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Setting feature but not the right one for XXE prevention
        dbf.setFeature("http://xml.org/sax/features/namespaces", true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with namespaces");
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Setting feature incorrectly (false instead of true)
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with incorrect XXE protection");
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Setting only one protection but not all required ones
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with partial XXE protection");
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Using deprecated attribute which doesn't fully protect against XXE
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with incomplete protection");
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Incomplete protection - missing external parameter entities
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with incomplete XXE protection");
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            String xmlData = request.getParameter("xml");
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            if (request.getParameter("secure") != null) {
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            }
            // ruleid: java-xxe-in-document-builder-factory
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
            
            response.getWriter().println("XML processed with conditional protection");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Setting XMLConstants.FEATURE_SECURE_PROCESSING alone is not sufficient for XXE protection
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with insufficient protection");
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlFile = request.getParameter("xmlFile");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Setting expandEntityReferences to false doesn't prevent XXE
        dbf.setExpandEntityReferences(false);
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new File(xmlFile));
        
        response.getWriter().println("XML processed with insufficient protection");
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Setting only AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA is not enough
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with partial protection");
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Using incorrect feature name that doesn't exist
        try {
            dbf.setFeature("http://xml.org/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            // Silently ignore the error
        }
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with incorrect feature name");
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely");
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely");
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely with multiple protections");
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely with secure processing");
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely with restricted access");
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ParserConfigurationException, SAXException, IOException {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely with comprehensive protection");
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed securely with XInclude protection");
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with comprehensive protection");
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            String xmlData = request.getParameter("xml");
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xxe-in-document-builder-factory
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
            
            response.getWriter().println("XML processed securely with error handling");
        } catch (ParserConfigurationException e) {
            response.getWriter().println("Parser configuration error: " + e.getMessage());
        } catch (SAXException e) {
            response.getWriter().println("XML parsing error: " + e.getMessage());
        }
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Create a new factory with secure defaults
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with comprehensive security");
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        // Comprehensive approach combining multiple protections
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with maximum security");
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Create a secure factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-document-builder-factory
        // Java 7+ approach
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        // Additional protections
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with Java 7+ security features");
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Create a factory with secure configuration
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // ok: java-xxe-in-document-builder-factory
        // Apply security features conditionally based on Java version
        String javaVersion = System.getProperty("java.version");
        if (javaVersion.startsWith("1.7") || javaVersion.startsWith("1.8") || 
            !javaVersion.startsWith("1.")) {
            // Java 7+ specific protections
            dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        }
        
        // Common protections for all versions
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with version-specific protections");
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Create a secure factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // ok: java-xxe-in-document-builder-factory
        // Most restrictive approach - completely disallow DOCTYPE declarations
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        try {
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed successfully");
        } catch (SAXException e) {
            // This will catch attempts to use DOCTYPE declarations
            response.getWriter().println("XML processing failed: DOCTYPE not allowed");
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Create a factory with secure configuration
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // ok: java-xxe-in-document-builder-factory
        // Apply all known XXE protections
        // 1. Disable DOCTYPE declarations (preferred approach)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        // 2. Disable external entities
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        // 3. Disable entity expansion
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        
        // 4. General security feature
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        // 5. Restrict access to external resources (Java 7+)
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("XML processed with maximum security protections");
    }
}
// {/fact}