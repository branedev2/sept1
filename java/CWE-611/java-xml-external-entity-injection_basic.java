import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class XXEVulnerabilityExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setXIncludeAware(true);
            dbf.setExpandEntityReferences(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed successfully");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error processing XML: " + e.getMessage());
        }
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlContent");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            DocumentBuilder db = dbf.newDocumentBuilder(); // Default configuration is vulnerable
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML document parsed");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setNamespaceAware(true); // Setting namespace aware without disabling XXE
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(xmlStream);
            response.getWriter().println("XML processed");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlFile = request.getParameter("xmlFile");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setValidating(true); // Enabling validation without disabling XXE
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new File(xmlFile));
            response.getWriter().println("XML file processed");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getHeader("X-XML-Data");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setIgnoringElementContentWhitespace(true); // Setting whitespace handling without XXE protection
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed from header");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("data");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setCoalescing(true); // Setting coalescing without XXE protection
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed with coalescing");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("content");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setXIncludeAware(true);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            response.getWriter().println("XML processed with external DTD loading");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            byte[] xmlBytes = request.getParameter("xml").getBytes(StandardCharsets.UTF_8);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setIgnoringComments(true); // Setting comment handling without XXE protection
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xmlBytes));
            response.getWriter().println("XML processed from bytes");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlData");
            SAXParserFactory spf = SAXParserFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            spf.setXIncludeAware(true);
            SAXParser parser = spf.newSAXParser();
            parser.parse(new InputSource(new StringReader(xmlData)), new DefaultHandler());
            response.getWriter().println("XML processed with SAX parser");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed with external general entities enabled");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed with external parameter entities enabled");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlUrl = request.getParameter("xmlUrl");
            URL url = new URL(xmlUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setExpandEntityReferences(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(conn.getInputStream());
            response.getWriter().println("XML processed from URL");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            XMLInputFactory xif = XMLInputFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(xmlData));
            while (xsr.hasNext()) {
                xsr.next();
            }
            response.getWriter().println("XML processed with XMLStreamReader");
        } catch (XMLStreamException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed with DOCTYPE allowed");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setAttribute("http://xml.org/sax/features/external-general-entities", Boolean.TRUE);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed with external entities enabled via setAttribute");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    // True Negative Examples (Secure Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlContent");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML document parsed securely");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            dbf.setNamespaceAware(true); // This is safe when combined with XXE protections
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(xmlStream);
            response.getWriter().println("XML processed securely with namespace awareness");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlFile = request.getParameter("xmlFile");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setValidating(false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new File(xmlFile));
            response.getWriter().println("XML file processed securely");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getHeader("X-XML-Data");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            dbf.setIgnoringElementContentWhitespace(true); // Safe with XXE protections
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely from header");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("data");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setCoalescing(true); // Safe with XXE protections
            dbf.setXIncludeAware(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely with coalescing");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getParameter("content");
            SAXParserFactory spf = SAXParserFactory.newInstance();
            // ok: java-xml-external-entity-injection
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setXIncludeAware(false);
            SAXParser parser = spf.newSAXParser();
            parser.parse(new InputSource(new StringReader(xmlContent)), new DefaultHandler());
            response.getWriter().println("XML processed securely with SAX parser");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            byte[] xmlBytes = request.getParameter("xml").getBytes(StandardCharsets.UTF_8);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setIgnoringComments(true); // Safe with XXE protections
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xmlBytes));
            response.getWriter().println("XML processed securely from bytes");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xmlData");
            XMLInputFactory xif = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(xmlData));
            while (xsr.hasNext()) {
                xsr.next();
            }
            response.getWriter().println("XML processed securely with XMLStreamReader");
        } catch (XMLStreamException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlUrl = request.getParameter("xmlUrl");
            URL url = new URL(xmlUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(conn.getInputStream());
            response.getWriter().println("XML processed securely from URL");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely with DTD handling disabled");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setAttribute(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely with attributes");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed with comprehensive XXE protections");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            Properties props = new Properties();
            props.load(request.getInputStream());
            String xmlData = props.getProperty("xmlData");
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely from properties");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setValidating(false);
            dbf.setNamespaceAware(true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            dbf.setIgnoringComments(true);
            dbf.setCoalescing(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely with multiple features");
        } catch (ParserConfigurationException | SAXException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}
// {/fact}