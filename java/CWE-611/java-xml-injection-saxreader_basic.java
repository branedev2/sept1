import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.Part;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;
import java.util.Properties;
import org.apache.commons.io.IOUtils;

public class XXEVulnerabilityExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException {
        String xmlData = request.getParameter("xml");
        SAXReader reader = new SAXReader();
        // ruleid: java-xml-injection-saxreader
        Document document = reader.read(new StringReader(xmlData));
        response.getWriter().println("XML processed: " + document.getRootElement().getName());
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException {
        Part filePart = request.getPart("xmlFile");
        InputStream fileContent = filePart.getInputStream();
        SAXBuilder builder = new SAXBuilder();
        try {
            // ruleid: java-xml-injection-saxreader
            org.jdom2.Document document = builder.build(fileContent);
            response.getWriter().println("XML processed successfully");
        } catch (JDOMException e) {
            response.getWriter().println("Error processing XML");
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        String xmlUrl = request.getParameter("xmlUrl");
        XMLReader reader = XMLReaderFactory.createXMLReader();
        try {
            // ruleid: java-xml-injection-saxreader
            reader.parse(xmlUrl);
            response.getWriter().println("XML parsed successfully");
        } catch (Exception e) {
            response.getWriter().println("Error parsing XML");
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException {
        InputStream xmlStream = request.getInputStream();
        SAXReader reader = new SAXReader();
        try {
            // ruleid: java-xml-injection-saxreader
            Document document = reader.read(xmlStream);
            String rootElement = document.getRootElement().getName();
            response.getWriter().println("Root element: " + rootElement);
        } catch (DocumentException e) {
            response.getWriter().println("Error reading XML");
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException {
        String xmlContent = IOUtils.toString(request.getReader());
        SAXBuilder builder = new SAXBuilder();
        StringReader stringReader = new StringReader(xmlContent);
        try {
            // ruleid: java-xml-injection-saxreader
            org.jdom2.Document document = builder.build(stringReader);
            response.getWriter().println("XML processed with " + document.getRootElement().getChildren().size() + " child elements");
        } catch (JDOMException e) {
            response.getWriter().println("Error processing XML");
        }
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        String xmlData = request.getParameter("xmlData");
        XMLReader reader = XMLReaderFactory.createXMLReader();
        InputSource source = new InputSource(new StringReader(xmlData));
        // ruleid: java-xml-injection-saxreader
        reader.parse(source);
        response.getWriter().println("XML parsed successfully");
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException {
        String fileName = request.getParameter("fileName");
        File file = new File(fileName);
        SAXReader reader = new SAXReader();
        if (file.exists()) {
            // ruleid: java-xml-injection-saxreader
            Document document = reader.read(file);
            response.getWriter().println("XML file processed: " + document.getRootElement().getName());
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException {
        URL xmlUrl = new URL(request.getParameter("url"));
        SAXBuilder builder = new SAXBuilder();
        try {
            // ruleid: java-xml-injection-saxreader
            org.jdom2.Document document = builder.build(xmlUrl);
            response.getWriter().println("XML from URL processed successfully");
        } catch (JDOMException e) {
            response.getWriter().println("Error processing XML from URL");
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException {
        String xmlData = request.getHeader("X-XML-Data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlData.getBytes(StandardCharsets.UTF_8));
        SAXReader reader = new SAXReader();
        // ruleid: java-xml-injection-saxreader
        Document document = reader.read(inputStream);
        response.getWriter().println("XML from header processed");
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        InputStream fileContent = filePart.getInputStream();
        
        XMLReader reader = XMLReaderFactory.createXMLReader();
        InputSource source = new InputSource(fileContent);
        // ruleid: java-xml-injection-saxreader
        reader.parse(source);
        response.getWriter().println("Uploaded XML file " + fileName + " parsed successfully");
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException {
        String xmlData = request.getParameter("data");
        if (xmlData != null && !xmlData.isEmpty()) {
            SAXBuilder builder = new SAXBuilder();
            // Even with validation disabled, it's still vulnerable without disabling DTDs
            builder.setValidation(false);
            // ruleid: java-xml-injection-saxreader
            org.jdom2.Document document = builder.build(new StringReader(xmlData));
            response.getWriter().println("XML processed with validation disabled");
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException {
        String cookie = request.getHeader("Cookie");
        String xmlData = extractXmlFromCookie(cookie);
        
        SAXReader reader = new SAXReader();
        // Setting some properties but not the security-critical ones
        reader.setEncoding("UTF-8");
        reader.setStripWhitespaceText(true);
        
        // ruleid: java-xml-injection-saxreader
        Document document = reader.read(new StringReader(xmlData));
        response.getWriter().println("XML from cookie processed");
    }

    private String extractXmlFromCookie(String cookie) {
        // Simple extraction logic for example purposes
        return cookie.replace("xml=", "");
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        String xmlData = request.getParameter("xml");
        
        XMLReader reader = XMLReaderFactory.createXMLReader();
        // Setting some features but not the security-critical ones
        reader.setFeature("http://xml.org/sax/features/namespaces", true);
        reader.setFeature("http://xml.org/sax/features/namespace-prefixes", false);
        
        // ruleid: java-xml-injection-saxreader
        reader.parse(new InputSource(new StringReader(xmlData)));
        response.getWriter().println("XML parsed with some features configured");
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException {
        // Getting XML from a request attribute that might have been set by another component
        Object xmlObj = request.getAttribute("xmlContent");
        if (xmlObj != null && xmlObj instanceof String) {
            String xmlData = (String) xmlObj;
            SAXReader reader = new SAXReader();
            // ruleid: java-xml-injection-saxreader
            Document document = reader.read(new StringReader(xmlData));
            response.getWriter().println("XML from request attribute processed");
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException {
        // Processing XML in a loop for multiple files
        for (Part part : request.getParts()) {
            if (part.getContentType() != null && part.getContentType().contains("xml")) {
                SAXBuilder builder = new SAXBuilder();
                // ruleid: java-xml-injection-saxreader
                org.jdom2.Document document = builder.build(part.getInputStream());
                response.getWriter().println("Processed XML part: " + part.getName());
            }
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException, SAXException {
        String xmlData = request.getParameter("xml");
        SAXReader reader = new SAXReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        Document document = reader.read(new StringReader(xmlData));
        response.getWriter().println("XML processed securely: " + document.getRootElement().getName());
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException, SAXException {
        Part filePart = request.getPart("xmlFile");
        InputStream fileContent = filePart.getInputStream();
        SAXBuilder builder = new SAXBuilder();
        // ok: java-xml-injection-saxreader
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        try {
            org.jdom2.Document document = builder.build(fileContent);
            response.getWriter().println("XML processed securely");
        } catch (JDOMException e) {
            response.getWriter().println("Error processing XML");
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        String xmlUrl = request.getParameter("xmlUrl");
        XMLReader reader = XMLReaderFactory.createXMLReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        try {
            reader.parse(xmlUrl);
            response.getWriter().println("XML parsed securely");
        } catch (Exception e) {
            response.getWriter().println("Error parsing XML");
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException, SAXException {
        InputStream xmlStream = request.getInputStream();
        SAXReader reader = new SAXReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        try {
            Document document = reader.read(xmlStream);
            String rootElement = document.getRootElement().getName();
            response.getWriter().println("Root element: " + rootElement);
        } catch (DocumentException e) {
            response.getWriter().println("Error reading XML");
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException, SAXException {
        String xmlContent = IOUtils.toString(request.getReader());
        SAXBuilder builder = new SAXBuilder();
        // ok: java-xml-injection-saxreader
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        StringReader stringReader = new StringReader(xmlContent);
        try {
            org.jdom2.Document document = builder.build(stringReader);
            response.getWriter().println("XML processed securely with " + document.getRootElement().getChildren().size() + " child elements");
        } catch (JDOMException e) {
            response.getWriter().println("Error processing XML");
        }
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        String xmlData = request.getParameter("xmlData");
        XMLReader reader = XMLReaderFactory.createXMLReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        InputSource source = new InputSource(new StringReader(xmlData));
        reader.parse(source);
        response.getWriter().println("XML parsed securely");
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException, SAXException {
        String fileName = request.getParameter("fileName");
        File file = new File(fileName);
        SAXReader reader = new SAXReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        if (file.exists()) {
            Document document = reader.read(file);
            response.getWriter().println("XML file processed securely: " + document.getRootElement().getName());
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException, SAXException {
        URL xmlUrl = new URL(request.getParameter("url"));
        SAXBuilder builder = new SAXBuilder();
        // ok: java-xml-injection-saxreader
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        try {
            org.jdom2.Document document = builder.build(xmlUrl);
            response.getWriter().println("XML from URL processed securely");
        } catch (JDOMException e) {
            response.getWriter().println("Error processing XML from URL");
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException, SAXException {
        String xmlData = request.getHeader("X-XML-Data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlData.getBytes(StandardCharsets.UTF_8));
        SAXReader reader = new SAXReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        Document document = reader.read(inputStream);
        response.getWriter().println("XML from header processed securely");
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        InputStream fileContent = filePart.getInputStream();
        
        XMLReader reader = XMLReaderFactory.createXMLReader();
        // ok: java-xml-injection-saxreader
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        InputSource source = new InputSource(fileContent);
        reader.parse(source);
        response.getWriter().println("Uploaded XML file " + fileName + " parsed securely");
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, JDOMException, SAXException {
        String xmlData = request.getParameter("data");
        if (xmlData != null && !xmlData.isEmpty()) {
            SAXBuilder builder = new SAXBuilder();
            // ok: java-xml-injection-saxreader
            builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            builder.setValidation(false);
            org.jdom2.Document document = builder.build(new StringReader(xmlData));
            response.getWriter().println("XML processed securely with validation disabled");
        }
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException, SAXException {
        // Alternative approach: Use a secure factory method that sets security features
        String xmlData = request.getParameter("xml");
        SAXReader reader = createSecureSAXReader();
        // ok: java-xml-injection-saxreader
        Document document = reader.read(new StringReader(xmlData));
        response.getWriter().println("XML processed using secure factory method");
    }

    private SAXReader createSecureSAXReader() throws SAXException {
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        return reader;
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException, ParserConfigurationException {
        // Alternative approach: Use DocumentBuilderFactory with secure settings instead of SAXReader
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xml-injection-saxreader
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        org.w3c.dom.Document document = builder.parse(new InputSource(new StringReader(xmlData)));
        response.getWriter().println("XML processed using secure DocumentBuilderFactory");
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SAXException {
        // Alternative approach: Use SAXParserFactory with secure settings
        String xmlData = request.getParameter("xml");
        
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // ok: java-xml-injection-saxreader
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setValidating(false);
        
        SAXParser parser = factory.newSAXParser();
        parser.parse(new InputSource(new StringReader(xmlData)), new org.xml.sax.helpers.DefaultHandler());
        response.getWriter().println("XML processed using secure SAXParserFactory");
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, DocumentException, SAXException {
        // Processing XML in a loop for multiple files with secure configuration
        for (Part part : request.getParts()) {
            if (part.getContentType() != null && part.getContentType().contains("xml")) {
                SAXReader reader = new SAXReader();
                // ok: java-xml-injection-saxreader
                reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
                reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                Document document = reader.read(part.getInputStream());
                response.getWriter().println("Processed XML part securely: " + part.getName());
            }
        }
    }
}
// {/fact}