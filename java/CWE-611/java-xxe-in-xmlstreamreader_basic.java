import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.util.Properties;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import javax.xml.transform.stream.StreamSource;
import java.io.BufferedReader;

public class XXEVulnerabilityExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Reading XML data from HTTP request
        BufferedReader reader = request.getReader();
        StringBuilder xmlData = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            xmlData.append(line);
        }
        
        // Creating XMLStreamReader without proper security configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader streamReader = factory.createXMLStreamReader(new StringReader(xmlData.toString()));
        
        // Process XML data
        while (streamReader.hasNext()) {
            streamReader.next();
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter
        String xmlContent = request.getParameter("xml_data");
        
        // Create XMLInputFactory without security settings
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new StringReader(xmlContent));
        
        // Process the XML
        processXml(reader);
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML file path from request
        String xmlFilePath = request.getParameter("file_path");
        File xmlFile = new File(xmlFilePath);
        
        // Create factory and reader without security
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlReader = factory.createXMLStreamReader(new FileInputStream(xmlFile));
        
        // Process XML
        while (xmlReader.hasNext()) {
            xmlReader.next();
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request part
        InputStream inputStream = request.getPart("xml_file").getInputStream();
        
        // Create factory with explicit disabling of secure processing
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request header
        String xmlData = request.getHeader("X-XML-Data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlData.getBytes());
        
        // Create factory with default settings (vulnerable)
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        processXmlContent(reader);
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML URL from request
        String xmlUrl = request.getParameter("xml_url");
        URL url = new URL(xmlUrl);
        InputStream inputStream = url.openStream();
        
        // Create factory without security configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request attribute
        String xmlContent = (String) request.getAttribute("xml_content");
        
        // Create factory with explicit vulnerability
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter
        String xmlData = request.getParameter("data");
        
        // Create factory with multiple insecure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML
        processXmlStream(reader);
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from session attribute
        String xmlData = (String) request.getSession().getAttribute("user_xml");
        
        // Create factory with default settings
        XMLInputFactory factory = XMLInputFactory.newFactory();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from cookie
        String xmlData = getCookieValue(request, "xml_data");
        
        // Create factory with no security configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new ByteArrayInputStream(xmlData.getBytes()));
        
        // Process XML
        processXmlData(reader);
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter with base64 encoding
        String base64XmlData = request.getParameter("encoded_xml");
        byte[] decodedXml = java.util.Base64.getDecoder().decode(base64XmlData);
        
        // Create factory without security settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new ByteArrayInputStream(decodedXml));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML file name from request
        String fileName = request.getParameter("file_name");
        File file = new File("/tmp/" + fileName);
        
        // Create factory with default settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(file), "UTF-8");
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from multipart request
        InputStream xmlStream = request.getPart("xml_file").getInputStream();
        
        // Create factory with explicit insecure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_REPLAC_REDACTED_TWILIO_ID_ENTITY_REFERENCES, true);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(xmlStream);
        
        // Process XML
        processXmlDocument(reader);
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter
        String xmlContent = request.getParameter("xml");
        
        // Create factory with default settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Explicitly set insecure property
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.TRUE);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request input stream
        InputStream inputStream = request.getInputStream();
        
        // Create factory with default settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Set property that allows DTD processing
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Reading XML data from HTTP request
        BufferedReader reader = request.getReader();
        StringBuilder xmlData = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            xmlData.append(line);
        }
        
        // Creating XMLStreamReader with proper security configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader streamReader = factory.createXMLStreamReader(new StringReader(xmlData.toString()));
        
        // Process XML data
        while (streamReader.hasNext()) {
            streamReader.next();
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter
        String xmlContent = request.getParameter("xml_data");
        
        // Create XMLInputFactory with security settings
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new StringReader(xmlContent));
        
        // Process the XML
        processXml(reader);
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML file path from request
        String xmlFilePath = request.getParameter("file_path");
        File xmlFile = new File(xmlFilePath);
        
        // Create factory and reader with security settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlReader = factory.createXMLStreamReader(new FileInputStream(xmlFile));
        
        // Process XML
        while (xmlReader.hasNext()) {
            xmlReader.next();
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request part
        InputStream inputStream = request.getPart("xml_file").getInputStream();
        
        // Create factory with secure processing
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request header
        String xmlData = request.getHeader("X-XML-Data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlData.getBytes());
        
        // Create factory with secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        processXmlContent(reader);
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML URL from request
        String xmlUrl = request.getParameter("xml_url");
        URL url = new URL(xmlUrl);
        InputStream inputStream = url.openStream();
        
        // Create factory with secure configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request attribute
        String xmlContent = (String) request.getAttribute("xml_content");
        
        // Create factory with secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter
        String xmlData = request.getParameter("data");
        
        // Create factory with comprehensive secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_REPLAC_REDACTED_TWILIO_ID_ENTITY_REFERENCES, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML
        processXmlStream(reader);
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException, SAXException {
        // Get XML from session attribute
        String xmlData = (String) request.getSession().getAttribute("user_xml");
        
        // Alternative secure approach using DocumentBuilder
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        builder.parse(new InputSource(new StringReader(xmlData)));
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from cookie
        String xmlData = getCookieValue(request, "xml_data");
        
        // Create factory with secure configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new ByteArrayInputStream(xmlData.getBytes()));
        
        // Process XML
        processXmlData(reader);
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter with base64 encoding
        String base64XmlData = request.getParameter("encoded_xml");
        byte[] decodedXml = java.util.Base64.getDecoder().decode(base64XmlData);
        
        // Create factory with secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new ByteArrayInputStream(decodedXml));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML file name from request
        String fileName = request.getParameter("file_name");
        File file = new File("/tmp/" + fileName);
        
        // Create factory with secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(file), "UTF-8");
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from multipart request
        InputStream xmlStream = request.getPart("xml_file").getInputStream();
        
        // Create factory with secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(xmlStream);
        
        // Process XML
        processXmlDocument(reader);
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request parameter
        String xmlContent = request.getParameter("xml");
        
        // Create factory with secure settings using constants
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws XMLStreamException, IOException {
        // Get XML from request input stream
        InputStream inputStream = request.getInputStream();
        
        // Create factory with secure settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_REPLAC_REDACTED_TWILIO_ID_ENTITY_REFERENCES, false);
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        // Process XML
        while (reader.hasNext()) {
            reader.next();
        }
    }

    // Helper methods
    private void processXml(XMLStreamReader reader) throws XMLStreamException {
        while (reader.hasNext()) {
            reader.next();
        }
    }

    private void processXmlContent(XMLStreamReader reader) throws XMLStreamException {
        while (reader.hasNext()) {
            reader.next();
        }
    }

    private void processXmlStream(XMLStreamReader reader) throws XMLStreamException {
        while (reader.hasNext()) {
            reader.next();
        }
    }

    private void processXmlData(XMLStreamReader reader) throws XMLStreamException {
        while (reader.hasNext()) {
            reader.next();
        }
    }

    private void processXmlDocument(XMLStreamReader reader) throws XMLStreamException {
        while (reader.hasNext()) {
            reader.next();
        }
    }

    private String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (javax.servlet.http.Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return "";
    }
}
// {/fact}