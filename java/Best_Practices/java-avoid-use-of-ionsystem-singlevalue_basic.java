import software.amazon.ion.*;
import software.amazon.ion.system.*;
import java.io.*;
import java.util.*;

public class IonSystemUsageExamples {

    // True Positive Examples (Bad Cases)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String ionData = "{name:\"John\", age:30}";
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(ionData);
        
        String name = value.get("name").stringValue();
        System.out.println("Name: " + name);
    }

    public void bad_case_2() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        byte[] ionBytes = "{data:[1,2,3,4,5]}".getBytes();
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(ionBytes);
        
        IonList list = (IonList) value.get("data");
        System.out.println("List size: " + list.size());
    }

    public void bad_case_3() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            File ionFile = new File("data.ion");
            FileInputStream fis = new FileInputStream(ionFile);
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(fis);
            
            processIonValue(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String complexData = "[{id:1, name:\"Product A\"}, {id:2, name:\"Product B\"}]";
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(complexData);
        
        IonList products = (IonList) value;
        for (int i = 0; i < products.size(); i++) {
            IonStruct product = (IonStruct) products.get(i);
            System.out.println(product.get("name").stringValue());
        }
    }

    public void bad_case_5() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            Reader reader = new StringReader("{config:{timeout:30, retries:3}}");
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(reader);
            
            IonStruct config = (IonStruct) value.get("config");
            int timeout = config.get("timeout").intValue();
            System.out.println("Timeout: " + timeout);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("name", "Alice");
        dataMap.put("age", 25);
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(ionSystem.newString(dataMap.toString()));
        
        System.out.println("Processed value: " + value.toString());
    }

    public void bad_case_7() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            URL url = new URL("https://example.com/data.ion");
            InputStream stream = url.openStream();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(stream);
            
            if (value instanceof IonStruct) {
                IonStruct struct = (IonStruct) value;
                System.out.println("Fields: " + struct.size());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String largeData = generateLargeIonDocument(); // Assume this generates a large Ion document
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(largeData);
        
        processLargeDocument(value);
    }

    public void bad_case_9() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        for (int i = 0; i < 100; i++) {
            String data = "{index:" + i + ", value:\"data" + i + "\"}";
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(data);
            
            processIonValue(value);
        }
    }

    public void bad_case_10() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            ByteArrayInputStream bais = new ByteArrayInputStream("{binary:{{AQIDBA==}}}".getBytes());
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(bais);
            
            IonBlob blob = (IonBlob) value.get("binary");
            System.out.println("Blob size: " + blob.getBytes().length);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String nestedData = "{outer:{middle:{inner:{value:42}}}}";
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(nestedData);
        
        IonStruct outer = (IonStruct) value;
        IonStruct middle = (IonStruct) outer.get("middle");
        IonStruct inner = (IonStruct) middle.get("inner");
        int innerValue = inner.get("value").intValue();
        System.out.println("Inner value: " + innerValue);
    }

    public void bad_case_12() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String[] dataArray = {"{id:1}", "{id:2}", "{id:3}"};
        
        for (String data : dataArray) {
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(data);
            
            int id = ((IonStruct) value).get("id").intValue();
            System.out.println("ID: " + id);
        }
    }

    public void bad_case_13() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            BufferedReader reader = new BufferedReader(new FileReader("config.ion"));
            StringBuilder sb = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(sb.toString());
            
            applyConfiguration(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String timestamp = "2023-05-15T14:30:00Z";
        String data = "{timestamp:\"" + timestamp + "\", event:\"login\"}";
        
        // ruleid: java-avoid-use-of-ionsystem-singlevalue
        IonValue value = ionSystem.singleValue(data);
        
        String event = value.get("event").stringValue();
        System.out.println("Event: " + event);
    }

    public void bad_case_15() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String jsonData = "{\"key\":\"value\"}"; // JSON format
        
        try {
            // Convert JSON to Ion format
            String ionData = convertJsonToIon(jsonData);
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(ionData);
            
            String key = value.get("key").stringValue();
            System.out.println("Key: " + key);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String ionData = "{name:\"John\", age:30}";
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(ionData);
        IonValue value = ionSystem.newValue(reader);
        
        String name = value.get("name").stringValue();
        System.out.println("Name: " + name);
    }

    public void good_case_2() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        byte[] ionBytes = "{data:[1,2,3,4,5]}".getBytes();
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(ionBytes);
        IonValue value = ionSystem.newValue(reader);
        
        IonList list = (IonList) value.get("data");
        System.out.println("List size: " + list.size());
    }

    public void good_case_3() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            File ionFile = new File("data.ion");
            FileInputStream fis = new FileInputStream(ionFile);
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(fis);
            processIonReader(reader);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String complexData = "[{id:1, name:\"Product A\"}, {id:2, name:\"Product B\"}]";
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(complexData);
        IonValue value = ionSystem.newValue(reader);
        
        IonList products = (IonList) value;
        for (int i = 0; i < products.size(); i++) {
            IonStruct product = (IonStruct) products.get(i);
            System.out.println(product.get("name").stringValue());
        }
    }

    public void good_case_5() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            Reader stringReader = new StringReader("{config:{timeout:30, retries:3}}");
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(stringReader);
            IonValue value = ionSystem.newValue(reader);
            
            IonStruct config = (IonStruct) value.get("config");
            int timeout = config.get("timeout").intValue();
            System.out.println("Timeout: " + timeout);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("name", "Alice");
        dataMap.put("age", 25);
        String data = dataMap.toString();
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(data);
        while (reader.next() != null) {
            processIonType(reader);
        }
    }

    public void good_case_7() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            URL url = new URL("https://example.com/data.ion");
            InputStream stream = url.openStream();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(stream);
            processStreamingData(reader);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String largeData = generateLargeIonDocument(); // Assume this generates a large Ion document
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(largeData);
        processLargeDocumentStreaming(reader);
    }

    public void good_case_9() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        for (int i = 0; i < 100; i++) {
            String data = "{index:" + i + ", value:\"data" + i + "\"}";
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(data);
            while (reader.next() != null) {
                if (reader.getType() == IonType.STRUCT) {
                    reader.stepIn();
                    while (reader.next() != null) {
                        System.out.println(reader.getFieldName() + ": " + reader.stringValue());
                    }
                    reader.stepOut();
                }
            }
        }
    }

    public void good_case_10() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            ByteArrayInputStream bais = new ByteArrayInputStream("{binary:{{AQIDBA==}}}".getBytes());
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(bais);
            processIonReader(reader);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String nestedData = "{outer:{middle:{inner:{value:42}}}}";
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(nestedData);
        IonValue value = ionSystem.newValue(reader);
        
        IonStruct outer = (IonStruct) value;
        IonStruct middle = (IonStruct) outer.get("middle");
        IonStruct inner = (IonStruct) middle.get("inner");
        int innerValue = inner.get("value").intValue();
        System.out.println("Inner value: " + innerValue);
    }

    public void good_case_12() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String[] dataArray = {"{id:1}", "{id:2}", "{id:3}"};
        
        for (String data : dataArray) {
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(data);
            while (reader.next() != null) {
                if (reader.getType() == IonType.STRUCT) {
                    reader.stepIn();
                    while (reader.next() != null) {
                        if ("id".equals(reader.getFieldName())) {
                            System.out.println("ID: " + reader.intValue());
                        }
                    }
                    reader.stepOut();
                }
            }
        }
    }

    public void good_case_13() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            BufferedReader fileReader = new BufferedReader(new FileReader("config.ion"));
            StringBuilder sb = new StringBuilder();
            String line;
            
            while ((line = fileReader.readLine()) != null) {
                sb.append(line);
            }
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(sb.toString());
            processConfigurationStreaming(reader);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String timestamp = "2023-05-15T14:30:00Z";
        String data = "{timestamp:\"" + timestamp + "\", event:\"login\"}";
        
        // ok: java-avoid-use-of-ionsystem-singlevalue
        IonReader reader = ionSystem.newReader(data);
        IonValue value = ionSystem.newValue(reader);
        
        String event = value.get("event").stringValue();
        System.out.println("Event: " + event);
    }

    public void good_case_15() {
        IonSystem ionSystem = IonSystemBuilder.standard().build();
        String jsonData = "{\"key\":\"value\"}"; // JSON format
        
        try {
            // Convert JSON to Ion format
            String ionData = convertJsonToIon(jsonData);
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(ionData);
            processJsonAsIon(reader);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper methods
    private void processIonValue(IonValue value) {
        // Process the IonValue
    }

    private void processLargeDocument(IonValue value) {
        // Process a large document
    }

    private void applyConfiguration(IonValue value) {
        // Apply configuration from IonValue
    }

    private String convertJsonToIon(String json) {
        // Convert JSON to Ion format
        return json;
    }

    private void processIonReader(IonReader reader) {
        // Process using IonReader
    }

    private void processIonType(IonReader reader) {
        // Process specific Ion type
    }

    private void processStreamingData(IonReader reader) {
        // Process streaming data
    }

    private void processLargeDocumentStreaming(IonReader reader) {
        // Process large document in streaming fashion
    }

    private void processConfigurationStreaming(IonReader reader) {
        // Process configuration in streaming fashion
    }

    private void processJsonAsIon(IonReader reader) {
        // Process JSON data as Ion
    }

    private String generateLargeIonDocument() {
        // Generate a large Ion document
        return "{large:\"document\"}";
    }
}
// {/fact}