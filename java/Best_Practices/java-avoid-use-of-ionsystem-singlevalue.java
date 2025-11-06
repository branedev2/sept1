package com.example.ionusage;

import software.amazon.ion.*;
import software.amazon.ion.system.*;
import java.io.*;
import java.util.*;

public class IonSystemUsageExamples {

    // True Positives (Vulnerable/Inefficient Code)
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = getIonData();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(ionData);
            
            processIonValue(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String ionText = "{name: \"John\", age: 30}";
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonStruct struct = (IonStruct) ionSystem.singleValue(ionText);
            
            String name = struct.get("name").stringValue();
            System.out.println("Name: " + name);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_3() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            File ionFile = new File("data.ion");
            FileInputStream fis = new FileInputStream(ionFile);
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(fis);
            
            fis.close();
            processLargeIonDocument(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            InputStream inputStream = getIonInputStream();
            
            for (int i = 0; i < 100; i++) {
                // ruleid: java-avoid-use-of-ionsystem-singlevalue
                IonValue value = ionSystem.singleValue(inputStream);
                processIonValue(value);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            Reader reader = new StringReader("[1, 2, 3, 4, 5]");
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonList list = (IonList) ionSystem.singleValue(reader);
            
            for (IonValue item : list) {
                System.out.println(item.intValue());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6() {
        try {
            Map<String, Object> data = getUserData();
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String ionText = convertToIonText(data);
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonDatagram datagram = ionSystem.singleValue(ionText);
            
            processIonDatagram(datagram);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = downloadIonData();
            
            if (ionData != null && ionData.length > 0) {
                // ruleid: java-avoid-use-of-ionsystem-singlevalue
                IonValue value = ionSystem.singleValue(ionData);
                validateIonDocument(value);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String[] ionTexts = {"1", "\"hello\"", "2.5", "true", "null"};
            
            for (String text : ionTexts) {
                // ruleid: java-avoid-use-of-ionsystem-singlevalue
                IonValue value = ionSystem.singleValue(text);
                System.out.println("Type: " + value.getType());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            InputStream is = getConfigInputStream();
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonStruct config = (IonStruct) ionSystem.singleValue(is);
            
            is.close();
            applyConfiguration(config);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = getIonData();
            
            long startTime = System.currentTimeMillis();
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(ionData);
            long endTime = System.currentTimeMillis();
            
            System.out.println("Parsing took " + (endTime - startTime) + " ms");
            processIonValue(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String jsonString = getJsonString();
            String ionString = convertJsonToIon(jsonString);
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue ionValue = ionSystem.singleValue(ionString);
            
            transformIonValue(ionValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] data = new byte[1024 * 1024]; // 1MB of data
            fillWithIonData(data);
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonValue value = ionSystem.singleValue(data);
            
            extractMetadata(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            List<String> ionDocuments = getIonDocuments();
            
            for (String doc : ionDocuments) {
                // ruleid: java-avoid-use-of-ionsystem-singlevalue
                IonValue value = ionSystem.singleValue(doc);
                validateDocument(value);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            Reader reader = new FileReader("large_document.ion");
            
            // ruleid: java-avoid-use-of-ionsystem-singlevalue
            IonDatagram datagram = (IonDatagram) ionSystem.singleValue(reader);
            
            reader.close();
            System.out.println("Document size: " + datagram.size());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = getIonData();
            
            switch (getProcessingMode()) {
                case FULL:
                    // ruleid: java-avoid-use-of-ionsystem-singlevalue
                    IonValue fullValue = ionSystem.singleValue(ionData);
                    processFullDocument(fullValue);
                    break;
                case PARTIAL:
                    processPartially(ionData);
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negatives (Safe/Efficient Code)
    
    public void good_case_1() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = getIonData();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(ionData);
            processIonReader(reader);
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String ionText = "{name: \"John\", age: 30}";
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(ionText);
            
            reader.next();
            if (reader.getType() == IonType.STRUCT) {
                reader.stepIn();
                while (reader.next() != null) {
                    String fieldName = reader.getFieldName();
                    if ("name".equals(fieldName) && reader.getType() == IonType.STRING) {
                        System.out.println("Name: " + reader.stringValue());
                    }
                }
                reader.stepOut();
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_3() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            File ionFile = new File("data.ion");
            FileInputStream fis = new FileInputStream(ionFile);
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(fis);
            processLargeIonDocumentWithReader(reader);
            reader.close();
            fis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_4() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            InputStream inputStream = getIonInputStream();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(inputStream);
            for (int i = 0; i < 100; i++) {
                if (reader.next() != null) {
                    processCurrentValue(reader);
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            Reader textReader = new StringReader("[1, 2, 3, 4, 5]");
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(textReader);
            
            reader.next(); // Move to the list
            if (reader.getType() == IonType.LIST) {
                reader.stepIn();
                while (reader.next() != null) {
                    System.out.println(reader.intValue());
                }
                reader.stepOut();
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() {
        try {
            Map<String, Object> data = getUserData();
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String ionText = convertToIonText(data);
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(ionText);
            processIonReaderAsDatagram(reader);
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = downloadIonData();
            
            if (ionData != null && ionData.length > 0) {
                // ok: java-avoid-use-of-ionsystem-singlevalue
                IonReader reader = ionSystem.newReader(ionData);
                validateIonDocumentWithReader(reader);
                reader.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String[] ionTexts = {"1", "\"hello\"", "2.5", "true", "null"};
            
            for (String text : ionTexts) {
                // ok: java-avoid-use-of-ionsystem-singlevalue
                IonReader reader = ionSystem.newReader(text);
                if (reader.next() != null) {
                    System.out.println("Type: " + reader.getType());
                }
                reader.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_9() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            InputStream is = getConfigInputStream();
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(is);
            Map<String, Object> config = parseConfigFromReader(reader);
            reader.close();
            is.close();
            
            applyConfiguration(config);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = getIonData();
            
            long startTime = System.currentTimeMillis();
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(ionData);
            processIonReader(reader);
            reader.close();
            long endTime = System.currentTimeMillis();
            
            System.out.println("Parsing took " + (endTime - startTime) + " ms");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            String jsonString = getJsonString();
            String ionString = convertJsonToIon(jsonString);
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(ionString);
            transformIonValueFromReader(reader);
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] data = new byte[1024 * 1024]; // 1MB of data
            fillWithIonData(data);
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(data);
            extractMetadataFromReader(reader);
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            List<String> ionDocuments = getIonDocuments();
            
            for (String doc : ionDocuments) {
                // ok: java-avoid-use-of-ionsystem-singlevalue
                IonReader reader = ionSystem.newReader(doc);
                validateDocumentWithReader(reader);
                reader.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            Reader fileReader = new FileReader("large_document.ion");
            
            // ok: java-avoid-use-of-ionsystem-singlevalue
            IonReader reader = ionSystem.newReader(fileReader);
            int documentSize = countTopLevelValues(reader);
            reader.close();
            fileReader.close();
            
            System.out.println("Document size: " + documentSize);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        try {
            IonSystem ionSystem = IonSystemBuilder.standard().build();
            byte[] ionData = getIonData();
            
            switch (getProcessingMode()) {
                case FULL:
                    // ok: java-avoid-use-of-ionsystem-singlevalue
                    IonReader reader = ionSystem.newReader(ionData);
                    processFullDocumentWithReader(reader);
                    reader.close();
                    break;
                case PARTIAL:
                    processPartially(ionData);
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper methods to make the examples compile
    private byte[] getIonData() {
        return new byte[0];
    }
    
    private void processIonValue(IonValue value) {
    }
    
    private void processLargeIonDocument(IonValue value) {
    }
    
    private InputStream getIonInputStream() {
        return null;
    }
    
    private Map<String, Object> getUserData() {
        return new HashMap<>();
    }
    
    private String convertToIonText(Map<String, Object> data) {
        return "";
    }
    
    private void processIonDatagram(IonDatagram datagram) {
    }
    
    private byte[] downloadIonData() {
        return new byte[0];
    }
    
    private void validateIonDocument(IonValue value) {
    }
    
    private InputStream getConfigInputStream() {
        return null;
    }
    
    private void applyConfiguration(IonStruct config) {
    }
    
    private void applyConfiguration(Map<String, Object> config) {
    }
    
    private String getJsonString() {
        return "";
    }
    
    private String convertJsonToIon(String jsonString) {
        return "";
    }
    
    private void transformIonValue(IonValue ionValue) {
    }
    
    private void fillWithIonData(byte[] data) {
    }
    
    private void extractMetadata(IonValue value) {
    }
    
    private List<String> getIonDocuments() {
        return new ArrayList<>();
    }
    
    private void validateDocument(IonValue value) {
    }
    
    private void processFullDocument(IonValue fullValue) {
    }
    
    private void processPartially(byte[] ionData) {
    }
    
    private ProcessingMode getProcessingMode() {
        return ProcessingMode.FULL;
    }
    
    private enum ProcessingMode {
        FULL, PARTIAL
    }
    
    private void processIonReader(IonReader reader) {
    }
    
    private void processLargeIonDocumentWithReader(IonReader reader) {
    }
    
    private void processCurrentValue(IonReader reader) {
    }
    
    private void processIonReaderAsDatagram(IonReader reader) {
    }
    
    private void validateIonDocumentWithReader(IonReader reader) {
    }
    
    private Map<String, Object> parseConfigFromReader(IonReader reader) {
        return new HashMap<>();
    }
    
    private void transformIonValueFromReader(IonReader reader) {
    }
    
    private void extractMetadataFromReader(IonReader reader) {
    }
    
    private void validateDocumentWithReader(IonReader reader) {
    }
    
    private int countTopLevelValues(IonReader reader) {
        return 0;
    }
    
    private void processFullDocumentWithReader(IonReader reader) {
    }
}
// {/fact}