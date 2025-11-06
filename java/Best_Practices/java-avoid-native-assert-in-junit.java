import org.junit.Test;
import org.junit.jupiter.api.Test as JupiterTest;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.Before;
import org.junit.After;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

public class JUnitAssertionTests {

    // True Positive Examples (using native assert in JUnit tests)
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    @Test
    public void bad_case_1() {
        String expected = "Hello";
        String actual = "Hello";
        // ruleid: java-avoid-native-assert-in-junit
        assert expected.equals(actual);
    }
    
    @Test
    public void bad_case_2() {
        int x = 5;
        int y = 5;
        // ruleid: java-avoid-native-assert-in-junit
        assert x == y : "Values should be equal";
    }
    
    @Test
    public void bad_case_3() {
        List<String> list = new ArrayList<>();
        list.add("item");
        // ruleid: java-avoid-native-assert-in-junit
        assert !list.isEmpty();
    }
    
    @JupiterTest
    public void bad_case_4() {
        Map<String, Integer> map = new HashMap<>();
        map.put("key", 42);
        // ruleid: java-avoid-native-assert-in-junit
        assert map.containsKey("key") : "Map should contain the key";
    }
    
    @Test
    public void bad_case_5() {
        String str = null;
        try {
            str = "Not null anymore";
            // ruleid: java-avoid-native-assert-in-junit
            assert str != null;
        } catch (Exception e) {
            fail("Should not throw exception");
        }
    }
    
    @Test
    public void bad_case_6() {
        int result = calculateSum(2, 3);
        // ruleid: java-avoid-native-assert-in-junit
        assert result == 5 : "Sum calculation is incorrect";
    }
    
    @Test
    public void bad_case_7() {
        boolean condition = true;
        if (condition) {
            // ruleid: java-avoid-native-assert-in-junit
            assert condition;
        } else {
            fail("Condition should be true");
        }
    }
    
    @Test
    public void bad_case_8() {
        String[] array = {"a", "b", "c"};
        // ruleid: java-avoid-native-assert-in-junit
        assert array.length == 3;
    }
    
    @RunWith(MockitoJUnitRunner.class)
    public class NestedTestClass {
        @Mock
        private List<String> mockList;
        
        @Test
        public void bad_case_9() {
            mockList.add("test");
            // ruleid: java-avoid-native-assert-in-junit
            assert mockList.size() == 1;
        }
    }
    
    @Test
    public void bad_case_10() {
        double result = Math.sqrt(16);
        // ruleid: java-avoid-native-assert-in-junit
        assert result == 4.0;
    }
    
    @Before
    public void bad_case_11() {
        // Even in setup methods, native assertions should be avoided
        boolean initialized = initializeTestEnvironment();
        // ruleid: java-avoid-native-assert-in-junit
        assert initialized : "Test environment initialization failed";
    }
    
    @After
    public void bad_case_12() {
        boolean cleanedUp = cleanupTestResources();
        // ruleid: java-avoid-native-assert-in-junit
        assert cleanedUp : "Resource cleanup failed";
    }
    
    @Test
    public void bad_case_13() {
        try {
            methodThatShouldThrowException();
            // ruleid: java-avoid-native-assert-in-junit
            assert false : "Exception was expected but not thrown";
        } catch (IllegalArgumentException e) {
            // Expected exception
        }
    }
    
    @Test
    public void bad_case_14() {
        Object obj = new Object();
        Object sameObj = obj;
        // ruleid: java-avoid-native-assert-in-junit
        assert obj == sameObj : "Objects should be the same instance";
    }
    
    @Test
    public void bad_case_15() {
        String result = processString("test");
        // ruleid: java-avoid-native-assert-in-junit
        assert result != null && result.startsWith("processed_");
    }
    
    // True Negative Examples (using JUnit assertions properly)
    
    @Test
    public void good_case_1() {
        String expected = "Hello";
        String actual = "Hello";
        // ok: java-avoid-native-assert-in-junit
        assertEquals(expected, actual);
    }
    
    @Test
    public void good_case_2() {
        int x = 5;
        int y = 5;
        // ok: java-avoid-native-assert-in-junit
        assertEquals("Values should be equal", x, y);
    }
    
    @Test
    public void good_case_3() {
        List<String> list = new ArrayList<>();
        list.add("item");
        // ok: java-avoid-native-assert-in-junit
        assertFalse(list.isEmpty());
    }
    
    @JupiterTest
    public void good_case_4() {
        Map<String, Integer> map = new HashMap<>();
        map.put("key", 42);
        // ok: java-avoid-native-assert-in-junit
        assertTrue(map.containsKey("key"), "Map should contain the key");
    }
    
    @Test
    public void good_case_5() {
        String str = null;
        try {
            str = "Not null anymore";
            // ok: java-avoid-native-assert-in-junit
            assertNotNull(str);
        } catch (Exception e) {
            fail("Should not throw exception");
        }
    }
    
    @Test
    public void good_case_6() {
        int result = calculateSum(2, 3);
        // ok: java-avoid-native-assert-in-junit
        assertEquals("Sum calculation is incorrect", 5, result);
    }
    
    @Test
    public void good_case_7() {
        boolean condition = true;
        // ok: java-avoid-native-assert-in-junit
        assertTrue(condition);
    }
    
    @Test
    public void good_case_8() {
        String[] array = {"a", "b", "c"};
        // ok: java-avoid-native-assert-in-junit
        assertEquals(3, array.length);
    }
    
    @RunWith(MockitoJUnitRunner.class)
    public class NestedGoodTestClass {
        @Mock
        private List<String> mockList;
        
        @Test
        public void good_case_9() {
            mockList.add("test");
            // ok: java-avoid-native-assert-in-junit
            assertEquals(1, mockList.size());
        }
    }
    
    @Test
    public void good_case_10() {
        double result = Math.sqrt(16);
        // ok: java-avoid-native-assert-in-junit
        assertEquals(4.0, result, 0.0001);
    }
    
    @Before
    public void good_case_11() {
        boolean initialized = initializeTestEnvironment();
        // ok: java-avoid-native-assert-in-junit
        assertTrue("Test environment initialization failed", initialized);
    }
    
    @After
    public void good_case_12() {
        boolean cleanedUp = cleanupTestResources();
        // ok: java-avoid-native-assert-in-junit
        assertTrue("Resource cleanup failed", cleanedUp);
    }
    
    @Test
    public void good_case_13() {
        try {
            methodThatShouldThrowException();
            // ok: java-avoid-native-assert-in-junit
            fail("Exception was expected but not thrown");
        } catch (IllegalArgumentException e) {
            // Expected exception
        }
    }
    
    @Test
    public void good_case_14() {
        Object obj = new Object();
        Object sameObj = obj;
        // ok: java-avoid-native-assert-in-junit
        assertSame("Objects should be the same instance", obj, sameObj);
    }
    
    @Test
    public void good_case_15() {
        String result = processString("test");
        // ok: java-avoid-native-assert-in-junit
        assertNotNull(result);
        assertTrue(result.startsWith("processed_"));
    }
    
    // Helper methods
    private int calculateSum(int a, int b) {
        return a + b;
    }
    
    private boolean initializeTestEnvironment() {
        return true;
    }
    
    private boolean cleanupTestResources() {
        return true;
    }
    
    private void methodThatShouldThrowException() {
        throw new IllegalArgumentException("Expected exception");
    }
    
    private String processString(String input) {
        return "processed_" + input;
    }
}
// {/fact}