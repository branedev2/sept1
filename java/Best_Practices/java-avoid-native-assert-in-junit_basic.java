import org.junit.Test;
import org.junit.jupiter.api.Test;
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
        String result = "test";
        // ruleid: java-avoid-native-assert-in-junit
        assert result.equals("test");
    }
    
    @Test
    public void bad_case_2() {
        int value = calculateValue();
        // ruleid: java-avoid-native-assert-in-junit
        assert value > 0 : "Value should be positive";
    }
    
    @Test
    public void bad_case_3() {
        List<String> items = new ArrayList<>();
        items.add("item1");
        // ruleid: java-avoid-native-assert-in-junit
        assert !items.isEmpty();
    }
    
    @org.junit.jupiter.api.Test
    public void bad_case_4() {
        Map<String, Integer> map = new HashMap<>();
        map.put("key", 42);
        // ruleid: java-avoid-native-assert-in-junit
        assert map.containsKey("key") : "Map should contain key";
    }
    
    @Test
    public void bad_case_5() {
        String[] array = {"a", "b", "c"};
        // ruleid: java-avoid-native-assert-in-junit
        assert array.length == 3;
    }
    
    @org.junit.jupiter.api.Test
    public void bad_case_6() {
        boolean condition = checkCondition();
        // ruleid: java-avoid-native-assert-in-junit
        assert condition;
    }
    
    @Test
    public void bad_case_7() {
        Object obj = new Object();
        // ruleid: java-avoid-native-assert-in-junit
        assert obj != null : "Object should not be null";
    }
    
    @org.junit.jupiter.api.Test
    public void bad_case_8() {
        int result = sum(2, 3);
        // ruleid: java-avoid-native-assert-in-junit
        assert result == 5 : "Sum should be 5";
    }
    
    @Test
    public void bad_case_9() {
        String str = null;
        try {
            str = "test";
            // ruleid: java-avoid-native-assert-in-junit
            assert str.length() > 0;
        } catch (Exception e) {
            fail("Should not throw exception");
        }
    }
    
    @org.junit.jupiter.api.Test
    public void bad_case_10() {
        double result = divide(10, 2);
        // ruleid: java-avoid-native-assert-in-junit
        assert result == 5.0 : "Division result incorrect";
    }
    
    @Test
    public void bad_case_11() {
        for (int i = 0; i < 5; i++) {
            // ruleid: java-avoid-native-assert-in-junit
            assert i < 5 : "Index should be less than 5";
        }
    }
    
    @org.junit.jupiter.api.Test
    public void bad_case_12() {
        String result = processString("input");
        // ruleid: java-avoid-native-assert-in-junit
        assert result != null && result.contains("input") : "Result should contain input";
    }
    
    @Test
    public void bad_case_13() {
        int[] numbers = {1, 2, 3, 4, 5};
        int sum = 0;
        for (int num : numbers) {
            sum += num;
        }
        // ruleid: java-avoid-native-assert-in-junit
        assert sum == 15;
    }
    
    @org.junit.jupiter.api.Test
    public void bad_case_14() {
        boolean flag = false;
        if (isConditionMet()) {
            flag = true;
        }
        // ruleid: java-avoid-native-assert-in-junit
        assert flag : "Condition should be met";
    }
    
    @Test
    public void bad_case_15() {
        StringBuilder sb = new StringBuilder();
        sb.append("Hello").append(" ").append("World");
        // ruleid: java-avoid-native-assert-in-junit
        assert "Hello World".equals(sb.toString());
    }
    
    // True Negative Examples (using JUnit assertions properly)
    
    @Test
    public void good_case_1() {
        String result = "test";
        // ok: java-avoid-native-assert-in-junit
        assertEquals("test", result);
    }
    
    @Test
    public void good_case_2() {
        int value = calculateValue();
        // ok: java-avoid-native-assert-in-junit
        assertTrue("Value should be positive", value > 0);
    }
    
    @Test
    public void good_case_3() {
        List<String> items = new ArrayList<>();
        items.add("item1");
        // ok: java-avoid-native-assert-in-junit
        assertFalse(items.isEmpty());
    }
    
    @org.junit.jupiter.api.Test
    public void good_case_4() {
        Map<String, Integer> map = new HashMap<>();
        map.put("key", 42);
        // ok: java-avoid-native-assert-in-junit
        assertTrue(map.containsKey("key"), "Map should contain key");
    }
    
    @Test
    public void good_case_5() {
        String[] array = {"a", "b", "c"};
        // ok: java-avoid-native-assert-in-junit
        assertEquals(3, array.length);
    }
    
    @org.junit.jupiter.api.Test
    public void good_case_6() {
        boolean condition = checkCondition();
        // ok: java-avoid-native-assert-in-junit
        assertTrue(condition);
    }
    
    @Test
    public void good_case_7() {
        Object obj = new Object();
        // ok: java-avoid-native-assert-in-junit
        assertNotNull("Object should not be null", obj);
    }
    
    @org.junit.jupiter.api.Test
    public void good_case_8() {
        int result = sum(2, 3);
        // ok: java-avoid-native-assert-in-junit
        assertEquals(5, result, "Sum should be 5");
    }
    
    @Test
    public void good_case_9() {
        String str = null;
        try {
            str = "test";
            // ok: java-avoid-native-assert-in-junit
            assertTrue(str.length() > 0);
        } catch (Exception e) {
            fail("Should not throw exception");
        }
    }
    
    @org.junit.jupiter.api.Test
    public void good_case_10() {
        double result = divide(10, 2);
        // ok: java-avoid-native-assert-in-junit
        assertEquals(5.0, result, 0.001, "Division result incorrect");
    }
    
    @Test
    public void good_case_11() {
        for (int i = 0; i < 5; i++) {
            // ok: java-avoid-native-assert-in-junit
            assertTrue("Index should be less than 5", i < 5);
        }
    }
    
    @org.junit.jupiter.api.Test
    public void good_case_12() {
        String result = processString("input");
        // ok: java-avoid-native-assert-in-junit
        assertNotNull(result);
        assertTrue(result.contains("input"), "Result should contain input");
    }
    
    @Test
    public void good_case_13() {
        int[] numbers = {1, 2, 3, 4, 5};
        int sum = 0;
        for (int num : numbers) {
            sum += num;
        }
        // ok: java-avoid-native-assert-in-junit
        assertEquals(15, sum);
    }
    
    @org.junit.jupiter.api.Test
    public void good_case_14() {
        boolean flag = false;
        if (isConditionMet()) {
            flag = true;
        }
        // ok: java-avoid-native-assert-in-junit
        assertTrue("Condition should be met", flag);
    }
    
    @Test
    public void good_case_15() {
        StringBuilder sb = new StringBuilder();
        sb.append("Hello").append(" ").append("World");
        // ok: java-avoid-native-assert-in-junit
        assertEquals("Hello World", sb.toString());
    }
    
    // Helper methods
    private int calculateValue() {
        return 42;
    }
    
    private boolean checkCondition() {
        return true;
    }
    
    private int sum(int a, int b) {
        return a + b;
    }
    
    private double divide(double a, double b) {
        return a / b;
    }
    
    private boolean isConditionMet() {
        return true;
    }
    
    private String processString(String input) {
        return "processed_" + input;
    }
}
// {/fact}