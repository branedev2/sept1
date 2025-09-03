// File: DoubleCheckedLockingExamples.java

import java.util.concurrent.atomic.AtomicReference;
import java.io.Serializable;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Lock;

public class DoubleCheckedLockingExamples {

    // True Positive Examples (Vulnerable Code)

    // Example 1: Classic incorrect double-checked locking
    public static class bad_case_1 {
        private static bad_case_1 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_1() {}
        
        public static bad_case_1 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_1.class) {
                    if (instance == null) {
                        instance = new bad_case_1();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 2: Missing volatile keyword in double-checked locking
    public static class bad_case_2 {
        private static bad_case_2 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_2() {}
        
        public static bad_case_2 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_2.class) {
                    if (instance == null) {
                        instance = new bad_case_2();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 3: Singleton with public constructor
    public static class bad_case_3 {
        private static volatile bad_case_3 instance;
        
        // Public constructor allows direct instantiation
// {fact rule=double-checked-locking@v1.0 defects=1}
        public bad_case_3() {}
        
        public static bad_case_3 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_3.class) {
                    if (instance == null) {
                        instance = new bad_case_3();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 4: Missing synchronization entirely
    public static class bad_case_4 {
        private static bad_case_4 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_4() {}
        
        public static bad_case_4 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new bad_case_4();
            }
            return instance;
        }
    }
// {/fact}

    // Example 5: Incorrect synchronization on different object
    public static class bad_case_5 {
        private static bad_case_5 instance;
        private static final Object lock = new Object();
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_5() {}
        
        public static bad_case_5 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (lock) {
                    instance = new bad_case_5();
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 6: Lazy initialization with non-volatile field
    public static class bad_case_6 {
        private static bad_case_6 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_6() {}
        
        public static synchronized bad_case_6 getInstanceSynchronized() {
            return getInstance();
        }
        
        public static bad_case_6 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new bad_case_6();
            }
            return instance;
        }
    }
// {/fact}

    // Example 7: Double-checked locking with non-final fields
    public static class bad_case_7 {
        private static bad_case_7 instance;
        private int data;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_7() {
            data = 42;
        }
        
        public static bad_case_7 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_7.class) {
                    if (instance == null) {
                        instance = new bad_case_7();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 8: Incorrect synchronization with early return
    public static class bad_case_8 {
        private static bad_case_8 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_8() {}
        
        public static bad_case_8 getInstance() {
            if (instance != null) {
                return instance;
            }
            
            // ruleid: java-incorrect-double-checked-locking
            synchronized (bad_case_8.class) {
                if (instance == null) {
                    instance = new bad_case_8();
                }
                return instance;
            }
        }
    }
// {/fact}

    // Example 9: Incorrect lazy initialization in multi-threaded environment
    public static class bad_case_9 {
        private static bad_case_9 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_9() {}
        
        public static bad_case_9 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                createInstance();
            }
            return instance;
        }
        
        private static synchronized void createInstance() {
            if (instance == null) {
                instance = new bad_case_9();
            }
        }
    }
// {/fact}

    // Example 10: Singleton with multiple check points
    public static class bad_case_10 {
        private static bad_case_10 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_10() {}
        
        public static bad_case_10 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                synchronized (bad_case_10.class) {
                    instance = new bad_case_10();
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 11: Incorrect double-checked locking with complex initialization
    public static class bad_case_11 {
        private static bad_case_11 instance;
        private int[] data;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_11() {
            data = new int[1000];
            for (int i = 0; i < data.length; i++) {
                data[i] = i;
            }
        }
        
        public static bad_case_11 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_11.class) {
                    if (instance == null) {
                        instance = new bad_case_11();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 12: Incorrect implementation with lazy initialization in constructor
    public static class bad_case_12 {
        private static bad_case_12 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_12() {
            // Some expensive initialization
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        
        public static bad_case_12 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                synchronized (bad_case_12.class) {
                    instance = new bad_case_12();
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 13: Incorrect double-checked locking with serialization support
    public static class bad_case_13 implements Serializable {
        private static final long serialVersionUID = 1L;
        private static bad_case_13 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_13() {}
        
        public static bad_case_13 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_13.class) {
                    if (instance == null) {
                        instance = new bad_case_13();
                    }
                }
            }
            return instance;
        }
        
        protected Object readResolve() {
            return getInstance();
        }
    }
// {/fact}

    // Example 14: Incorrect double-checked locking with lazy field initialization
    public static class bad_case_14 {
        private static bad_case_14 instance;
        private Object data;
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_14() {}
        
        public static bad_case_14 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                synchronized (bad_case_14.class) {
                    if (instance == null) {
                        instance = new bad_case_14();
                    }
                }
            }
            return instance;
        }
        
        public Object getData() {
            if (data == null) {
                data = new Object();
            }
            return data;
        }
    }
// {/fact}

    // Example 15: Incorrect double-checked locking with lock object
    public static class bad_case_15 {
        private static bad_case_15 instance;
        private static final Lock lock = new ReentrantLock();
        
// {fact rule=double-checked-locking@v1.0 defects=1}
        private bad_case_15() {}
        
        public static bad_case_15 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                lock.lock();
                try {
                    if (instance == null) {
                        instance = new bad_case_15();
                    }
                } finally {
                    lock.unlock();
                }
            }
            return instance;
        }
    }
// {/fact}

    // True Negative Examples (Secure Code)

    // Example 1: Correct implementation with volatile
    public static class good_case_1 {
        private static volatile good_case_1 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_1() {}
        
        public static good_case_1 getInstance() {
            if (instance == null) {
                // ok: java-incorrect-double-checked-locking
                synchronized (good_case_1.class) {
                    if (instance == null) {
                        instance = new good_case_1();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 2: Initialization-on-demand holder idiom
    public static class good_case_2 {
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_2() {}
        
        // ok: java-incorrect-double-checked-locking
        private static class InstanceHolder {
            private static final good_case_2 INSTANCE = new good_case_2();
        }
        
        public static good_case_2 getInstance() {
            return InstanceHolder.INSTANCE;
        }
    }
// {/fact}

    // Example 3: Enum-based singleton
    // ok: java-incorrect-double-checked-locking
    public enum good_case_3 {
        INSTANCE;
        
        private int value;
        
        public int getValue() {
            return value;
        }
        
        public void setValue(int value) {
            this.value = value;
        }
    }

    // Example 4: Early initialization
    public static class good_case_4 {
        // ok: java-incorrect-double-checked-locking
        private static final good_case_4 INSTANCE = new good_case_4();
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_4() {}
        
        public static good_case_4 getInstance() {
            return INSTANCE;
        }
    }
// {/fact}

    // Example 5: Synchronized method
    public static class good_case_5 {
        private static good_case_5 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_5() {}
        
        // ok: java-incorrect-double-checked-locking
        public static synchronized good_case_5 getInstance() {
            if (instance == null) {
                instance = new good_case_5();
            }
            return instance;
        }
    }
// {/fact}

    // Example 6: Thread-safe with AtomicReference
    public static class good_case_6 {
        private static final AtomicReference<good_case_6> INSTANCE = new AtomicReference<>();
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_6() {}
        
        public static good_case_6 getInstance() {
            // ok: java-incorrect-double-checked-locking
            if (INSTANCE.get() == null) {
                INSTANCE.compareAndSet(null, new good_case_6());
            }
            return INSTANCE.get();
        }
    }
// {/fact}

    // Example 7: Correct implementation with final fields
    public static class good_case_7 {
        private static volatile good_case_7 instance;
        private final int data;
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_7() {
            data = 42;
        }
        
        public static good_case_7 getInstance() {
            if (instance == null) {
                // ok: java-incorrect-double-checked-locking
                synchronized (good_case_7.class) {
                    if (instance == null) {
                        instance = new good_case_7();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 8: Thread-safe factory method
    public static class good_case_8 {
        private static volatile good_case_8 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_8() {}
        
        // ok: java-incorrect-double-checked-locking
        public static good_case_8 getInstance() {
            good_case_8 result = instance;
            if (result == null) {
                synchronized (good_case_8.class) {
                    result = instance;
                    if (result == null) {
                        instance = result = new good_case_8();
                    }
                }
            }
            return result;
        }
    }
// {/fact}

    // Example 9: Singleton with proper serialization support
    public static class good_case_9 implements Serializable {
        private static final long serialVersionUID = 1L;
        
        // ok: java-incorrect-double-checked-locking
        private static class InstanceHolder {
            private static final good_case_9 INSTANCE = new good_case_9();
        }
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_9() {}
        
        public static good_case_9 getInstance() {
            return InstanceHolder.INSTANCE;
        }
        
        protected Object readResolve() {
            return getInstance();
        }
    }
// {/fact}

    // Example 10: Thread-safe with proper locking
    public static class good_case_10 {
        private static volatile good_case_10 instance;
        private static final Object MUTEX = new Object();
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_10() {}
        
        public static good_case_10 getInstance() {
            if (instance == null) {
                // ok: java-incorrect-double-checked-locking
                synchronized (MUTEX) {
                    if (instance == null) {
                        instance = new good_case_10();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 11: Thread-safe with ReentrantLock
    public static class good_case_11 {
        private static volatile good_case_11 instance;
        private static final Lock lock = new ReentrantLock();
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_11() {}
        
        public static good_case_11 getInstance() {
            if (instance == null) {
                // ok: java-incorrect-double-checked-locking
                lock.lock();
                try {
                    if (instance == null) {
                        instance = new good_case_11();
                    }
                } finally {
                    lock.unlock();
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 12: Thread-safe with static block initialization
    public static class good_case_12 {
        private static good_case_12 instance;
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_12() {}
        
        // ok: java-incorrect-double-checked-locking
        static {
            instance = new good_case_12();
        }
        
        public static good_case_12 getInstance() {
            return instance;
        }
    }
// {/fact}

    // Example 13: Thread-safe with proper initialization and final fields
    public static class good_case_13 {
        private static volatile good_case_13 instance;
        private final String name;
        private final int id;
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_13() {
            name = "Singleton";
            id = 1;
        }
        
        public static good_case_13 getInstance() {
            if (instance == null) {
                // ok: java-incorrect-double-checked-locking
                synchronized (good_case_13.class) {
                    if (instance == null) {
                        instance = new good_case_13();
                    }
                }
            }
            return instance;
        }
    }
// {/fact}

    // Example 14: Thread-safe with lazy holder and private constructor
    public static class good_case_14 {
        // ok: java-incorrect-double-checked-locking
        private static class SingletonHolder {
            private static final good_case_14 INSTANCE = new good_case_14();
        }
        
// {fact rule=double-checked-locking@v1.0 defects=0}
        private good_case_14() {
            // Prevent instantiation via reflection
            if (SingletonHolder.INSTANCE != null) {
                throw new IllegalStateException("Already initialized");
            }
        }
        
        public static good_case_14 getInstance() {
            return SingletonHolder.INSTANCE;
        }
    }
// {/fact}

    // Example 15: Thread-safe with enum and additional functionality
    // ok: java-incorrect-double-checked-locking
    public enum good_case_15 {
        INSTANCE;
        
        private final String name;
        private int counter;
        
        good_case_15() {
            name = "EnumSingleton";
            counter = 0;
        }
        
        public String getName() {
            return name;
        }
        
        public synchronized int incrementAndGetCounter() {
            return ++counter;
        }
    }

    public static void main(String[] args) {
        // Test cases can be run here
        System.out.println("Testing singleton implementations...");
    }
}