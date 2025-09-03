import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Examples of correct and incorrect implementations of the Singleton pattern
 * focusing on thread safety issues, particularly double-checked locking.
 */
public class SingletonExamples {

    // TRUE POSITIVES (Vulnerable implementations)

    /**
     * Bad case 1: Classic non-thread-safe singleton
     */
    public static class BadSingleton1 {
        private static BadSingleton1 instance;
        
        // Public constructor allows multiple instantiation
        public BadSingleton1() {}
        
        public static BadSingleton1 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new BadSingleton1();
            }
            return instance;
        }
    }
    
    /**
     * Bad case 2: Incorrect double-checked locking without volatile
     */
    public static class BadSingleton2 {
        // Missing volatile keyword
        private static BadSingleton2 instance;
        
        private BadSingleton2() {}
        
        public static BadSingleton2 getInstance() {
            if (instance == null) {
                synchronized (BadSingleton2.class) {
                    // ruleid: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new BadSingleton2();
                    }
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 3: Synchronized method but public constructor
     */
    public static class BadSingleton3 {
        private static BadSingleton3 instance;
        
        // Public constructor allows bypassing singleton pattern
        public BadSingleton3() {}
        
        public static synchronized BadSingleton3 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new BadSingleton3();
            }
            return instance;
        }
    }
    
    /**
     * Bad case 4: Double-checked locking with non-final fields
     */
    public static class BadSingleton4 {
        private static BadSingleton4 instance;
        private String data;
        
        private BadSingleton4() {
            data = "Sensitive data";
        }
        
        public static BadSingleton4 getInstance() {
            if (instance == null) {
                synchronized (BadSingleton4.class) {
                    // ruleid: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new BadSingleton4();
                    }
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 5: Lazy initialization without any synchronization
     */
    public static class BadSingleton5 {
        private static BadSingleton5 instance;
        
        private BadSingleton5() {}
        
        public static BadSingleton5 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new BadSingleton5();
            }
            return instance;
        }
    }
    
    /**
     * Bad case 6: Using lock object incorrectly
     */
    public static class BadSingleton6 {
        private static BadSingleton6 instance;
        private static final Lock lock = new ReentrantLock();
        
        private BadSingleton6() {}
        
        public static BadSingleton6 getInstance() {
            if (instance == null) {
                lock.lock();
                try {
                    // ruleid: java-incorrect-double-checked-locking
                    instance = new BadSingleton6();
                } finally {
                    lock.unlock();
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 7: Synchronized block but missing double-check
     */
    public static class BadSingleton7 {
        private static BadSingleton7 instance;
        
        private BadSingleton7() {}
        
        public static BadSingleton7 getInstance() {
            synchronized (BadSingleton7.class) {
                // ruleid: java-incorrect-double-checked-locking
                if (instance == null) {
                    instance = new BadSingleton7();
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 8: Double-checked locking with potential publication issue
     */
    public static class BadSingleton8 {
        private static BadSingleton8 instance;
        private int[] data;
        
        private BadSingleton8() {
            data = new int[1000];
            for (int i = 0; i < 1000; i++) {
                data[i] = i;
            }
        }
        
        public static BadSingleton8 getInstance() {
            if (instance == null) {
                synchronized (BadSingleton8.class) {
                    // ruleid: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new BadSingleton8();
                    }
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 9: Incorrect use of ThreadLocal for singleton
     */
    public static class BadSingleton9 {
        private static final ThreadLocal<BadSingleton9> instance = new ThreadLocal<>();
        
        private BadSingleton9() {}
        
        public static BadSingleton9 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance.get() == null) {
                instance.set(new BadSingleton9());
            }
            return instance.get();
        }
    }
    
    /**
     * Bad case 10: Singleton with reset capability (anti-pattern)
     */
    public static class BadSingleton10 {
        private static BadSingleton10 instance;
        
        private BadSingleton10() {}
        
        public static BadSingleton10 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new BadSingleton10();
            }
            return instance;
        }
        
        // Allows resetting the singleton, breaking the pattern
        public static void reset() {
            instance = null;
        }
    }
    
    /**
     * Bad case 11: Using non-static instance variable
     */
    public static class BadSingleton11 {
        // Non-static instance variable
        private BadSingleton11 instance;
        
        private BadSingleton11() {}
        
        public BadSingleton11 getInstance() {
            // ruleid: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new BadSingleton11();
            }
            return instance;
        }
    }
    
    /**
     * Bad case 12: Incorrect initialization order
     */
    public static class BadSingleton12 {
        private static BadSingleton12 instance;
        private final String data;
        
        private BadSingleton12() {
            data = loadData();
        }
        
        private String loadData() {
            return "Loaded data";
        }
        
        public static BadSingleton12 getInstance() {
            if (instance == null) {
                // ruleid: java-incorrect-double-checked-locking
                instance = new BadSingleton12(); // Initialized before synchronization
                synchronized (BadSingleton12.class) {
                    // Empty synchronized block, incorrect pattern
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 13: Double-checked locking with potential memory visibility issues
     */
    public static class BadSingleton13 {
        private static BadSingleton13 instance;
        private int[] data;
        
        private BadSingleton13() {
            data = new int[100];
            for (int i = 0; i < data.length; i++) {
                data[i] = i * 2;
            }
        }
        
        public static BadSingleton13 getInstance() {
            BadSingleton13 localInstance = instance;
            if (localInstance == null) {
                synchronized (BadSingleton13.class) {
                    localInstance = instance;
                    // ruleid: java-incorrect-double-checked-locking
                    if (localInstance == null) {
                        instance = localInstance = new BadSingleton13();
                    }
                }
            }
            return localInstance;
        }
    }
    
    /**
     * Bad case 14: Using multiple locks for the same singleton
     */
    public static class BadSingleton14 {
        private static BadSingleton14 instance;
        private static final Object lock1 = new Object();
        private static final Object lock2 = new Object();
        
        private BadSingleton14() {}
        
        public static BadSingleton14 getInstance() {
            if (instance == null) {
                synchronized (lock1) {
                    if (instance == null) {
                        synchronized (lock2) {
                            // ruleid: java-incorrect-double-checked-locking
                            if (instance == null) {
                                instance = new BadSingleton14();
                            }
                        }
                    }
                }
            }
            return instance;
        }
    }
    
    /**
     * Bad case 15: Lazy initialization with race condition in constructor
     */
    public static class BadSingleton15 {
        private static BadSingleton15 instance;
        private static int counter = 0;
        
        private BadSingleton15() {
            counter++; // This could lead to race condition
        }
        
        public static BadSingleton15 getInstance() {
            if (instance == null) {
                synchronized (BadSingleton15.class) {
                    // ruleid: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new BadSingleton15();
                    }
                }
            }
            return instance;
        }
        
        public static int getInstanceCount() {
            return counter;
        }
    }

    // TRUE NEGATIVES (Safe implementations)

    /**
     * Good case 1: Eager initialization (thread-safe by default)
     */
    public static class GoodSingleton1 {
        // Initialized during class loading
        private static final GoodSingleton1 INSTANCE = new GoodSingleton1();
        
        private GoodSingleton1() {}
        
        public static GoodSingleton1 getInstance() {
            // ok: java-incorrect-double-checked-locking
            return INSTANCE;
        }
    }
    
    /**
     * Good case 2: Proper double-checked locking with volatile
     */
    public static class GoodSingleton2 {
        // Volatile ensures visibility across threads
        private static volatile GoodSingleton2 instance;
        
        private GoodSingleton2() {}
        
        public static GoodSingleton2 getInstance() {
            if (instance == null) {
                synchronized (GoodSingleton2.class) {
                    // ok: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new GoodSingleton2();
                    }
                }
            }
            return instance;
        }
    }
    
    /**
     * Good case 3: Initialization-on-demand holder idiom
     */
    public static class GoodSingleton3 {
        private GoodSingleton3() {}
        
        // Inner static class is not loaded until needed
        private static class SingletonHolder {
            // ok: java-incorrect-double-checked-locking
            private static final GoodSingleton3 INSTANCE = new GoodSingleton3();
        }
        
        public static GoodSingleton3 getInstance() {
            return SingletonHolder.INSTANCE;
        }
    }
    
    /**
     * Good case 4: Enum singleton (thread-safe by Java guarantee)
     */
    public enum GoodSingleton4 {
        // ok: java-incorrect-double-checked-locking
        INSTANCE;
        
        private String data = "Singleton data";
        
        public String getData() {
            return data;
        }
        
        public void setData(String data) {
            this.data = data;
        }
    }
    
    /**
     * Good case 5: Synchronized method (thread-safe but less efficient)
     */
    public static class GoodSingleton5 {
        private static GoodSingleton5 instance;
        
        private GoodSingleton5() {}
        
        // Synchronized method ensures thread safety
        public static synchronized GoodSingleton5 getInstance() {
            // ok: java-incorrect-double-checked-locking
            if (instance == null) {
                instance = new GoodSingleton5();
            }
            return instance;
        }
    }
    
    /**
     * Good case 6: Using AtomicReference for thread safety
     */
    public static class GoodSingleton6 {
        private static final AtomicReference<GoodSingleton6> INSTANCE = new AtomicReference<>();
        
        private GoodSingleton6() {}
        
        public static GoodSingleton6 getInstance() {
            // ok: java-incorrect-double-checked-locking
            if (INSTANCE.get() == null) {
                INSTANCE.compareAndSet(null, new GoodSingleton6());
            }
            return INSTANCE.get();
        }
    }
    
    /**
     * Good case 7: Static block initialization
     */
    public static class GoodSingleton7 {
        private static final GoodSingleton7 INSTANCE;
        
        static {
            // ok: java-incorrect-double-checked-locking
            INSTANCE = new GoodSingleton7();
        }
        
        private GoodSingleton7() {}
        
        public static GoodSingleton7 getInstance() {
            return INSTANCE;
        }
    }
    
    /**
     * Good case 8: Thread-safe lazy initialization with proper locking
     */
    public static class GoodSingleton8 {
        private static GoodSingleton8 instance;
        private static final Object LOCK = new Object();
        
        private GoodSingleton8() {}
        
        public static GoodSingleton8 getInstance() {
            synchronized (LOCK) {
                // ok: java-incorrect-double-checked-locking
                if (instance == null) {
                    instance = new GoodSingleton8();
                }
                return instance;
            }
        }
    }
    
    /**
     * Good case 9: Using java.util.concurrent.locks.Lock properly
     */
    public static class GoodSingleton9 {
        private static GoodSingleton9 instance;
        private static final Lock LOCK = new ReentrantLock();
        
        private GoodSingleton9() {}
        
        public static GoodSingleton9 getInstance() {
            if (instance == null) {
                LOCK.lock();
                try {
                    // ok: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new GoodSingleton9();
                    }
                } finally {
                    LOCK.unlock();
                }
            }
            return instance;
        }
    }
    
    /**
     * Good case 10: Thread-safe singleton with immutable state
     */
    public static class GoodSingleton10 {
        private static volatile GoodSingleton10 instance;
        private final String[] immutableData;
        
        private GoodSingleton10() {
            immutableData = new String[]{"data1", "data2", "data3"};
        }
        
        public static GoodSingleton10 getInstance() {
            if (instance == null) {
                synchronized (GoodSingleton10.class) {
                    // ok: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new GoodSingleton10();
                    }
                }
            }
            return instance;
        }
        
        public String[] getData() {
            // Return a copy to maintain immutability
            return immutableData.clone();
        }
    }
    
    /**
     * Good case 11: Singleton with thread-safe lazy initialization using ThreadLocal
     */
    public static class GoodSingleton11 {
        private static final GoodSingleton11 INSTANCE = new GoodSingleton11();
        private final ThreadLocal<String> threadLocalData = new ThreadLocal<>();
        
        private GoodSingleton11() {}
        
        public static GoodSingleton11 getInstance() {
            // ok: java-incorrect-double-checked-locking
            return INSTANCE;
        }
        
        public void setData(String data) {
            threadLocalData.set(data);
        }
        
        public String getData() {
            return threadLocalData.get();
        }
    }
    
    /**
     * Good case 12: Factory method returning singleton with proper initialization
     */
    public static class GoodSingleton12 {
        private static class SingletonHolder {
            // ok: java-incorrect-double-checked-locking
            private static final GoodSingleton12 INSTANCE = new GoodSingleton12();
        }
        
        private GoodSingleton12() {}
        
        public static GoodSingleton12 create() {
            return SingletonHolder.INSTANCE;
        }
    }
    
    /**
     * Good case 13: Singleton with proper lazy initialization in Spring-like context
     */
    public static class GoodSingleton13 {
        private static volatile GoodSingleton13 instance;
        
        private GoodSingleton13() {}
        
        public static GoodSingleton13 getInstance() {
            GoodSingleton13 result = instance;
            if (result == null) {
                synchronized (GoodSingleton13.class) {
                    result = instance;
                    // ok: java-incorrect-double-checked-locking
                    if (result == null) {
                        instance = result = new GoodSingleton13();
                    }
                }
            }
            return result;
        }
    }
    
    /**
     * Good case 14: Singleton with proper initialization using enum
     */
    public static class GoodSingleton14 {
        private GoodSingleton14() {}
        
        private enum Singleton {
            INSTANCE;
            
            // ok: java-incorrect-double-checked-locking
            private final GoodSingleton14 instance = new GoodSingleton14();
            
            public GoodSingleton14 getInstance() {
                return instance;
            }
        }
        
        public static GoodSingleton14 getInstance() {
            return Singleton.INSTANCE.getInstance();
        }
    }
    
    /**
     * Good case 15: Thread-safe singleton with proper initialization and resource cleanup
     */
    public static class GoodSingleton15 {
        private static volatile GoodSingleton15 instance;
        private final AutoCloseable resource;
        
        private GoodSingleton15() {
            resource = new AutoCloseable() {
                @Override
                public void close() throws Exception {
                    // Resource cleanup logic
                }
            };
        }
        
        public static GoodSingleton15 getInstance() {
            if (instance == null) {
                synchronized (GoodSingleton15.class) {
                    // ok: java-incorrect-double-checked-locking
                    if (instance == null) {
                        instance = new GoodSingleton15();
                    }
                }
            }
            return instance;
        }
        
        public void shutdown() throws Exception {
            if (resource != null) {
                resource.close();
            }
        }
    }
}