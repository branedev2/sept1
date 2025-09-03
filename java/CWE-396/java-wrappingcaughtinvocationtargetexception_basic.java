import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.io.IOException;
import java.sql.SQLException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class InvocationTargetExceptionHandlingExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=do-not-catch-and-throw-exception@v1.0 defects=1}
    public void bad_case_1() {
        try {
            Method method = String.class.getMethod("valueOf", int.class);
            method.invoke(null, 42);
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new RuntimeException("Error invoking method", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_2() {
        try {
            Method method = Integer.class.getMethod("parseInt", String.class);
            method.invoke(null, "abc"); // This will cause NumberFormatException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IllegalStateException("Failed to parse integer", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_3() {
        try {
            Method method = Class.forName("java.util.ArrayList").getMethod("get", int.class);
            method.invoke(new java.util.ArrayList<>(), 10); // IndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IllegalArgumentException("Invalid index access", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_4() {
        try {
            Method method = String.class.getMethod("substring", int.class, int.class);
            method.invoke("hello", 10, 15); // StringIndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new RuntimeException("String operation failed: " + cause.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_5() {
        try {
            Method method = Integer.class.getMethod("divideUnsigned", int.class, int.class);
            method.invoke(null, 10, 0); // ArithmeticException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IllegalStateException("Division error occurred", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_6() {
        try {
            Method method = Class.forName("java.io.FileInputStream").getMethod("read");
            method.invoke(null); // NullPointerException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new NullPointerException("Null object reference: " + e.getCause().getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_7() {
        try {
            Method method = Class.forName("java.util.HashMap").getMethod("put", Object.class, Object.class);
            method.invoke(null, "key", "value"); // NullPointerException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            Exception newException = new RuntimeException("HashMap operation failed");
            newException.initCause(e);
            throw newException;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_8() {
        try {
            Method method = Class.forName("java.lang.Integer").getMethod("parseInt", String.class);
            method.invoke(null, "not_a_number"); // NumberFormatException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            RuntimeException re = new RuntimeException();
            re.initCause(e);
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_9() {
        try {
            Method method = String.class.getMethod("charAt", int.class);
            method.invoke("", 0); // StringIndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IndexOutOfBoundsException("String index error: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_10() {
        try {
            Method method = Class.forName("java.util.ArrayList").getMethod("remove", int.class);
            method.invoke(new java.util.ArrayList<>(), 5); // IndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IllegalStateException("Collection operation failed", new RuntimeException(e));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_11() {
        try {
            Method method = Class.forName("java.io.FileReader").getConstructor(String.class).newInstance("nonexistent_file");
            method.invoke("read"); // FileNotFoundException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IllegalArgumentException("File operation error", new Exception(e));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_12() {
        try {
            Method method = Class.class.getMethod("forName", String.class);
            method.invoke(null, "nonexistent.Class"); // ClassNotFoundException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            IllegalStateException ise = new IllegalStateException("Class loading failed");
            ise.initCause(e);
            throw ise;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_13() {
        try {
            Method method = Integer.class.getMethod("decode", String.class);
            method.invoke(null, "not_a_hex_number"); // NumberFormatException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new IllegalArgumentException("Failed to decode: " + e.getCause().getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_14() {
        try {
            Method method = Class.forName("java.net.URL").getConstructor(String.class).newInstance("malformed:url");
            method.invoke("openConnection"); // MalformedURLException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new RuntimeException("URL error", new IllegalStateException(e));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void bad_case_15() {
        try {
            Method method = Class.forName("java.util.concurrent.Future").getMethod("get");
            Future<?> future = createFailingFuture();
            method.invoke(future); // ExecutionException
        } catch (InvocationTargetException e) {
            // ruleid: java-wrappingcaughtinvocationtargetexception
            throw new RuntimeException("Future execution failed", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        try {
            Method method = String.class.getMethod("valueOf", int.class);
            method.invoke(null, 42);
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            throw (RuntimeException) e.getCause();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_2() {
        try {
            Method method = Integer.class.getMethod("parseInt", String.class);
            method.invoke(null, "abc"); // This will cause NumberFormatException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            throw (RuntimeException) e.getTargetException();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_3() {
        try {
            Method method = Class.forName("java.util.ArrayList").getMethod("get", int.class);
            method.invoke(new java.util.ArrayList<>(), 10); // IndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            // ok: java-wrappingcaughtinvocationtargetexception
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_4() {
        try {
            Method method = String.class.getMethod("substring", int.class, int.class);
            method.invoke("hello", 10, 15); // StringIndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            // ok: java-wrappingcaughtinvocationtargetexception
            if (cause instanceof IndexOutOfBoundsException) {
                throw (IndexOutOfBoundsException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_5() {
        try {
            Method method = Integer.class.getMethod("divideUnsigned", int.class, int.class);
            method.invoke(null, 10, 0); // ArithmeticException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            if (e.getCause() instanceof ArithmeticException) {
                throw (ArithmeticException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_6() {
        try {
            Method method = Class.forName("java.io.FileInputStream").getMethod("read");
            method.invoke(null); // NullPointerException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getTargetException();
            if (cause instanceof NullPointerException) {
                throw (NullPointerException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_7() {
        try {
            Method method = Class.forName("java.util.HashMap").getMethod("put", Object.class, Object.class);
            method.invoke(null, "key", "value"); // NullPointerException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else if (cause instanceof Error) {
                throw (Error) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_8() {
        try {
            Method method = Class.forName("java.lang.Integer").getMethod("parseInt", String.class);
            method.invoke(null, "not_a_number"); // NumberFormatException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getTargetException();
            if (cause instanceof NumberFormatException) {
                throw (NumberFormatException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_9() {
        try {
            Method method = String.class.getMethod("charAt", int.class);
            method.invoke("", 0); // StringIndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getCause();
            if (cause instanceof IndexOutOfBoundsException) {
                throw (IndexOutOfBoundsException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_10() {
        try {
            Method method = Class.forName("java.util.ArrayList").getMethod("remove", int.class);
            method.invoke(new java.util.ArrayList<>(), 5); // IndexOutOfBoundsException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable targetException = e.getTargetException();
            if (targetException instanceof RuntimeException) {
                throw (RuntimeException) targetException;
            } else if (targetException instanceof Error) {
                throw (Error) targetException;
            } else {
                throw new RuntimeException(targetException);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_11() {
        try {
            Method method = Class.forName("java.io.FileReader").getConstructor(String.class).newInstance("nonexistent_file");
            method.invoke("read"); // FileNotFoundException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw new RuntimeException(cause);
            } else if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_12() {
        try {
            Method method = Class.class.getMethod("forName", String.class);
            method.invoke(null, "nonexistent.Class"); // ClassNotFoundException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getCause();
            if (cause instanceof ClassNotFoundException) {
                throw new RuntimeException(cause);
            } else if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_13() {
        try {
            Method method = Integer.class.getMethod("decode", String.class);
            method.invoke(null, "not_a_hex_number"); // NumberFormatException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getTargetException();
            if (cause instanceof NumberFormatException) {
                throw (NumberFormatException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_14() {
        try {
            Method method = Class.forName("java.net.URL").getConstructor(String.class).newInstance("malformed:url");
            method.invoke("openConnection"); // MalformedURLException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw new RuntimeException(cause);
            } else if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void good_case_15() {
        try {
            Method method = Class.forName("java.util.concurrent.Future").getMethod("get");
            Future<?> future = createFailingFuture();
            method.invoke(future); // ExecutionException
        } catch (InvocationTargetException e) {
            // ok: java-wrappingcaughtinvocationtargetexception
            Throwable cause = e.getCause();
            if (cause instanceof ExecutionException) {
                throw new RuntimeException(cause.getCause());
            } else if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            } else {
                throw new RuntimeException(cause);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Helper method to create a failing Future
    private Future<String> createFailingFuture() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> future = executor.submit(new Callable<String>() {
            @Override
            public String call() throws Exception {
                throw new SQLException("Database error");
            }
        });
        executor.shutdown();
        return future;
    }
}
// {/fact}