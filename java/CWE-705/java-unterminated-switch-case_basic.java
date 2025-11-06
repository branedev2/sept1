public class UnterminatedSwitchCaseExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=code-injection@v1.0 defects=1}
    public void bad_case_1(int value) {
        switch (value) {
            case 1:
                System.out.println("Value is 1");
                // ruleid: java-unterminated-switch-case
                // Missing break statement causes fall-through to next case
            case 2:
                System.out.println("Value is 2");
                break;
            default:
                System.out.println("Unknown value");
        }
    }

    public void bad_case_2(String command) {
        switch (command) {
            case "delete":
                System.out.println("Deleting files");
                // ruleid: java-unterminated-switch-case
                // Missing break causes unintended execution of "format" case
            case "format":
                System.out.println("Formatting drive");
                break;
            case "backup":
                System.out.println("Backing up files");
                break;
        }
    }

    public void bad_case_3(char grade) {
        int points = 0;
        switch (grade) {
            case 'A':
                points = 4;
                // ruleid: java-unterminated-switch-case
            case 'B':
                points = 3;
                // ruleid: java-unterminated-switch-case
            case 'C':
                points = 2;
                break;
            default:
                points = 0;
        }
        System.out.println("Points: " + points);
    }

    public void bad_case_4(int accessLevel) {
        boolean canRead = false;
        boolean canWrite = false;
        boolean canDelete = false;
        
        switch (accessLevel) {
            case 3:
                canDelete = true;
                // ruleid: java-unterminated-switch-case
            case 2:
                canWrite = true;
                // ruleid: java-unterminated-switch-case
            case 1:
                canRead = true;
                break;
            default:
                System.out.println("No permissions");
        }
        
        System.out.println("Permissions: Read=" + canRead + ", Write=" + canWrite + ", Delete=" + canDelete);
    }

    public void bad_case_5(String role) {
        switch (role) {
            case "admin":
                System.out.println("Full access granted");
                // ruleid: java-unterminated-switch-case
            case "manager":
                System.out.println("Limited access granted");
                break;
            default:
                System.out.println("Access denied");
        }
    }

    public void bad_case_6(int errorCode) {
        String message = "";
        switch (errorCode) {
            case 404:
                message = "Not found";
                // ruleid: java-unterminated-switch-case
            case 500:
                message = "Server error";
                break;
            default:
                message = "Unknown error";
        }
        System.out.println("Error: " + message);
    }

    public void bad_case_7(String operation) {
        switch (operation) {
            case "encrypt":
                System.out.println("Encrypting data");
                // ruleid: java-unterminated-switch-case
                // Missing break causes unintended execution
            case "decrypt":
                System.out.println("Decrypting data");
                break;
            default:
                System.out.println("Invalid operation");
        }
    }

    public void bad_case_8(int day) {
        String dayType = "";
        switch (day) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
                dayType = "Weekday";
                // ruleid: java-unterminated-switch-case
            case 6:
            case 7:
                dayType = "Weekend";
                break;
        }
        System.out.println("Day type: " + dayType);
    }

    public void bad_case_9(String status) {
        boolean isActive = false;
        switch (status) {
            case "active":
                isActive = true;
                // ruleid: java-unterminated-switch-case
            case "pending":
                System.out.println("Account needs review");
                break;
            case "inactive":
                System.out.println("Account is disabled");
                break;
        }
        System.out.println("Active status: " + isActive);
    }

    public void bad_case_10(int option) {
        switch (option) {
            case 1:
                System.out.println("Option 1 selected");
                if (option > 0) {
                    System.out.println("Positive option");
                }
                // ruleid: java-unterminated-switch-case
            case 2:
                System.out.println("Option 2 selected");
                break;
        }
    }

    public void bad_case_11(String fruit) {
        int price = 0;
        switch (fruit) {
            case "apple":
                price = 1;
                System.out.println("Selected apple");
                // ruleid: java-unterminated-switch-case
            case "banana":
                price = 2;
                System.out.println("Selected banana");
                break;
            default:
                price = 5;
        }
        System.out.println("Price: $" + price);
    }

    public void bad_case_12(char category) {
        switch (category) {
            case 'A':
                System.out.println("Premium category");
                // ruleid: java-unterminated-switch-case
            case 'B':
                System.out.println("Standard category");
                // ruleid: java-unterminated-switch-case
            case 'C':
                System.out.println("Basic category");
                // No break statement
        }
    }

    public void bad_case_13(int level) {
        String message = "";
        switch (level) {
            case 1:
                message = "Beginner";
                // ruleid: java-unterminated-switch-case
            case 2:
                message = "Intermediate";
                // ruleid: java-unterminated-switch-case
            case 3:
                message = "Advanced";
                // No break statement
        }
        System.out.println("Level: " + message);
    }

    public void bad_case_14(String action) {
        switch (action) {
            case "save":
                System.out.println("Saving document");
                // ruleid: java-unterminated-switch-case
            case "saveAs":
                System.out.println("Saving document as new file");
                break;
            case "open":
                System.out.println("Opening document");
                break;
        }
    }

    public void bad_case_15(int state) {
        String status = "";
        switch (state) {
            case 0:
                status = "Stopped";
                // ruleid: java-unterminated-switch-case
            case 1:
                status = "Running";
                break;
            case 2:
                status = "Paused";
                break;
        }
        System.out.println("Current status: " + status);
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(int value) {
        switch (value) {
            case 1:
                System.out.println("Value is 1");
                // ok: java-unterminated-switch-case
                break;
            case 2:
                System.out.println("Value is 2");
                break;
            default:
                System.out.println("Unknown value");
        }
    }

    public void good_case_2(String command) {
        switch (command) {
            case "delete":
                System.out.println("Deleting files");
                // ok: java-unterminated-switch-case
                break;
            case "format":
                System.out.println("Formatting drive");
                break;
            case "backup":
                System.out.println("Backing up files");
                break;
        }
    }

    public void good_case_3(char grade) {
        int points = 0;
        switch (grade) {
            case 'A':
                points = 4;
                // ok: java-unterminated-switch-case
                break;
            case 'B':
                points = 3;
                break;
            case 'C':
                points = 2;
                break;
            default:
                points = 0;
        }
        System.out.println("Points: " + points);
    }

    public void good_case_4(int accessLevel) {
        boolean canRead = false;
        boolean canWrite = false;
        boolean canDelete = false;
        
        switch (accessLevel) {
            case 3:
                canDelete = true;
                canWrite = true;
                canRead = true;
                // ok: java-unterminated-switch-case
                break;
            case 2:
                canWrite = true;
                canRead = true;
                break;
            case 1:
                canRead = true;
                break;
            default:
                System.out.println("No permissions");
        }
        
        System.out.println("Permissions: Read=" + canRead + ", Write=" + canWrite + ", Delete=" + canDelete);
    }

    public void good_case_5(String role) {
        switch (role) {
            case "admin":
                System.out.println("Full access granted");
                // ok: java-unterminated-switch-case
                break;
            case "manager":
                System.out.println("Limited access granted");
                break;
            default:
                System.out.println("Access denied");
        }
    }

    public void good_case_6(int errorCode) {
        String message = "";
        switch (errorCode) {
            case 404:
                message = "Not found";
                // ok: java-unterminated-switch-case
                break;
            case 500:
                message = "Server error";
                break;
            default:
                message = "Unknown error";
        }
        System.out.println("Error: " + message);
    }

    public void good_case_7(String operation) {
        switch (operation) {
            case "encrypt":
                System.out.println("Encrypting data");
                // ok: java-unterminated-switch-case
                return; // Using return instead of break is also valid
            case "decrypt":
                System.out.println("Decrypting data");
                return;
            default:
                System.out.println("Invalid operation");
        }
    }

    public void good_case_8(int day) {
        String dayType = "";
        switch (day) {
            // Intentional fall-through for weekdays (1-5)
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
                dayType = "Weekday";
                // ok: java-unterminated-switch-case
                break;
            // Intentional fall-through for weekend days (6-7)
            case 6:
            case 7:
                dayType = "Weekend";
                break;
        }
        System.out.println("Day type: " + dayType);
    }

    public void good_case_9(String status) {
        boolean isActive = false;
        switch (status) {
            case "active":
                isActive = true;
                // ok: java-unterminated-switch-case
                break;
            case "pending":
                System.out.println("Account needs review");
                break;
            case "inactive":
                System.out.println("Account is disabled");
                break;
        }
        System.out.println("Active status: " + isActive);
    }

    public void good_case_10(int option) {
        switch (option) {
            case 1:
                System.out.println("Option 1 selected");
                if (option > 0) {
                    System.out.println("Positive option");
                }
                // ok: java-unterminated-switch-case
                break;
            case 2:
                System.out.println("Option 2 selected");
                break;
        }
    }

    public void good_case_11(String fruit) {
        int price = 0;
        switch (fruit) {
            case "apple":
                price = 1;
                System.out.println("Selected apple");
                // ok: java-unterminated-switch-case
                break;
            case "banana":
                price = 2;
                System.out.println("Selected banana");
                break;
            default:
                price = 5;
        }
        System.out.println("Price: $" + price);
    }

    public void good_case_12(char category) {
        switch (category) {
            case 'A':
                System.out.println("Premium category");
                // ok: java-unterminated-switch-case
                break;
            case 'B':
                System.out.println("Standard category");
                break;
            case 'C':
                System.out.println("Basic category");
                break;
        }
    }

    public void good_case_13(int level) {
        String message = "";
        switch (level) {
            case 1:
                message = "Beginner";
                // ok: java-unterminated-switch-case
                break;
            case 2:
                message = "Intermediate";
                break;
            case 3:
                message = "Advanced";
                break;
        }
        System.out.println("Level: " + message);
    }

    public void good_case_14(String action) {
        switch (action) {
            case "save":
                System.out.println("Saving document");
                // ok: java-unterminated-switch-case
                throw new RuntimeException("Error saving document"); // Using throw instead of break is also valid
            case "saveAs":
                System.out.println("Saving document as new file");
                break;
            case "open":
                System.out.println("Opening document");
                break;
        }
    }

    public void good_case_15(int state) {
        String status = "";
        switch (state) {
            case 0:
                status = "Stopped";
                // ok: java-unterminated-switch-case
                break;
            case 1:
                status = "Running";
                break;
            case 2:
                status = "Paused";
                break;
        }
        System.out.println("Current status: " + status);
    }
}
// {/fact}