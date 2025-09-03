// File: redundant_switch_statement_tests.ts

// True Positives (Vulnerable Code Examples)

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1() {
    // Simple switch with only one case
    const userRole = "admin";
    
    // ruleid: typescript-redundant-switch-statement
    switch (userRole) {
        case "admin":
            console.log("Admin access granted");
            break;
        default:
            console.log("Access denied");
            break;
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2() {
    // Switch with one case and default in authentication logic
    const authMethod = "password";
    let isAuthenticated = false;
    
    // ruleid: typescript-redundant-switch-statement
    switch (authMethod) {
        case "password":
            isAuthenticated = true;
            break;
        default:
            isAuthenticated = false;
    }
    
    return isAuthenticated;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3() {
    // Switch with two cases in permission check
    const permission = "read";
    
    // ruleid: typescript-redundant-switch-statement
    switch (permission) {
        case "read":
            return true;
        case "write":
            return false;
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4() {
    // Switch with one case in error handling
    const errorCode = 404;
    
    // ruleid: typescript-redundant-switch-statement
    switch (errorCode) {
        case 404:
            throw new Error("Resource not found");
        default:
            throw new Error("Unknown error");
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5() {
    // Switch with two cases in input validation
    const inputType = "string";
    
    // ruleid: typescript-redundant-switch-statement
    switch (inputType) {
        case "string":
            return validateString();
        case "number":
            return validateNumber();
    }
    
    function validateString() { return true; }
    function validateNumber() { return true; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6() {
    // Switch with one case in configuration selection
    const environment = "production";
    let apiUrl: string;
    
    // ruleid: typescript-redundant-switch-statement
    switch (environment) {
        case "production":
            apiUrl = "https://api.example.com";
            break;
        default:
            apiUrl = "https://dev-api.example.com";
    }
    
    return apiUrl;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7() {
    // Switch with two cases in user role handling
    const role = "user";
    
    // ruleid: typescript-redundant-switch-statement
    switch (role) {
        case "user":
            return { canRead: true, canWrite: false };
        case "admin":
            return { canRead: true, canWrite: true };
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8() {
    // Switch with one case in HTTP method handling
    const method = "GET";
    
    // ruleid: typescript-redundant-switch-statement
    switch (method) {
        case "GET":
            return handleGet();
        default:
            return handleOther();
    }
    
    function handleGet() { return {}; }
    function handleOther() { return {}; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_9() {
    // Switch with two cases in data format handling
    const format = "json";
    
    // ruleid: typescript-redundant-switch-statement
    switch (format) {
        case "json":
            return JSON.stringify({ success: true });
        case "xml":
            return "<response><success>true</success></response>";
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10() {
    // Switch with one case in authentication type selection
    const authType = "oauth";
    
    // ruleid: typescript-redundant-switch-statement
    switch (authType) {
        case "oauth":
            return getOAuthToken();
        default:
            return getBasicAuthToken();
    }
    
    function getOAuthToken() { return "token"; }
    function getBasicAuthToken() { return "token"; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11() {
    // Switch with two cases in database connection selection
    const dbType = "mysql";
    
    // ruleid: typescript-redundant-switch-statement
    switch (dbType) {
        case "mysql":
            return connectToMySQL();
        case "postgres":
            return connectToPostgres();
    }
    
    function connectToMySQL() { return {}; }
    function connectToPostgres() { return {}; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12() {
    // Switch with one case in logging level selection
    const logLevel = "error";
    
    // ruleid: typescript-redundant-switch-statement
    switch (logLevel) {
        case "error":
            console.error("This is an error");
            break;
        default:
            console.log("This is a regular log");
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13() {
    // Switch with two cases in encryption method selection
    const encryptionType = "aes";
    
    // ruleid: typescript-redundant-switch-statement
    switch (encryptionType) {
        case "aes":
            return encryptAES("sensitive data");
        case "rsa":
            return encryptRSA("sensitive data");
    }
    
    function encryptAES(data: string) { return data; }
    function encryptRSA(data: string) { return data; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14() {
    // Switch with one case in file access permission check
    const fileAccess = "read";
    
    // ruleid: typescript-redundant-switch-statement
    switch (fileAccess) {
        case "read":
            return true;
        default:
            return false;
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15() {
    // Switch with two cases in API version handling
    const apiVersion = "v1";
    
    // ruleid: typescript-redundant-switch-statement
    switch (apiVersion) {
        case "v1":
            return handleV1Request();
        case "v2":
            return handleV2Request();
    }
    
    function handleV1Request() { return {}; }
    function handleV2Request() { return {}; }
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=code-injection@v1.0 defects=0}
function good_case_1() {
    // Using if-else instead of switch for binary condition
    const userRole = "admin";
    
    // ok: typescript-redundant-switch-statement
    if (userRole === "admin") {
        console.log("Admin access granted");
    } else {
        console.log("Access denied");
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_2() {
    // Using ternary operator for binary condition
    const authMethod = "password";
    
    // ok: typescript-redundant-switch-statement
    const isAuthenticated = authMethod === "password" ? true : false;
    
    return isAuthenticated;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_3() {
    // Using switch with three cases (sufficient complexity)
    const permission = "read";
    
    // ok: typescript-redundant-switch-statement
    switch (permission) {
        case "read":
            return { canRead: true, canWrite: false, canDelete: false };
        case "write":
            return { canRead: true, canWrite: true, canDelete: false };
        case "admin":
            return { canRead: true, canWrite: true, canDelete: true };
        default:
            return { canRead: false, canWrite: false, canDelete: false };
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_4() {
    // Using object literal for mapping instead of switch
    const errorCode = 404;
    
    // ok: typescript-redundant-switch-statement
    const errorMessages: Record<number, string> = {
        404: "Resource not found",
        500: "Internal server error"
    };
    
    const message = errorMessages[errorCode] || "Unknown error";
    throw new Error(message);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_5() {
    // Using Map for mapping values
    const inputType = "string";
    
    // ok: typescript-redundant-switch-statement
    const validators = new Map<string, () => boolean>();
    validators.set("string", () => true);
    validators.set("number", () => true);
    
    const validator = validators.get(inputType);
    return validator ? validator() : false;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_6() {
    // Using switch with multiple cases (sufficient complexity)
    const environment = "production";
    let apiUrl: string;
    
    // ok: typescript-redundant-switch-statement
    switch (environment) {
        case "development":
            apiUrl = "http://localhost:3000";
            break;
        case "staging":
            apiUrl = "https://staging-api.example.com";
            break;
        case "production":
            apiUrl = "https://api.example.com";
            break;
        default:
            apiUrl = "https://dev-api.example.com";
    }
    
    return apiUrl;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_7() {
    // Using direct object access instead of switch
    const role = "user";
    
    // ok: typescript-redundant-switch-statement
    const permissions = {
        user: { canRead: true, canWrite: false },
        admin: { canRead: true, canWrite: true },
        guest: { canRead: true, canWrite: false }
    };
    
    return permissions[role as keyof typeof permissions] || { canRead: false, canWrite: false };
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_8() {
    // Using function mapping instead of switch
    const method = "GET";
    
    // ok: typescript-redundant-switch-statement
    const handlers: Record<string, () => object> = {
        GET: () => handleGet(),
        POST: () => handlePost(),
        PUT: () => handlePut()
    };
    
    const handler = handlers[method] || (() => handleOther());
    return handler();
    
    function handleGet() { return {}; }
    function handlePost() { return {}; }
    function handlePut() { return {}; }
    function handleOther() { return {}; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_9() {
    // Using switch with three cases for data format handling
    const format = "json";
    
    // ok: typescript-redundant-switch-statement
    switch (format) {
        case "json":
            return JSON.stringify({ success: true });
        case "xml":
            return "<response><success>true</success></response>";
        case "yaml":
            return "success: true";
        default:
            return "success=true";
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_10() {
    // Using a more direct approach with object literals
    const authType = "oauth";
    
    // ok: typescript-redundant-switch-statement
    const authHandlers = {
        oauth: getOAuthToken,
        basic: getBasicAuthToken,
        jwt: getJWTToken
    };
    
    const handler = authHandlers[authType as keyof typeof authHandlers] || getBasicAuthToken;
    return handler();
    
    function getOAuthToken() { return "oauth_token"; }
    function getBasicAuthToken() { return "basic_token"; }
    function getJWTToken() { return "jwt_token"; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_11() {
    // Using switch with three or more cases
    const dbType = "mysql";
    
    // ok: typescript-redundant-switch-statement
    switch (dbType) {
        case "mysql":
            return connectToMySQL();
        case "postgres":
            return connectToPostgres();
        case "mongodb":
            return connectToMongoDB();
        case "sqlite":
            return connectToSQLite();
        default:
            throw new Error("Unsupported database type");
    }
    
    function connectToMySQL() { return {}; }
    function connectToPostgres() { return {}; }
    function connectToMongoDB() { return {}; }
    function connectToSQLite() { return {}; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_12() {
    // Using if-else-if chain instead of switch
    const logLevel = "error";
    
    // ok: typescript-redundant-switch-statement
    if (logLevel === "error") {
        console.error("This is an error");
    } else if (logLevel === "warn") {
        console.warn("This is a warning");
    } else {
        console.log("This is a regular log");
    }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_13() {
    // Using a dictionary approach for encryption methods
    const encryptionType = "aes";
    
    // ok: typescript-redundant-switch-statement
    const encryptionMethods = {
        aes: (data: string) => encryptAES(data),
        rsa: (data: string) => encryptRSA(data),
        blowfish: (data: string) => encryptBlowfish(data)
    };
    
    const encrypt = encryptionMethods[encryptionType as keyof typeof encryptionMethods];
    return encrypt ? encrypt("sensitive data") : "encryption failed";
    
    function encryptAES(data: string) { return data; }
    function encryptRSA(data: string) { return data; }
    function encryptBlowfish(data: string) { return data; }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_14() {
    // Using a more direct boolean expression
    const fileAccess = "read";
    
    // ok: typescript-redundant-switch-statement
    return fileAccess === "read";
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_15() {
    // Using switch with three cases for API version handling
    const apiVersion = "v1";
    
    // ok: typescript-redundant-switch-statement
    switch (apiVersion) {
        case "v1":
            return handleV1Request();
        case "v2":
            return handleV2Request();
        case "v3":
            return handleV3Request();
        default:
            return handleLatestRequest();
    }
    
    function handleV1Request() { return {}; }
    function handleV2Request() { return {}; }
    function handleV3Request() { return {}; }
    function handleLatestRequest() { return {}; }
}
// {/fact}