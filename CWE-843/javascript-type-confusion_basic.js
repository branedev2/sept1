// JavaScript Type Confusion Vulnerability Examples
// Rule ID: javascript-type-confusion
// CWE: 843

// Required imports for HTTP handling
const express = require('express');
const app = express();
const http = require('http');
const url = require('url');
const axios = require('axios');

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Using includes on request parameter without type checking
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.search;
    
    // Checking if input contains a specific substring without type checking
    if (userInput.includes("admin")) {
        // ruleid: javascript-type-confusion
        res.status(403).send("Access denied");
    } else {
        res.status(200).send("Access granted");
    }
}
// {/fact}

// Example 2: Using indexOf on request parameter without type checking
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_2(req, res) {
    const userInput = req.query.keyword;
    
    // Using indexOf without type checking
    // ruleid: javascript-type-confusion
    if (userInput.indexOf("password") !== -1) {
        res.status(403).send("Cannot use 'password' in search");
    } else {
        performSearch(userInput);
    }
}
// {/fact}

// Example 3: Using lastIndexOf on request body without type checking
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_3(req, res) {
    const userInput = req.body.text;
    
    // Using lastIndexOf without type checking
    // ruleid: javascript-type-confusion
    const lastDotPosition = userInput.lastIndexOf(".");
    const fileExtension = userInput.substring(lastDotPosition + 1);
    
    if (["jpg", "png", "gif"].includes(fileExtension)) {
        processImage(userInput);
    } else {
        res.status(400).send("Invalid file format");
    }
}
// {/fact}

// Example 4: Using includes in a more complex flow
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_4(req, res) {
    const userRole = req.headers['x-user-role'];
    
    function checkAccess() {
        // Using includes without type checking in a nested function
        // ruleid: javascript-type-confusion
        if (userRole.includes("admin") || userRole.includes("superuser")) {
            return true;
        }
        return false;
    }
    
    if (checkAccess()) {
        res.status(200).send("Admin panel access granted");
    } else {
        res.status(403).send("Access denied");
    }
}
// {/fact}

// Example 5: Using indexOf with request headers
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_5(req, res) {
    const userAgent = req.headers['user-agent'];
    
    // Using indexOf without type checking
    // ruleid: javascript-type-confusion
    if (userAgent.indexOf("Mozilla") !== -1) {
        res.status(200).send("Browser detected");
    } else {
        res.status(200).send("Non-browser client detected");
    }
}
// {/fact}

// Example 6: Using includes with URL parameters
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_6(req, res) {
    const urlPath = req.path;
    
    // Using includes without type checking
    // ruleid: javascript-type-confusion
    if (urlPath.includes("/api/")) {
        handleApiRequest(req, res);
    } else {
        handleWebRequest(req, res);
    }
}
// {/fact}

// Example 7: Using indexOf in a conditional with cookies
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_7(req, res) {
    const sessionToken = req.cookies.session;
    
    // Using indexOf without type checking
    // ruleid: javascript-type-confusion
    if (sessionToken.indexOf("valid") === 0) {
        authenticateUser(sessionToken);
    } else {
        res.status(401).send("Invalid session");
    }
}
// {/fact}

// Example 8: Using lastIndexOf with query parameters in a loop
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_8(req, res) {
    const queries = Object.values(req.query);
    
    for (let i = 0; i < queries.length; i++) {
        const query = queries[i];
        // Using lastIndexOf without type checking in a loop
        // ruleid: javascript-type-confusion
        const lastSlashPos = query.lastIndexOf("/");
        if (lastSlashPos !== -1) {
            const segment = query.substring(lastSlashPos + 1);
            validateSegment(segment);
        }
    }
    
    res.status(200).send("Queries processed");
}
// {/fact}

// Example 9: Using includes with request body in JSON format
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_9(req, res) {
    const userData = req.body.user;
    
    // Using includes without type checking
    // ruleid: javascript-type-confusion
    if (userData.email.includes("@company.com")) {
        grantInternalAccess(userData);
    } else {
        grantExternalAccess(userData);
    }
}
// {/fact}

// Example 10: Using indexOf with URL parameters in an async function
// {fact rule=type-confusion@v1.0 defects=1}
async function bad_case_10(req, res) {
    const redirectUrl = req.query.redirect;
    
    try {
        // Using indexOf without type checking
        // ruleid: javascript-type-confusion
        if (redirectUrl.indexOf("https://") === 0) {
            await logRedirect(redirectUrl);
            res.redirect(redirectUrl);
        } else {
            res.status(400).send("Invalid redirect URL");
        }
    } catch (error) {
        res.status(500).send("Server error");
    }
}
// {/fact}

// Example 11: Using includes with form data
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_11(req, res) {
    const formData = req.body.formData;
    
    // Using includes without type checking
    // ruleid: javascript-type-confusion
    if (formData.message.includes("<script>")) {
        res.status(400).send("Potential XSS detected");
    } else {
        saveFormData(formData);
        res.status(200).send("Form submitted");
    }
}
// {/fact}

// Example 12: Using indexOf with request parameters in a switch statement
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_12(req, res) {
    const action = req.query.action;
    
    // Using indexOf without type checking
    // ruleid: javascript-type-confusion
    const actionType = action.indexOf("admin") !== -1 ? "admin" : 
                      action.indexOf("user") !== -1 ? "user" : "guest";
    
    switch (actionType) {
        case "admin":
            performAdminAction();
            break;
        case "user":
            performUserAction();
            break;
        default:
            performGuestAction();
    }
    
    res.status(200).send(`${actionType} action performed`);
}
// {/fact}

// Example 13: Using lastIndexOf with multiple request parameters
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_13(req, res) {
    const filePath = req.query.path;
    const fileName = req.query.name;
    
    // Using lastIndexOf without type checking
    // ruleid: javascript-type-confusion
    const fileExt = fileName.substring(fileName.lastIndexOf(".") + 1);
    
    if (isValidExtension(fileExt)) {
        // Using lastIndexOf without type checking again
        // ruleid: javascript-type-confusion
        const dirPath = filePath.substring(0, filePath.lastIndexOf("/"));
        saveFile(dirPath, fileName);
        res.status(200).send("File saved");
    } else {
        res.status(400).send("Invalid file extension");
    }
}
// {/fact}

// Example 14: Using includes with request parameters in an arrow function
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_14(req, res) {
    const tags = req.query.tags;
    
    const hasRestrictedTag = () => {
        const restrictedTags = ["private", "confidential", "secret"];
        // Using includes without type checking in an arrow function
        // ruleid: javascript-type-confusion
        return restrictedTags.some(tag => tags.includes(tag));
    };
    
    if (hasRestrictedTag()) {
        res.status(403).send("Access to restricted tags denied");
    } else {
        res.status(200).send("Access granted");
    }
}
// {/fact}

// Example 15: Using indexOf with request parameters in a try-catch block
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_15(req, res) {
    const searchQuery = req.query.q;
    
    try {
        // Using indexOf without type checking
        // ruleid: javascript-type-confusion
        if (searchQuery.indexOf("!") !== -1) {
            performPrioritySearch(searchQuery);
        } else {
            performRegularSearch(searchQuery);
        }
        res.status(200).send("Search completed");
    } catch (error) {
        res.status(500).send("Search error: " + error.message);
    }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using includes with type checking
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.search;
    
    // Type checking before using includes
    // ok: javascript-type-confusion
    if (typeof userInput === 'string' && userInput.includes("admin")) {
        res.status(403).send("Access denied");
    } else {
        res.status(200).send("Access granted");
    }
}
// {/fact}

// Example 2: Using indexOf with type checking
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_2(req, res) {
    const userInput = req.query.keyword;
    
    // Type checking before using indexOf
    // ok: javascript-type-confusion
    if (typeof userInput === 'string' && userInput.indexOf("password") !== -1) {
        res.status(403).send("Cannot use 'password' in search");
    } else {
        performSearch(userInput);
    }
}
// {/fact}

// Example 3: Using lastIndexOf with type checking
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_3(req, res) {
    const userInput = req.body.text;
    
    // Type checking before using lastIndexOf
    // ok: javascript-type-confusion
    if (typeof userInput === 'string') {
        const lastDotPosition = userInput.lastIndexOf(".");
        const fileExtension = userInput.substring(lastDotPosition + 1);
        
        if (["jpg", "png", "gif"].includes(fileExtension)) {
            processImage(userInput);
        } else {
            res.status(400).send("Invalid file format");
        }
    } else {
        res.status(400).send("Input must be a string");
    }
}
// {/fact}

// Example 4: Using includes with type checking in a complex flow
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_4(req, res) {
    const userRole = req.headers['x-user-role'];
    
    function checkAccess() {
        // Type checking before using includes
        // ok: javascript-type-confusion
        if (typeof userRole === 'string' && 
            (userRole.includes("admin") || userRole.includes("superuser"))) {
            return true;
        }
        return false;
    }
    
    if (checkAccess()) {
        res.status(200).send("Admin panel access granted");
    } else {
        res.status(403).send("Access denied");
    }
}
// {/fact}

// Example 5: Using indexOf with type checking for headers
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_5(req, res) {
    const userAgent = req.headers['user-agent'];
    
    // Type checking before using indexOf
    // ok: javascript-type-confusion
    if (typeof userAgent === 'string' && userAgent.indexOf("Mozilla") !== -1) {
        res.status(200).send("Browser detected");
    } else {
        res.status(200).send("Non-browser client detected");
    }
}
// {/fact}

// Example 6: Using String constructor to ensure string type
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_6(req, res) {
    const urlPath = req.path;
    
    // Converting to string before using includes
    // ok: javascript-type-confusion
    const pathString = String(urlPath);
    if (pathString.includes("/api/")) {
        handleApiRequest(req, res);
    } else {
        handleWebRequest(req, res);
    }
}
// {/fact}

// Example 7: Using toString method to ensure string type
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_7(req, res) {
    const sessionToken = req.cookies.session;
    
    // Converting to string before using indexOf
    // ok: javascript-type-confusion
    if (sessionToken && sessionToken.toString().indexOf("valid") === 0) {
        authenticateUser(sessionToken);
    } else {
        res.status(401).send("Invalid session");
    }
}
// {/fact}

// Example 8: Using type checking in a loop
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_8(req, res) {
    const queries = Object.values(req.query);
    
    for (let i = 0; i < queries.length; i++) {
        const query = queries[i];
        // Type checking before using lastIndexOf
        // ok: javascript-type-confusion
        if (typeof query === 'string') {
            const lastSlashPos = query.lastIndexOf("/");
            if (lastSlashPos !== -1) {
                const segment = query.substring(lastSlashPos + 1);
                validateSegment(segment);
            }
        }
    }
    
    res.status(200).send("Queries processed");
}
// {/fact}

// Example 9: Using type checking with request body
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_9(req, res) {
    const userData = req.body.user;
    
    // Type checking before using includes
    // ok: javascript-type-confusion
    if (userData && typeof userData.email === 'string' && 
        userData.email.includes("@company.com")) {
        grantInternalAccess(userData);
    } else {
        grantExternalAccess(userData);
    }
}
// {/fact}

// Example 10: Using type checking in an async function
// {fact rule=type-confusion@v1.0 defects=0}
async function good_case_10(req, res) {
    const redirectUrl = req.query.redirect;
    
    try {
        // Type checking before using indexOf
        // ok: javascript-type-confusion
        if (typeof redirectUrl === 'string' && redirectUrl.indexOf("https://") === 0) {
            await logRedirect(redirectUrl);
            res.redirect(redirectUrl);
        } else {
            res.status(400).send("Invalid redirect URL");
        }
    } catch (error) {
        res.status(500).send("Server error");
    }
}
// {/fact}

// Example 11: Using type checking with form data
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_11(req, res) {
    const formData = req.body.formData;
    
    // Type checking before using includes
    // ok: javascript-type-confusion
    if (formData && typeof formData.message === 'string') {
        if (formData.message.includes("<script>")) {
            res.status(400).send("Potential XSS detected");
        } else {
            saveFormData(formData);
            res.status(200).send("Form submitted");
        }
    } else {
        res.status(400).send("Invalid form data");
    }
}
// {/fact}

// Example 12: Using type checking in a complex condition
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_12(req, res) {
    const action = req.query.action;
    
    // Type checking before using indexOf
    // ok: javascript-type-confusion
    let actionType = "guest";
    if (typeof action === 'string') {
        if (action.indexOf("admin") !== -1) {
            actionType = "admin";
        } else if (action.indexOf("user") !== -1) {
            actionType = "user";
        }
    }
    
    switch (actionType) {
        case "admin":
            performAdminAction();
            break;
        case "user":
            performUserAction();
            break;
        default:
            performGuestAction();
    }
    
    res.status(200).send(`${actionType} action performed`);
}
// {/fact}

// Example 13: Using type checking with multiple parameters
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_13(req, res) {
    const filePath = req.query.path;
    const fileName = req.query.name;
    
    // Type checking before using lastIndexOf
    // ok: javascript-type-confusion
    if (typeof fileName === 'string' && typeof filePath === 'string') {
        const fileExt = fileName.substring(fileName.lastIndexOf(".") + 1);
        
        if (isValidExtension(fileExt)) {
            const dirPath = filePath.substring(0, filePath.lastIndexOf("/"));
            saveFile(dirPath, fileName);
            res.status(200).send("File saved");
        } else {
            res.status(400).send("Invalid file extension");
        }
    } else {
        res.status(400).send("Invalid file path or name");
    }
}
// {/fact}

// Example 14: Using type checking in an arrow function
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_14(req, res) {
    const tags = req.query.tags;
    
    const hasRestrictedTag = () => {
        const restrictedTags = ["private", "confidential", "secret"];
        // Type checking before using includes in an arrow function
        // ok: javascript-type-confusion
        return typeof tags === 'string' && 
               restrictedTags.some(tag => tags.includes(tag));
    };
    
    if (hasRestrictedTag()) {
        res.status(403).send("Access to restricted tags denied");
    } else {
        res.status(200).send("Access granted");
    }
}
// {/fact}

// Example 15: Using type checking in a try-catch block
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_15(req, res) {
    const searchQuery = req.query.q;
    
    try {
        // Type checking before using indexOf
        // ok: javascript-type-confusion
        if (typeof searchQuery === 'string') {
            if (searchQuery.indexOf("!") !== -1) {
                performPrioritySearch(searchQuery);
            } else {
                performRegularSearch(searchQuery);
            }
            res.status(200).send("Search completed");
        } else {
            res.status(400).send("Search query must be a string");
        }
    } catch (error) {
        res.status(500).send("Search error: " + error.message);
    }
}
// {/fact}

// Helper functions (implementations not shown for brevity)
function performSearch() {}
function processImage() {}
function handleApiRequest() {}
function handleWebRequest() {}
function authenticateUser() {}
function validateSegment() {}
function grantInternalAccess() {}
function grantExternalAccess() {}
function logRedirect() {}
function saveFormData() {}
function performAdminAction() {}
function performUserAction() {}
function performGuestAction() {}
function isValidExtension() {}
function saveFile() {}
function performPrioritySearch() {}
function performRegularSearch() {}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});