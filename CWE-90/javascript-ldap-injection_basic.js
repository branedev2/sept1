// Filename: ldap_injection_test_cases.js

const express = require('express');
const ldap = require('ldapjs');
const { escape } = require('ldapjs');

// True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    app.get('/search', (req, res) => {
        const username = req.query.username;
        
        const client = ldap.createClient({
            url: 'ldap://ldap.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filter = `(uid=${username})`;
        client.search('dc=example,dc=com', { filter: filter }, (err, result) => {
            if (err) {
                return res.status(500).send('Error');
            }
            
            let entries = [];
            result.on('searchEntry', (entry) => {
                entries.push(entry.object);
            });
            
            result.on('end', () => {
                res.json(entries);
            });
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    app.post('/ldap-search', (req, res) => {
        const searchTerm = req.body.search;
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        client.search('ou=users,dc=example,dc=com', {
            filter: `(&(objectClass=person)(cn=${searchTerm}))`,
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    app.get('/user-details', (req, res) => {
        const userId = req.query.id;
        const client = ldap.createClient({
            url: 'ldaps://secure-ldap.example.com:636'
        });
        
        client.bind('cn=admin,dc=example,dc=com', 'password', (err) => {
            if (err) {
                return res.status(500).send('Bind error');
            }
            
            // ruleid: javascript-ldap-injection
            const searchOptions = {
                filter: `(|(uid=${userId})(mail=${userId}))`,
                scope: 'sub',
                attributes: ['cn', 'mail']
            };
            
            client.search('ou=people,dc=example,dc=com', searchOptions, (err, search) => {
                // Process results
                res.send('Search completed');
            });
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    app.get('/group-members', (req, res) => {
        const groupName = req.query.group;
        const client = ldap.createClient({
            url: 'ldap://ldap.internal.org:389'
        });
        
        // ruleid: javascript-ldap-injection
        const searchFilter = `(&(objectClass=groupOfNames)(cn=${groupName}))`;
        
        client.search('ou=groups,dc=example,dc=com', {
            filter: searchFilter,
            scope: 'one'
        }, (err, search) => {
            if (err) {
                return res.status(500).send('Error searching');
            }
            
            // Process results
            res.send('Group search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    app.get('/employee', (req, res) => {
        const employeeId = req.query.id;
        const department = req.query.dept;
        
        const client = ldap.createClient({
            url: 'ldap://corp-directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filter = `(&(employeeID=${employeeId})(departmentNumber=${department}))`;
        
        client.search('ou=employees,dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Employee search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    app.post('/authenticate', (req, res) => {
        const username = req.body.username;
        
        const client = ldap.createClient({
            url: 'ldap://auth.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        client.search(`ou=users,dc=example,dc=com`, {
            filter: `(uid=${username})`,
            scope: 'sub'
        }, (err, search) => {
            // Process authentication
            res.send('Authentication processed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    app.get('/search-by-attribute', (req, res) => {
        const attributeName = req.query.attr;
        const attributeValue = req.query.value;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const searchFilter = `(${attributeName}=${attributeValue})`;
        
        client.search('dc=example,dc=com', {
            filter: searchFilter
        }, (err, search) => {
            // Process results
            res.send('Attribute search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    app.get('/complex-search', (req, res) => {
        const firstName = req.query.first;
        const lastName = req.query.last;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filter = `(&(givenName=${firstName})(sn=${lastName}))`;
        
        client.search('ou=people,dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Complex search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    app.post('/search-with-headers', (req, res) => {
        const orgId = req.headers['x-organization-id'];
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        client.search('dc=example,dc=com', {
            filter: `(organizationId=${orgId})`,
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Organization search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    app.get('/search-with-cookie', (req, res) => {
        const userRole = req.cookies.role;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filter = `(roleAttribute=${userRole})`;
        
        client.search('ou=roles,dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Role search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    app.get('/search-with-template', (req, res) => {
        const searchTerm = req.query.q;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filterTemplate = `(|(cn=*${searchTerm}*)(mail=*${searchTerm}*))`;
        
        client.search('dc=example,dc=com', {
            filter: filterTemplate
        }, (err, search) => {
            // Process results
            res.send('Template search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    app.post('/modify-entry', (req, res) => {
        const dn = req.body.dn;
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        client.bind('cn=admin,dc=example,dc=com', 'password', (err) => {
            if (err) {
                return res.status(500).send('Bind error');
            }
            
            // ruleid: javascript-ldap-injection
            client.search(dn, {
                filter: '(objectClass=*)',
                scope: 'base'
            }, (err, search) => {
                // Process results
                res.send('DN search completed');
            });
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    app.get('/dynamic-base-dn', (req, res) => {
        const orgUnit = req.query.ou;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const baseDN = `ou=${orgUnit},dc=example,dc=com`;
        
        client.search(baseDN, {
            filter: '(objectClass=person)',
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Dynamic base DN search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    app.get('/search-with-json', (req, res) => {
        const searchData = JSON.parse(req.query.data);
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filter = `(&(objectClass=${searchData.class})(${searchData.attribute}=${searchData.value}))`;
        
        client.search('dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('JSON search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    app.get('/search-with-or', (req, res) => {
        const term1 = req.query.term1;
        const term2 = req.query.term2;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ruleid: javascript-ldap-injection
        const filter = `(|(cn=${term1})(cn=${term2}))`;
        
        client.search('dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('OR search completed');
        });
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1() {
    const app = express();
    app.get('/search', (req, res) => {
        const username = req.query.username;
        
        const client = ldap.createClient({
            url: 'ldap://ldap.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const filter = `(uid=${escape(username)})`;
        client.search('dc=example,dc=com', { filter: filter }, (err, result) => {
            if (err) {
                return res.status(500).send('Error');
            }
            
            let entries = [];
            result.on('searchEntry', (entry) => {
                entries.push(entry.object);
            });
            
            result.on('end', () => {
                res.json(entries);
            });
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2() {
    const app = express();
    app.post('/ldap-search', (req, res) => {
        const searchTerm = req.body.search;
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        client.search('ou=users,dc=example,dc=com', {
            filter: `(&(objectClass=person)(cn=${ldap.escape(searchTerm)}))`,
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3() {
    const app = express();
    app.get('/user-details', (req, res) => {
        const userId = req.query.id;
        const client = ldap.createClient({
            url: 'ldaps://secure-ldap.example.com:636'
        });
        
        client.bind('cn=admin,dc=example,dc=com', 'password', (err) => {
            if (err) {
                return res.status(500).send('Bind error');
            }
            
            // ok: javascript-ldap-injection
            const searchOptions = {
                filter: `(|(uid=${escape(userId)})(mail=${escape(userId)}))`,
                scope: 'sub',
                attributes: ['cn', 'mail']
            };
            
            client.search('ou=people,dc=example,dc=com', searchOptions, (err, search) => {
                // Process results
                res.send('Search completed');
            });
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4() {
    const app = express();
    app.get('/group-members', (req, res) => {
        const groupName = req.query.group;
        
        // Input validation
        if (!/^[a-zA-Z0-9-_]+$/.test(groupName)) {
            return res.status(400).send('Invalid group name');
        }
        
        const client = ldap.createClient({
            url: 'ldap://ldap.internal.org:389'
        });
        
        // ok: javascript-ldap-injection
        const searchFilter = `(&(objectClass=groupOfNames)(cn=${groupName}))`;
        
        client.search('ou=groups,dc=example,dc=com', {
            filter: searchFilter,
            scope: 'one'
        }, (err, search) => {
            if (err) {
                return res.status(500).send('Error searching');
            }
            
            // Process results
            res.send('Group search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5() {
    const app = express();
    app.get('/employee', (req, res) => {
        const employeeId = req.query.id;
        const department = req.query.dept;
        
        // Validate inputs are numeric
        if (!/^\d+$/.test(employeeId) || !/^\d+$/.test(department)) {
            return res.status(400).send('Invalid input');
        }
        
        const client = ldap.createClient({
            url: 'ldap://corp-directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const filter = `(&(employeeID=${employeeId})(departmentNumber=${department}))`;
        
        client.search('ou=employees,dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Employee search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6() {
    const app = express();
    app.post('/authenticate', (req, res) => {
        const username = req.body.username;
        
        const client = ldap.createClient({
            url: 'ldap://auth.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const sanitizedUsername = escape(username);
        client.search(`ou=users,dc=example,dc=com`, {
            filter: `(uid=${sanitizedUsername})`,
            scope: 'sub'
        }, (err, search) => {
            // Process authentication
            res.send('Authentication processed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7() {
    const app = express();
    app.get('/search-by-attribute', (req, res) => {
        const attributeName = req.query.attr;
        const attributeValue = req.query.value;
        
        // Whitelist allowed attributes
        const allowedAttributes = ['cn', 'mail', 'sn', 'givenName'];
        if (!allowedAttributes.includes(attributeName)) {
            return res.status(400).send('Invalid attribute');
        }
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const searchFilter = `(${attributeName}=${escape(attributeValue)})`;
        
        client.search('dc=example,dc=com', {
            filter: searchFilter
        }, (err, search) => {
            // Process results
            res.send('Attribute search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8() {
    const app = express();
    app.get('/complex-search', (req, res) => {
        const firstName = req.query.first;
        const lastName = req.query.last;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const filter = `(&(givenName=${escape(firstName)})(sn=${escape(lastName)}))`;
        
        client.search('ou=people,dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Complex search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9() {
    const app = express();
    app.post('/search-with-headers', (req, res) => {
        const orgId = req.headers['x-organization-id'];
        
        // Validate organization ID format
        if (!/^[a-zA-Z0-9-]+$/.test(orgId)) {
            return res.status(400).send('Invalid organization ID');
        }
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        client.search('dc=example,dc=com', {
            filter: `(organizationId=${orgId})`,
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Organization search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10() {
    const app = express();
    app.get('/search-with-cookie', (req, res) => {
        const userRole = req.cookies.role;
        
        // Whitelist allowed roles
        const allowedRoles = ['admin', 'user', 'guest', 'manager'];
        if (!allowedRoles.includes(userRole)) {
            return res.status(400).send('Invalid role');
        }
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const filter = `(roleAttribute=${userRole})`;
        
        client.search('ou=roles,dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Role search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11() {
    const app = express();
    app.get('/search-with-template', (req, res) => {
        const searchTerm = req.query.q;
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const escapedTerm = escape(searchTerm);
        const filterTemplate = `(|(cn=*${escapedTerm}*)(mail=*${escapedTerm}*))`;
        
        client.search('dc=example,dc=com', {
            filter: filterTemplate
        }, (err, search) => {
            // Process results
            res.send('Template search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12() {
    const app = express();
    app.post('/modify-entry', (req, res) => {
        const dn = req.body.dn;
        
        // Validate DN format
        if (!/^[a-zA-Z0-9=,]+$/.test(dn)) {
            return res.status(400).send('Invalid DN format');
        }
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        client.bind('cn=admin,dc=example,dc=com', 'password', (err) => {
            if (err) {
                return res.status(500).send('Bind error');
            }
            
            // ok: javascript-ldap-injection
            client.search(dn, {
                filter: '(objectClass=*)',
                scope: 'base'
            }, (err, search) => {
                // Process results
                res.send('DN search completed');
            });
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13() {
    const app = express();
    app.get('/dynamic-base-dn', (req, res) => {
        const orgUnit = req.query.ou;
        
        // Whitelist allowed organizational units
        const allowedOUs = ['marketing', 'engineering', 'sales', 'support'];
        if (!allowedOUs.includes(orgUnit)) {
            return res.status(400).send('Invalid organizational unit');
        }
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        const baseDN = `ou=${orgUnit},dc=example,dc=com`;
        
        client.search(baseDN, {
            filter: '(objectClass=person)',
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Dynamic base DN search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14() {
    const app = express();
    app.get('/parameterized-search', (req, res) => {
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // Using a predefined filter with no user input
        // ok: javascript-ldap-injection
        client.search('dc=example,dc=com', {
            filter: '(&(objectClass=person)(memberOf=cn=developers,ou=groups,dc=example,dc=com))',
            scope: 'sub'
        }, (err, search) => {
            // Process results
            res.send('Parameterized search completed');
        });
    });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15() {
    const app = express();
    app.get('/search-with-prepared-filter', (req, res) => {
        const username = req.query.username;
        
        // Create a filter object instead of string concatenation
        const filter = {
            type: 'EqualityMatch',
            attribute: 'uid',
            value: username
        };
        
        const client = ldap.createClient({
            url: 'ldap://directory.example.com:389'
        });
        
        // ok: javascript-ldap-injection
        client.search('dc=example,dc=com', {
            filter: filter
        }, (err, search) => {
            // Process results
            res.send('Prepared filter search completed');
        });
    });
}
// {/fact}

module.exports = {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};