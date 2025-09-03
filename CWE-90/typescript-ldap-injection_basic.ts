import * as ldap from 'ldapjs';
import * as express from 'express';
import { Request, Response } from 'express';
import * as bodyParser from 'body-parser';
import * as url from 'url';
import * as querystring from 'querystring';
import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';

// LDAP sanitization utility
function sanitizeLdapInput(input: string): string {
  // Escape special characters in LDAP filters
  return input.replace(/[\\*\(\)]/g, (match) => '\\' + match);
}

// Utility function for LDAP filter encoding
function ldapFilterEncode(input: string): string {
  return input
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

// True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  app.get('/search', (req: Request, res: Response) => {
    const username = req.query.username as string;
    const client = ldap.createClient({ url: 'ldap://ldap.example.com' });
    
    // ruleid: typescript-ldap-injection
    const filter = `(uid=${username})`;
    
    client.search('dc=example,dc=com', { filter: filter }, (err, search) => {
      // Process search results
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: true }));
  
  app.post('/ldap-search', (req: Request, res: Response) => {
    const email = req.body.email;
    const client = ldap.createClient({ url: 'ldap://directory.example.com' });
    
    // ruleid: typescript-ldap-injection
    client.search('ou=users,dc=example,dc=com', {
      filter: `(mail=${email})`,
      scope: 'sub'
    }, (err, result) => {
      // Handle results
      res.send('Search complete');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_3() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '');
    const queryParams = querystring.parse(parsedUrl.query || '');
    const department = queryParams.dept as string;
    
    const client = ldap.createClient({ url: 'ldaps://secure.example.com' });
    
    // ruleid: typescript-ldap-injection
    const searchFilter = `(&(objectClass=person)(department=${department}))`;
    
    client.search('ou=people,dc=example,dc=com', { filter: searchFilter }, (err, search) => {
      // Process results
      res.end('Search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/user-info', (req: Request, res: Response) => {
    const userId = req.query.id as string;
    const role = req.query.role as string;
    
    const client = ldap.createClient({ url: 'ldap://ldap.internal.org' });
    
    // Concatenating multiple user inputs makes this even more vulnerable
    // ruleid: typescript-ldap-injection
    const filter = `(&(uid=${userId})(role=${role}))`;
    
    client.search('dc=internal,dc=org', { filter }, (err, search) => {
      // Process results
      res.json({ status: 'complete' });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/employee', (req: Request, res: Response) => {
    const employeeId = req.headers['x-employee-id'] as string;
    const client = ldap.createClient({ url: 'ldap://directory.company.com' });
    
    // ruleid: typescript-ldap-injection
    const searchOptions = {
      filter: `(employeeNumber=${employeeId})`,
      scope: 'sub',
      attributes: ['cn', 'mail', 'telephoneNumber']
    };
    
    client.search('ou=employees,dc=company,dc=com', searchOptions, (err, search) => {
      // Process results
      res.send('Employee search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/group-members', (req: Request, res: Response) => {
    const groupName = req.body.group;
    const client = ldap.createClient({ url: 'ldap://ad.example.com' });
    
    // ruleid: typescript-ldap-injection
    const searchFilter = `(&(objectClass=group)(cn=${groupName}))`;
    
    client.search('dc=example,dc=com', { 
      filter: searchFilter,
      scope: 'sub'
    }, (err, search) => {
      // Process results
      res.json({ complete: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_7() {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url?.startsWith('/search')) {
      const parsedUrl = url.parse(req.url);
      const query = querystring.parse(parsedUrl.query || '');
      const lastName = query.lastName as string;
      
      const client = ldap.createClient({ url: 'ldap://directory.example.org' });
      
      // ruleid: typescript-ldap-injection
      const filter = `(sn=${lastName})`;
      
      client.search('ou=people,dc=example,dc=org', { filter }, (err, search) => {
        // Process results
        res.end('Search completed');
      });
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/find-user', (req: Request, res: Response) => {
    const firstName = req.query.firstName as string;
    const lastName = req.query.lastName as string;
    
    // User input is processed but still vulnerable
    const processedFirst = firstName.trim().toLowerCase();
    const processedLast = lastName.trim().toLowerCase();
    
    const client = ldap.createClient({ url: 'ldap://ldap.example.net' });
    
    // ruleid: typescript-ldap-injection
    const filter = `(&(givenName=${processedFirst})(sn=${processedLast}))`;
    
    client.search('ou=users,dc=example,dc=net', { filter }, (err, search) => {
      // Process results
      res.send('Search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/search-directory', (req: Request, res: Response) => {
    const searchTerm = req.body.term;
    const searchField = req.body.field || 'cn'; // Default to common name
    
    const client = ldap.createClient({ url: 'ldap://directory.company.net' });
    
    // Dynamic attribute makes this even more dangerous
    // ruleid: typescript-ldap-injection
    const filter = `(${searchField}=${searchTerm})`;
    
    client.search('dc=company,dc=net', { filter }, (err, search) => {
      // Process results
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/ldap-lookup', (req: Request, res: Response) => {
    const cookie = req.headers.cookie || '';
    const cookieValue = cookie.split('user=')[1]?.split(';')[0] || '';
    
    const client = ldap.createClient({ url: 'ldap://directory.internal.com' });
    
    // Even cookie values can be manipulated by attackers
    // ruleid: typescript-ldap-injection
    const filter = `(uid=${cookieValue})`;
    
    client.search('ou=people,dc=internal,dc=com', { filter }, (err, search) => {
      // Process results
      res.send('Lookup completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/advanced-search', (req: Request, res: Response) => {
    const attributes = req.body.attributes;
    let filterString = '(&';
    
    // Building a complex filter from multiple inputs
    for (const key in attributes) {
      if (attributes.hasOwnProperty(key)) {
        // ruleid: typescript-ldap-injection
        filterString += `(${key}=${attributes[key]})`;
      }
    }
    filterString += ')';
    
    const client = ldap.createClient({ url: 'ldap://ldap.company.org' });
    client.search('dc=company,dc=org', { filter: filterString }, (err, search) => {
      // Process results
      res.json({ status: 'complete' });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/user-search', (req: Request, res: Response) => {
    const searchQuery = req.query.q as string;
    
    // Attempting to make the query "safer" by wrapping in wildcards
    // but still vulnerable to injection
    const wildcardQuery = `*${searchQuery}*`;
    
    const client = ldap.createClient({ url: 'ldap://directory.example.com' });
    
    // ruleid: typescript-ldap-injection
    const filter = `(cn=${wildcardQuery})`;
    
    client.search('ou=users,dc=example,dc=com', { filter }, (err, search) => {
      // Process results
      res.send('Search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_13() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        try {
          const data = JSON.parse(body);
          const username = data.username;
          
          const client = ldap.createClient({ url: 'ldap://ldap.internal.net' });
          
          // ruleid: typescript-ldap-injection
          const filter = `(|(uid=${username})(mail=${username}))`;
          
          client.search('dc=internal,dc=net', { filter }, (err, search) => {
            // Process results
            res.end('Search completed');
          });
        } catch (e) {
          res.end('Error processing request');
        }
      });
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/directory', (req: Request, res: Response) => {
    // Multiple parameters used in filter
    const title = req.query.title as string;
    const org = req.query.org as string;
    const location = req.query.location as string;
    
    const client = ldap.createClient({ url: 'ldap://directory.corp.com' });
    
    // ruleid: typescript-ldap-injection
    const filter = `(&(title=${title})(o=${org})(l=${location}))`;
    
    client.search('ou=people,dc=corp,dc=com', { filter }, (err, search) => {
      // Process results
      res.json({ complete: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: true }));
  
  app.post('/find-groups', (req: Request, res: Response) => {
    const memberDN = req.body.userDN;
    
    const client = ldap.createClient({ url: 'ldap://ad.example.org' });
    
    // ruleid: typescript-ldap-injection
    const filter = `(&(objectClass=group)(member=${memberDN}))`;
    
    client.search('dc=example,dc=org', { filter }, (err, search) => {
      // Process results
      res.send('Group search completed');
    });
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  app.get('/search', (req: Request, res: Response) => {
    const username = req.query.username as string;
    
    // ok: typescript-ldap-injection
    const sanitizedUsername = sanitizeLdapInput(username);
    
    const client = ldap.createClient({ url: 'ldap://ldap.example.com' });
    const filter = `(uid=${sanitizedUsername})`;
    
    client.search('dc=example,dc=com', { filter: filter }, (err, search) => {
      // Process search results
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: true }));
  
  app.post('/ldap-search', (req: Request, res: Response) => {
    const email = req.body.email;
    
    // ok: typescript-ldap-injection
    const sanitizedEmail = ldapFilterEncode(email);
    
    const client = ldap.createClient({ url: 'ldap://directory.example.com' });
    client.search('ou=users,dc=example,dc=com', {
      filter: `(mail=${sanitizedEmail})`,
      scope: 'sub'
    }, (err, result) => {
      // Handle results
      res.send('Search complete');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_3() {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url || '');
    const queryParams = querystring.parse(parsedUrl.query || '');
    const department = queryParams.dept as string;
    
    // ok: typescript-ldap-injection
    const escapedDept = department.replace(/[\\*\(\)]/g, (match) => '\\' + match);
    
    const client = ldap.createClient({ url: 'ldaps://secure.example.com' });
    const searchFilter = `(&(objectClass=person)(department=${escapedDept}))`;
    
    client.search('ou=people,dc=example,dc=com', { filter: searchFilter }, (err, search) => {
      // Process results
      res.end('Search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/user-info', (req: Request, res: Response) => {
    const userId = req.query.id as string;
    const role = req.query.role as string;
    
    // ok: typescript-ldap-injection
    const sanitizedUserId = sanitizeLdapInput(userId);
    const sanitizedRole = sanitizeLdapInput(role);
    
    const client = ldap.createClient({ url: 'ldap://ldap.internal.org' });
    const filter = `(&(uid=${sanitizedUserId})(role=${sanitizedRole}))`;
    
    client.search('dc=internal,dc=org', { filter }, (err, search) => {
      // Process results
      res.json({ status: 'complete' });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/employee', (req: Request, res: Response) => {
    const employeeId = req.headers['x-employee-id'] as string;
    
    // Validate that employee ID is numeric
    // ok: typescript-ldap-injection
    if (!/^\d+$/.test(employeeId)) {
      return res.status(400).send('Invalid employee ID');
    }
    
    const client = ldap.createClient({ url: 'ldap://directory.company.com' });
    const searchOptions = {
      filter: `(employeeNumber=${employeeId})`,
      scope: 'sub',
      attributes: ['cn', 'mail', 'telephoneNumber']
    };
    
    client.search('ou=employees,dc=company,dc=com', searchOptions, (err, search) => {
      // Process results
      res.send('Employee search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_6() {
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/group-members', (req: Request, res: Response) => {
    const groupName = req.body.group;
    
    // ok: typescript-ldap-injection
    const sanitizedGroupName = ldapFilterEncode(groupName);
    
    const client = ldap.createClient({ url: 'ldap://ad.example.com' });
    const searchFilter = `(&(objectClass=group)(cn=${sanitizedGroupName}))`;
    
    client.search('dc=example,dc=com', { 
      filter: searchFilter,
      scope: 'sub'
    }, (err, search) => {
      // Process results
      res.json({ complete: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_7() {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url?.startsWith('/search')) {
      const parsedUrl = url.parse(req.url);
      const query = querystring.parse(parsedUrl.query || '');
      const lastName = query.lastName as string;
      
      // ok: typescript-ldap-injection
      const sanitizedLastName = lastName.replace(/[\\*\(\)]/g, (match) => '\\' + match);
      
      const client = ldap.createClient({ url: 'ldap://directory.example.org' });
      const filter = `(sn=${sanitizedLastName})`;
      
      client.search('ou=people,dc=example,dc=org', { filter }, (err, search) => {
        // Process results
        res.end('Search completed');
      });
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/find-user', (req: Request, res: Response) => {
    const firstName = req.query.firstName as string;
    const lastName = req.query.lastName as string;
    
    // Process and sanitize input
    // ok: typescript-ldap-injection
    const sanitizedFirst = sanitizeLdapInput(firstName.trim().toLowerCase());
    const sanitizedLast = sanitizeLdapInput(lastName.trim().toLowerCase());
    
    const client = ldap.createClient({ url: 'ldap://ldap.example.net' });
    const filter = `(&(givenName=${sanitizedFirst})(sn=${sanitizedLast}))`;
    
    client.search('ou=users,dc=example,dc=net', { filter }, (err, search) => {
      // Process results
      res.send('Search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_9() {
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/search-directory', (req: Request, res: Response) => {
    const searchTerm = req.body.term;
    const searchField = req.body.field || 'cn'; // Default to common name
    
    // Whitelist allowed fields
    // ok: typescript-ldap-injection
    const allowedFields = ['cn', 'mail', 'sn', 'givenName'];
    if (!allowedFields.includes(searchField)) {
      return res.status(400).send('Invalid search field');
    }
    
    const sanitizedTerm = ldapFilterEncode(searchTerm);
    
    const client = ldap.createClient({ url: 'ldap://directory.company.net' });
    const filter = `(${searchField}=${sanitizedTerm})`;
    
    client.search('dc=company,dc=net', { filter }, (err, search) => {
      // Process results
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/ldap-lookup', (req: Request, res: Response) => {
    const cookie = req.headers.cookie || '';
    const cookieValue = cookie.split('user=')[1]?.split(';')[0] || '';
    
    // ok: typescript-ldap-injection
    const sanitizedCookieValue = sanitizeLdapInput(cookieValue);
    
    const client = ldap.createClient({ url: 'ldap://directory.internal.com' });
    const filter = `(uid=${sanitizedCookieValue})`;
    
    client.search('ou=people,dc=internal,dc=com', { filter }, (err, search) => {
      // Process results
      res.send('Lookup completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_11() {
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/advanced-search', (req: Request, res: Response) => {
    const attributes = req.body.attributes;
    let filterString = '(&';
    
    // Building a complex filter from multiple inputs
    // ok: typescript-ldap-injection
    for (const key in attributes) {
      if (attributes.hasOwnProperty(key)) {
        const sanitizedKey = sanitizeLdapInput(key);
        const sanitizedValue = sanitizeLdapInput(attributes[key]);
        filterString += `(${sanitizedKey}=${sanitizedValue})`;
      }
    }
    filterString += ')';
    
    const client = ldap.createClient({ url: 'ldap://ldap.company.org' });
    client.search('dc=company,dc=org', { filter: filterString }, (err, search) => {
      // Process results
      res.json({ status: 'complete' });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/user-search', (req: Request, res: Response) => {
    const searchQuery = req.query.q as string;
    
    // ok: typescript-ldap-injection
    const sanitizedQuery = ldapFilterEncode(searchQuery);
    const wildcardQuery = `*${sanitizedQuery}*`;
    
    const client = ldap.createClient({ url: 'ldap://directory.example.com' });
    const filter = `(cn=${wildcardQuery})`;
    
    client.search('ou=users,dc=example,dc=com', { filter }, (err, search) => {
      // Process results
      res.send('Search completed');
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_13() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        try {
          const data = JSON.parse(body);
          const username = data.username;
          
          // ok: typescript-ldap-injection
          const sanitizedUsername = username.replace(/[\\*\(\)]/g, (match) => '\\' + match);
          
          const client = ldap.createClient({ url: 'ldap://ldap.internal.net' });
          const filter = `(|(uid=${sanitizedUsername})(mail=${sanitizedUsername}))`;
          
          client.search('dc=internal,dc=net', { filter }, (err, search) => {
            // Process results
            res.end('Search completed');
          });
        } catch (e) {
          res.end('Error processing request');
        }
      });
    }
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/directory', (req: Request, res: Response) => {
    // Multiple parameters used in filter
    const title = req.query.title as string;
    const org = req.query.org as string;
    const location = req.query.location as string;
    
    // ok: typescript-ldap-injection
    const sanitizedTitle = sanitizeLdapInput(title);
    const sanitizedOrg = sanitizeLdapInput(org);
    const sanitizedLocation = sanitizeLdapInput(location);
    
    const client = ldap.createClient({ url: 'ldap://directory.corp.com' });
    const filter = `(&(title=${sanitizedTitle})(o=${sanitizedOrg})(l=${sanitizedLocation}))`;
    
    client.search('ou=people,dc=corp,dc=com', { filter }, (err, search) => {
      // Process results
      res.json({ complete: true });
    });
  });
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
function good_case_15() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: true }));
  
  app.post('/find-groups', (req: Request, res: Response) => {
    const memberDN = req.body.userDN;
    
    // ok: typescript-ldap-injection
    const sanitizedMemberDN = ldapFilterEncode(memberDN);
    
    const client = ldap.createClient({ url: 'ldap://ad.example.org' });
    const filter = `(&(objectClass=group)(member=${sanitizedMemberDN}))`;
    
    client.search('dc=example,dc=org', { filter }, (err, search) => {
      // Process results
      res.send('Group search completed');
    });
  });
}
// {/fact}