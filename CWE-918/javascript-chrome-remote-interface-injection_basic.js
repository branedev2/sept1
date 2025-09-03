// Test cases for chrome-remote-interface-injection rule
const CDP = require('chrome-remote-interface');
const express = require('express');
const app = express();
const url = require('url');
const validator = require('validator');
const ipRangeCheck = require('ip-range-check');
const bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Directly using user input in CDP constructor
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req, res) {
    const userInput = req.query.target;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP({ target: userInput });
        const { Page } = client;
        await Page.enable();
        const result = await Page.navigate({ url: 'https://example.com' });
        res.json(result);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 2: Using user input in host parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req, res) {
    const userHost = req.query.host;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: userHost, port: 9222 });
        const { Network } = client;
        await Network.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 3: Using user input in port parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req, res) {
    const userPort = req.query.port;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: 'localhost', port: parseInt(userPort) });
        const { Runtime } = client;
        await Runtime.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 4: Using user input in both host and port
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req, res) {
    const userHost = req.body.host;
    const userPort = req.body.port;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: userHost, port: parseInt(userPort) });
        const { DOM } = client;
        await DOM.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 5: Using user input in CDP.New()
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req, res) {
    const userUrl = req.query.url;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const target = await CDP.New({ url: userUrl });
        const client = await CDP({ target });
        res.json({ success: true, targetId: target.targetId });
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 6: Using user input in CDP.Activate()
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req, res) {
    const targetId = req.query.targetId;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        await CDP.Activate({ id: targetId });
        res.json({ success: true });
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 7: Using user input in CDP.Close()
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req, res) {
    const targetId = req.headers['x-target-id'];
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        await CDP.Close({ id: targetId });
        res.json({ success: true });
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 8: Using user input in CDP.List() with host parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req, res) {
    const userHost = req.cookies.host;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const targets = await CDP.List({ host: userHost });
        res.json(targets);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 9: Using user input in CDP.Version() with port parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req, res) {
    const userPort = req.query.port;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const version = await CDP.Version({ port: parseInt(userPort) });
        res.json(version);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 10: Using user input in CDP constructor with complex object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req, res) {
    const config = {
        host: req.query.host || 'localhost',
        port: req.query.port ? parseInt(req.query.port) : 9222,
        target: req.query.target
    };
    
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP(config);
        const { Page } = client;
        await Page.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 11: Using user input in CDP.Protocol() with host parameter
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req, res) {
    const userHost = req.query.host;
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const protocol = await CDP.Protocol({ host: userHost });
        res.json(protocol);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 12: Using user input in CDP with variable assignment
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req, res) {
    const userInput = req.query.target;
    const options = { target: userInput };
    
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP(options);
        const { Network } = client;
        await Network.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 13: Using user input in CDP with conditional assignment
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req, res) {
    let options = {};
    
    if (req.query.target) {
        options.target = req.query.target;
    } else {
        options.host = 'localhost';
        options.port = 9222;
    }
    
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP(options);
        const { Page } = client;
        await Page.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 14: Using user input in CDP with template literals
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req, res) {
    const userHost = req.query.host;
    const options = { host: `${userHost}` };
    
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP(options);
        const { Runtime } = client;
        await Runtime.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 15: Using user input in CDP with object destructuring
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req, res) {
    const { host, port, target } = req.body;
    
    try {
        // ruleid: javascript-chrome-remote-interface-injection
        const client = await CDP({ host, port: parseInt(port), target });
        const { DOM } = client;
        await DOM.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using hardcoded values in CDP constructor
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req, res) {
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: 'localhost', port: 9222 });
        const { Page } = client;
        await Page.enable();
        const result = await Page.navigate({ url: 'https://example.com' });
        res.json(result);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 2: Validating host parameter before use
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req, res) {
    const userHost = req.query.host;
    
    // Validate that host is localhost or 127.0.0.1
    if (userHost !== 'localhost' && userHost !== '127.0.0.1') {
        return res.status(400).send('Invalid host');
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: userHost, port: 9222 });
        const { Network } = client;
        await Network.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 3: Validating port parameter before use
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req, res) {
    const userPort = req.query.port;
    const portNum = parseInt(userPort);
    
    // Validate port is a number and within allowed range
    if (isNaN(portNum) || portNum < 9000 || portNum > 9500) {
        return res.status(400).send('Invalid port');
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: 'localhost', port: portNum });
        const { Runtime } = client;
        await Runtime.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 4: Using environment variables instead of user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req, res) {
    const host = process.env.CHROME_HOST || 'localhost';
    const port = parseInt(process.env.CHROME_PORT || '9222');
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP({ host, port });
        const { DOM } = client;
        await DOM.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 5: Using a whitelist for target parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req, res) {
    const userTarget = req.query.target;
    const allowedTargets = ['page-1', 'page-2', 'browser'];
    
    if (!allowedTargets.includes(userTarget)) {
        return res.status(400).send('Invalid target');
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP({ target: userTarget });
        const { Page } = client;
        await Page.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 6: Using a configuration object with validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req, res) {
    const config = {
        host: 'localhost',
        port: 9222
    };
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP(config);
        const { Network } = client;
        await Network.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 7: Validating URL format before using in CDP.New()
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req, res) {
    const userUrl = req.query.url;
    
    if (!validator.isURL(userUrl, { protocols: ['http', 'https'], require_protocol: true })) {
        return res.status(400).send('Invalid URL');
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const target = await CDP.New({ url: userUrl });
        const client = await CDP({ target });
        res.json({ success: true, targetId: target.targetId });
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 8: Validating target ID format before using in CDP.Activate()
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req, res) {
    const targetId = req.query.targetId;
    
    // Validate target ID format (example: simple format validation)
    if (!/^[a-f0-9-]+$/i.test(targetId)) {
        return res.status(400).send('Invalid target ID format');
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        await CDP.Activate({ id: targetId });
        res.json({ success: true });
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 9: Using a secure configuration pattern
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req, res) {
    const chromeConfig = {
        host: 'localhost',
        port: 9222
    };
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const version = await CDP.Version(chromeConfig);
        res.json(version);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 10: Validating IP address before use
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req, res) {
    const userHost = req.query.host;
    
    // Check if IP is in private range
    if (!ipRangeCheck(userHost, ['127.0.0.1/32', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])) {
        return res.status(400).send('Only private IP addresses are allowed');
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP({ host: userHost, port: 9222 });
        const { Page } = client;
        await Page.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 11: Using a configuration factory with validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req, res) {
    function createSecureConfig() {
        return {
            host: 'localhost',
            port: 9222
        };
    }
    
    try {
        const config = createSecureConfig();
        // ok: javascript-chrome-remote-interface-injection
        const protocol = await CDP.Protocol(config);
        res.json(protocol);
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 12: Using a secure default with optional override from environment
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req, res) {
    const options = {
        host: process.env.CHROME_HOST || 'localhost',
        port: parseInt(process.env.CHROME_PORT || '9222')
    };
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP(options);
        const { Network } = client;
        await Network.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Example 13: Using a validation function before connecting
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req, res) {
    const userHost = req.query.host;
    const userPort = req.query.port;
    
    function validateConnection(host, port) {
        if (host !== 'localhost' && host !== '127.0.0.1') {
            throw new Error('Invalid host');
        }
        
        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 9000 || portNum > 9500) {
            throw new Error('Invalid port');
        }
        
        return { host, port: portNum };
    }
    
    try {
        const validConfig = validateConnection(userHost, userPort);
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP(validConfig);
        const { Page } = client;
        await Page.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(400).send(err.toString());
    }
}
// {/fact}

// Example 14: Using URL parsing and validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req, res) {
    const userUrl = req.query.url;
    
    try {
        // Parse and validate URL
        const parsedUrl = new URL(userUrl);
        
        // Only allow specific domains
        if (parsedUrl.hostname !== 'example.com' && parsedUrl.hostname !== 'test.example.com') {
            return res.status(400).send('Domain not allowed');
        }
        
        // ok: javascript-chrome-remote-interface-injection
        const target = await CDP.New({ url: parsedUrl.href });
        const client = await CDP({ target });
        res.json({ success: true, targetId: target.targetId });
    } catch (err) {
        res.status(400).send('Invalid URL');
    }
}
// {/fact}

// Example 15: Using a secure configuration object with validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req, res) {
    const userHost = req.query.host;
    const userPort = req.query.port;
    
    // Default secure configuration
    const config = {
        host: 'localhost',
        port: 9222
    };
    
    // Only update if values are valid
    if (userHost === 'localhost' || userHost === '127.0.0.1') {
        config.host = userHost;
    }
    
    const portNum = parseInt(userPort);
    if (!isNaN(portNum) && portNum >= 9000 && portNum <= 9500) {
        config.port = portNum;
    }
    
    try {
        // ok: javascript-chrome-remote-interface-injection
        const client = await CDP(config);
        const { DOM } = client;
        await DOM.enable();
        res.send('Connected to Chrome');
    } catch (err) {
        res.status(500).send(err.toString());
    }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});