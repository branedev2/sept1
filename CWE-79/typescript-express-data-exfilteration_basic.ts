import express from 'express';
import bodyParser from 'body-parser';
import { Request, Response } from 'express';

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// Example 1: Direct assignment of query parameter to Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userInput = req.query.userInput;
    const defaultConfig = { theme: 'light', fontSize: 12 };
    
    // ruleid: typescript-express-data-exfilteration
    const config = Object.assign({}, defaultConfig, { userValue: userInput });
    
    res.render('profile', { config });
}
// {/fact}

// Example 2: Using request body in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userData = req.body;
    const defaultUser = { role: 'user', permissions: [] };
    
    // ruleid: typescript-express-data-exfilteration
    const user = Object.assign({}, defaultUser, userData);
    
    res.json(user);
}
// {/fact}

// Example 3: Using request parameters in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const userId = req.params.id;
    const defaultSettings = { visible: true, editable: false };
    
    // ruleid: typescript-express-data-exfilteration
    const settings = Object.assign({}, defaultSettings, { owner: userId });
    
    res.render('settings', { settings });
}
// {/fact}

// Example 4: Using request headers in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'];
    const clientInfo = { timestamp: Date.now() };
    
    // ruleid: typescript-express-data-exfilteration
    const analytics = Object.assign({}, clientInfo, { agent: userAgent });
    
    res.json(analytics);
}
// {/fact}

// Example 5: Using cookies in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const theme = req.cookies.theme;
    const defaultTheme = { primary: 'blue', secondary: 'white' };
    
    // ruleid: typescript-express-data-exfilteration
    const userTheme = Object.assign({}, defaultTheme, { selected: theme });
    
    res.render('dashboard', { theme: userTheme });
}
// {/fact}

// Example 6: Using multiple request inputs in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const name = req.query.name;
    const role = req.body.role;
    
    // ruleid: typescript-express-data-exfilteration
    const userProfile = Object.assign({}, { name, role });
    
    res.json(userProfile);
}
// {/fact}

// Example 7: Using request input after some processing
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    let username = req.query.username as string;
    username = username ? username.toLowerCase() : 'guest';
    const defaultUser = { isLoggedIn: false };
    
    // ruleid: typescript-express-data-exfilteration
    const user = Object.assign({}, defaultUser, { username });
    
    res.render('welcome', { user });
}
// {/fact}

// Example 8: Using request input in nested Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const comment = req.body.comment;
    const metadata = { timestamp: Date.now() };
    
    const defaultComment = { approved: false };
    // ruleid: typescript-express-data-exfilteration
    const commentObj = Object.assign({}, defaultComment, { 
        content: comment,
        meta: Object.assign({}, metadata)
    });
    
    res.json(commentObj);
}
// {/fact}

// Example 9: Using request input in Object.assign inside a conditional
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const searchTerm = req.query.q;
    const defaultSearch = { filters: [], page: 1 };
    
    let searchConfig;
    if (searchTerm) {
        // ruleid: typescript-express-data-exfilteration
        searchConfig = Object.assign({}, defaultSearch, { term: searchTerm });
    } else {
        searchConfig = defaultSearch;
    }
    
    res.render('search', { searchConfig });
}
// {/fact}

// Example 10: Using request input in Object.assign inside a loop
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const tags = req.query.tags as string[];
    const defaultTags = ['general', 'public'];
    
    const allTags = [];
    for (const tag of tags || []) {
        // ruleid: typescript-express-data-exfilteration
        const tagObj = Object.assign({}, { name: tag, selected: true });
        allTags.push(tagObj);
    }
    
    res.render('tags', { tags: allTags });
}
// {/fact}

// Example 11: Using request input in Object.assign with destructuring
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const { title, content } = req.body;
    const defaultPost = { published: false, createdAt: new Date() };
    
    // ruleid: typescript-express-data-exfilteration
    const post = Object.assign({}, defaultPost, { title, content });
    
    res.json(post);
}
// {/fact}

// Example 12: Using request input in Object.assign with array methods
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const interests = req.body.interests as string[];
    const defaultProfile = { showInterests: true };
    
    if (Array.isArray(interests)) {
        const processedInterests = interests.map(i => i.trim().toLowerCase());
        // ruleid: typescript-express-data-exfilteration
        const profile = Object.assign({}, defaultProfile, { interests: processedInterests });
        res.json(profile);
    } else {
        res.status(400).send('Invalid interests format');
    }
}
// {/fact}

// Example 13: Using request input in Object.assign with try/catch
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    try {
        const settings = JSON.parse(req.body.settings as string);
        const defaultSettings = { darkMode: false };
        
        // ruleid: typescript-express-data-exfilteration
        const userSettings = Object.assign({}, defaultSettings, settings);
        
        res.json(userSettings);
    } catch (error) {
        res.status(400).send('Invalid settings format');
    }
}
// {/fact}

// Example 14: Using request input in Object.assign with Promise
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const userId = req.params.id;
    
    Promise.resolve({ id: userId })
        .then(user => {
            const defaultPermissions = { read: true, write: false };
            // ruleid: typescript-express-data-exfilteration
            const userWithPermissions = Object.assign({}, user, { permissions: defaultPermissions });
            res.json(userWithPermissions);
        })
        .catch(error => {
            res.status(500).send('Error processing user');
        });
}
// {/fact}

// Example 15: Using request input in Object.assign with async/await
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_15(req: Request, res: Response) {
    try {
        const email = req.body.email;
        const defaultContact = { verified: false };
        
        // Simulate async operation
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // ruleid: typescript-express-data-exfilteration
        const contact = Object.assign({}, defaultContact, { email });
        
        res.json(contact);
    } catch (error) {
        res.status(500).send('Error processing contact');
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using hardcoded values in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    // ok: typescript-express-data-exfilteration
    const config = Object.assign({}, { theme: 'dark', fontSize: 14 });
    
    res.render('profile', { config });
}
// {/fact}

// Example 2: Sanitizing user input before Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const userInput = req.query.userInput as string;
    const sanitizedInput = userInput ? userInput.replace(/[<>]/g, '') : '';
    const defaultConfig = { theme: 'light', fontSize: 12 };
    
    // ok: typescript-express-data-exfilteration
    const config = Object.assign({}, defaultConfig, { userValue: sanitizedInput });
    
    res.render('profile', { config });
}
// {/fact}

// Example 3: Using validated user input in Object.assign
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const theme = req.query.theme as string;
    const validThemes = ['light', 'dark', 'blue'];
    const safeTheme = validThemes.includes(theme) ? theme : 'light';
    
    // ok: typescript-express-data-exfilteration
    const config = Object.assign({}, { theme: safeTheme, fontSize: 12 });
    
    res.render('profile', { config });
}
// {/fact}

// Example 4: Using Object.assign without user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const defaultSettings = { notifications: true, sound: false };
    const overrides = { sound: true };
    
    // ok: typescript-express-data-exfilteration
    const settings = Object.assign({}, defaultSettings, overrides);
    
    res.json(settings);
}
// {/fact}

// Example 5: Using Object.assign with server-side data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const userId = 123; // Server-side generated ID
    const timestamp = Date.now();
    
    // ok: typescript-express-data-exfilteration
    const metadata = Object.assign({}, { userId, timestamp });
    
    res.json({ metadata });
}
// {/fact}

// Example 6: Using Object.assign with environment variables
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const apiVersion = process.env.API_VERSION || '1.0';
    const defaultConfig = { debug: false };
    
    // ok: typescript-express-data-exfilteration
    const config = Object.assign({}, defaultConfig, { version: apiVersion });
    
    res.json(config);
}
// {/fact}

// Example 7: Using Object.assign with constants
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const DEFAULT_THEME = 'light';
    const DEFAULT_FONT_SIZE = 14;
    
    // ok: typescript-express-data-exfilteration
    const config = Object.assign({}, { theme: DEFAULT_THEME, fontSize: DEFAULT_FONT_SIZE });
    
    res.render('settings', { config });
}
// {/fact}

// Example 8: Using Object.assign with computed properties
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth() + 1;
    
    // ok: typescript-express-data-exfilteration
    const dateInfo = Object.assign({}, { year, month, day: now.getDate() });
    
    res.json(dateInfo);
}
// {/fact}

// Example 9: Using Object.assign with function results
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    function getDefaultSettings() {
        return { darkMode: false, fontSize: 14 };
    }
    
    // ok: typescript-express-data-exfilteration
    const settings = Object.assign({}, getDefaultSettings());
    
    res.json(settings);
}
// {/fact}

// Example 10: Using Object.assign with typed data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    interface Theme {
        primary: string;
        secondary: string;
    }
    
    const defaultTheme: Theme = { primary: 'blue', secondary: 'white' };
    const darkTheme: Theme = { primary: 'black', secondary: 'gray' };
    
    // ok: typescript-express-data-exfilteration
    const theme = Object.assign({}, defaultTheme, darkTheme);
    
    res.render('theme', { theme });
}
// {/fact}

// Example 11: Using Object.assign with database results
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    // Simulating database result
    const dbUser = { id: 123, name: 'John Doe', role: 'user' };
    const defaultPermissions = { read: true, write: false };
    
    // ok: typescript-express-data-exfilteration
    const user = Object.assign({}, dbUser, { permissions: defaultPermissions });
    
    res.json(user);
}
// {/fact}

// Example 12: Using Object.assign with system information
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const serverInfo = {
        platform: process.platform,
        nodeVersion: process.version,
        uptime: process.uptime()
    };
    
    // ok: typescript-express-data-exfilteration
    const info = Object.assign({}, serverInfo, { timestamp: Date.now() });
    
    res.json(info);
}
// {/fact}

// Example 13: Using Object.assign with configuration objects
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const appConfig = {
        name: 'My App',
        version: '1.0.0'
    };
    
    const runtimeConfig = {
        environment: process.env.NODE_ENV || 'development',
        debug: process.env.NODE_ENV !== 'production'
    };
    
    // ok: typescript-express-data-exfilteration
    const config = Object.assign({}, appConfig, runtimeConfig);
    
    res.json(config);
}
// {/fact}

// Example 14: Using Object.assign with validated numeric input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const pageStr = req.query.page as string;
    const page = /^\d+$/.test(pageStr) ? parseInt(pageStr, 10) : 1;
    
    // ok: typescript-express-data-exfilteration
    const pagination = Object.assign({}, { page, limit: 10 });
    
    res.json(pagination);
}
// {/fact}

// Example 15: Using Object.assign with whitelisted properties
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const userData = req.body;
    const safeUserData: Record<string, any> = {};
    
    // Whitelist approach
    const allowedFields = ['name', 'email', 'age'];
    allowedFields.forEach(field => {
        if (userData[field] !== undefined) {
            safeUserData[field] = userData[field];
        }
    });
    
    // Validate age is a number
    if (safeUserData.age !== undefined) {
        safeUserData.age = parseInt(safeUserData.age, 10) || 0;
    }
    
    // ok: typescript-express-data-exfilteration
    const user = Object.assign({}, { role: 'user' }, safeUserData);
    
    res.json(user);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});