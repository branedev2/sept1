const express = require('express');
const app = express();
app.use(express.json());

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    app.post('/update-user', (req, res) => {
        const user = { id: 1, name: 'John', role: 'user' };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(user, req.body);
        // Now user.role could be overwritten to 'admin'
        res.json(user);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    app.put('/api/profile', (req, res) => {
        const userProfile = { id: req.user.id, email: req.user.email, permissions: ['read'] };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(userProfile, req.body);
        // Attacker could add 'admin' to permissions
        saveUserProfile(userProfile);
        res.send({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    app.post('/create-product', (req, res) => {
        const product = { createdBy: req.user.id, approved: false };
        // ruleid: javascript-express-data-exfilteration
        const updatedProduct = Object.assign(product, req.body);
        // Attacker could set approved: true
        saveProduct(updatedProduct);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    app.patch('/settings', (req, res) => {
        let userSettings = getUserSettings(req.user.id);
        // ruleid: javascript-express-data-exfilteration
        Object.assign(userSettings, req.body);
        // Could overwrite restricted settings
        updateUserSettings(userSettings);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    app.post('/register', (req, res) => {
        const newUser = { role: 'user', verified: false };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(newUser, req.body);
        // Attacker could set role: 'admin', verified: true
        createUser(newUser);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    app.put('/api/documents/:id', (req, res) => {
        const doc = getDocument(req.params.id);
        // ruleid: javascript-express-data-exfilteration
        const updatedDoc = Object.assign(doc, req.body);
        // Could overwrite ownership or permissions
        saveDocument(updatedDoc);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    app.post('/payment-settings', (req, res) => {
        const paymentConfig = { verified: false, limits: { daily: 100 } };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(paymentConfig, JSON.parse(req.body.config));
        // Attacker could modify limits or verification status
        updatePaymentConfig(req.user.id, paymentConfig);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    app.post('/api/orders', (req, res) => {
        const order = { status: 'pending', discount: 0 };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(order, req.body);
        // Could set arbitrary discount or change status
        createOrder(order);
        res.json(order);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    app.post('/create-invoice', (req, res) => {
        const invoice = { 
            createdAt: new Date(),
            paid: false,
            approved: false
        };
        // ruleid: javascript-express-data-exfilteration
        const result = Object.assign(invoice, req.body);
        // Could mark invoice as paid or approved
        saveInvoice(result);
        res.json({ id: result.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    app.put('/api/user-preferences', (req, res) => {
        const preferences = loadUserPreferences(req.user.id);
        // ruleid: javascript-express-data-exfilteration
        Object.assign(preferences, req.body.preferences);
        // Could overwrite system preferences
        saveUserPreferences(req.user.id, preferences);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    app.post('/api/comments', (req, res) => {
        const comment = { 
            authorId: req.user.id,
            timestamp: Date.now(),
            approved: false
        };
        // ruleid: javascript-express-data-exfilteration
        const newComment = Object.assign(comment, req.body);
        // Could override authorId or approval status
        saveComment(newComment);
        res.json({ success: true, id: newComment.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    app.post('/api/create-team', (req, res) => {
        let team = {
            createdBy: req.user.id,
            adminUsers: [req.user.id],
            createdAt: new Date()
        };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(team, req.body);
        // Could add users to adminUsers array
        createTeam(team);
        res.json({ teamId: team.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    app.put('/api/update-subscription', (req, res) => {
        const subscription = getUserSubscription(req.user.id);
        // ruleid: javascript-express-data-exfilteration
        Object.assign(subscription, req.body);
        // Could upgrade plan without payment
        updateSubscription(subscription);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    app.post('/api/create-listing', (req, res) => {
        const listing = {
            sellerId: req.user.id,
            status: 'pending',
            featured: false
        };
        // ruleid: javascript-express-data-exfilteration
        const newListing = Object.assign(listing, req.body);
        // Could set featured: true or change status
        saveListing(newListing);
        res.json({ id: newListing.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    app.post('/api/submit-review', (req, res) => {
        const review = {
            reviewerId: req.user.id,
            verified: false,
            date: new Date()
        };
        // ruleid: javascript-express-data-exfilteration
        Object.assign(review, req.body);
        // Could mark review as verified
        saveReview(review);
        res.json({ success: true });
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    app.post('/update-user', (req, res) => {
        const user = { id: 1, name: 'John', role: 'user' };
        // ok: javascript-express-data-exfilteration
        user.name = req.body.name; // Only update specific properties
        user.email = req.body.email;
        res.json(user);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    app.put('/api/profile', (req, res) => {
        const userProfile = { id: req.user.id, email: req.user.email, permissions: ['read'] };
        // ok: javascript-express-data-exfilteration
        const allowedFields = ['name', 'avatar', 'bio'];
        const updates = {};
        allowedFields.forEach(field => {
            if (req.body[field] !== undefined) {
                updates[field] = req.body[field];
            }
        });
        Object.assign(userProfile, updates);
        saveUserProfile(userProfile);
        res.send({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    app.post('/create-product', (req, res) => {
        const product = { createdBy: req.user.id, approved: false };
        // ok: javascript-express-data-exfilteration
        product.name = req.body.name;
        product.price = req.body.price;
        product.description = req.body.description;
        // Approved status cannot be overwritten
        saveProduct(product);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    app.patch('/settings', (req, res) => {
        let userSettings = getUserSettings(req.user.id);
        // ok: javascript-express-data-exfilteration
        const safeSettings = {
            theme: req.body.theme,
            notifications: req.body.notifications,
            language: req.body.language
        };
        Object.assign(userSettings, safeSettings);
        updateUserSettings(userSettings);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    app.post('/register', (req, res) => {
        // ok: javascript-express-data-exfilteration
        const newUser = {
            role: 'user', // Fixed role
            verified: false, // Fixed verification status
            username: req.body.username,
            email: req.body.email,
            password: hashPassword(req.body.password)
        };
        createUser(newUser);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    app.put('/api/documents/:id', (req, res) => {
        const doc = getDocument(req.params.id);
        // ok: javascript-express-data-exfilteration
        if (doc.ownerId === req.user.id) {
            doc.title = req.body.title;
            doc.content = req.body.content;
            doc.tags = req.body.tags;
            // Ownership and permissions remain unchanged
            saveDocument(doc);
            res.json({ updated: true });
        } else {
            res.status(403).json({ error: 'Unauthorized' });
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    app.post('/payment-settings', (req, res) => {
        const paymentConfig = { verified: false, limits: { daily: 100 } };
        // ok: javascript-express-data-exfilteration
        if (req.body.cardNumber) {
            paymentConfig.cardNumber = req.body.cardNumber;
        }
        if (req.body.expiryDate) {
            paymentConfig.expiryDate = req.body.expiryDate;
        }
        // Verification and limits controlled by server
        updatePaymentConfig(req.user.id, paymentConfig);
        res.json({ success: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    app.post('/api/orders', (req, res) => {
        // ok: javascript-express-data-exfilteration
        const order = {
            status: 'pending', // Fixed status
            discount: 0, // Fixed discount
            items: req.body.items,
            shippingAddress: req.body.shippingAddress,
            userId: req.user.id
        };
        createOrder(order);
        res.json(order);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    app.post('/create-invoice', (req, res) => {
        // ok: javascript-express-data-exfilteration
        const invoice = {
            createdAt: new Date(),
            paid: false,
            approved: false,
            amount: parseFloat(req.body.amount),
            description: req.body.description,
            clientId: req.body.clientId
        };
        // Critical fields are set by server
        saveInvoice(invoice);
        res.json({ id: invoice.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    app.put('/api/user-preferences', (req, res) => {
        const preferences = loadUserPreferences(req.user.id);
        // ok: javascript-express-data-exfilteration
        const whitelistedPrefs = ['theme', 'fontSize', 'notifications'];
        whitelistedPrefs.forEach(pref => {
            if (req.body[pref] !== undefined) {
                preferences[pref] = req.body[pref];
            }
        });
        // System preferences remain unchanged
        saveUserPreferences(req.user.id, preferences);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    app.post('/api/comments', (req, res) => {
        // ok: javascript-express-data-exfilteration
        const comment = {
            authorId: req.user.id, // Fixed author
            timestamp: Date.now(), // Fixed timestamp
            approved: false, // Fixed approval status
            content: req.body.content,
            postId: req.body.postId
        };
        saveComment(comment);
        res.json({ success: true, id: comment.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    app.post('/api/create-team', (req, res) => {
        // ok: javascript-express-data-exfilteration
        let team = {
            createdBy: req.user.id,
            adminUsers: [req.user.id],
            createdAt: new Date(),
            name: req.body.name,
            description: req.body.description,
            members: req.body.members || []
        };
        // Admin users controlled by server
        createTeam(team);
        res.json({ teamId: team.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    app.put('/api/update-subscription', (req, res) => {
        const subscription = getUserSubscription(req.user.id);
        // ok: javascript-express-data-exfilteration
        if (req.body.plan && isValidPlan(req.body.plan)) {
            // Validate plan change and possibly charge user
            if (canUpgradeToPlan(req.user.id, req.body.plan)) {
                subscription.plan = req.body.plan;
            }
        }
        // Other subscription details controlled by server
        updateSubscription(subscription);
        res.json({ updated: true });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    app.post('/api/create-listing', (req, res) => {
        // ok: javascript-express-data-exfilteration
        const listing = {
            sellerId: req.user.id, // Fixed seller
            status: 'pending', // Fixed status
            featured: false, // Fixed featured flag
            title: req.body.title,
            description: req.body.description,
            price: parseFloat(req.body.price),
            category: req.body.category
        };
        saveListing(listing);
        res.json({ id: listing.id });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    app.post('/api/submit-review', (req, res) => {
        // ok: javascript-express-data-exfilteration
        const review = {
            reviewerId: req.user.id, // Fixed reviewer
            verified: false, // Fixed verification
            date: new Date(), // Fixed date
            rating: parseInt(req.body.rating, 10),
            comment: req.body.comment,
            productId: req.body.productId
        };
        saveReview(review);
        res.json({ success: true });
    });
}
// {/fact}

// Helper functions to make the examples work
function saveUserProfile(profile) {}
function saveProduct(product) {}
function getUserSettings(userId) { return {}; }
function updateUserSettings(settings) {}
function createUser(user) {}
function getDocument(id) { return { ownerId: 1 }; }
function saveDocument(doc) {}
function updatePaymentConfig(userId, config) {}
function createOrder(order) {}
function saveInvoice(invoice) {}
function loadUserPreferences(userId) { return {}; }
function saveUserPreferences(userId, prefs) {}
function saveComment(comment) {}
function createTeam(team) {}
function getUserSubscription(userId) { return {}; }
function updateSubscription(subscription) {}
function saveListing(listing) {}
function saveReview(review) {}
function hashPassword(password) { return 'hashed'; }
function isValidPlan(plan) { return true; }
function canUpgradeToPlan(userId, plan) { return true; }