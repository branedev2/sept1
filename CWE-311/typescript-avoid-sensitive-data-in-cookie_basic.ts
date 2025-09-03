// File: cookie_security_examples.ts

import * as express from 'express';
import * as crypto from 'crypto';
import * as cookieParser from 'cookie-parser';
import { Request, Response } from 'express';
import { CookieOptions } from 'express';
import * as jwt from 'jsonwebtoken';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userSSN = req.body.ssn;
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('userSSN', userSSN, { maxAge: 900000 });
    res.send('SSN stored in cookie');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const creditCardNumber = req.body.ccNumber;
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('paymentInfo', creditCardNumber, { httpOnly: true });
    res.send('Credit card info stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const password = req.body.password;
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('userPassword', password);
    res.redirect('/dashboard');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const apiKey = 'sk_live_1234567890abcdef';
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('apiCredentials', apiKey, { secure: true });
    res.json({ status: 'API key stored in cookie' });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const userData = {
        name: req.body.name,
        email: req.body.email,
        ssn: req.body.ssn,
        dob: req.body.dob
    };
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('userProfile', JSON.stringify(userData));
    res.send('Profile saved');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const app = express();
    app.use(cookieParser());
    
    const healthData = {
        bloodType: req.body.bloodType,
        medicalConditions: req.body.conditions,
        medications: req.body.medications
    };
    
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('healthRecord', JSON.stringify(healthData), { maxAge: 3600000 });
    res.send('Health data stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const bankAccountDetails = {
        accountNumber: req.body.accountNumber,
        routingNumber: req.body.routingNumber,
        bankName: req.body.bankName
    };
    
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('bankInfo', JSON.stringify(bankAccountDetails), { httpOnly: true, secure: true });
    res.send('Bank details saved');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const passportNumber = req.body.passportNumber;
    const cookieOptions: CookieOptions = {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true
    };
    
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('passport', passportNumber, cookieOptions);
    res.send('Passport information stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    if (req.body.rememberMe) {
        // ruleid: typescript-avoid-sensitive-data-in-cookie
        res.cookie('credentials', {
            username: req.body.username,
            password: req.body.password
        });
    }
    res.redirect('/home');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const userPrivateKey = req.body.privateKey;
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('cryptoKey', userPrivateKey);
    res.send('Private key stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const app = express();
    app.use(cookieParser());
    
    const twoFactorSecret = req.body.twoFactorSecret;
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('2faSecret', twoFactorSecret, { httpOnly: true });
    res.send('2FA secret stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const personalInfo = {
        fullName: req.body.name,
        address: req.body.address,
        phoneNumber: req.body.phone,
        taxId: req.body.taxId
    };
    
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('personalData', JSON.stringify(personalInfo));
    res.send('Personal information saved');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const recoveryAnswers = {
        mothersMaidenName: req.body.maidenName,
        firstPetName: req.body.petName,
        elementarySchool: req.body.schoolName
    };
    
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('securityAnswers', JSON.stringify(recoveryAnswers));
    res.send('Security answers saved');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const biometricData = req.body.fingerprintHash;
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('biometricId', biometricData, { secure: true, httpOnly: true });
    res.send('Biometric data stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const employeeData = {
        id: req.body.employeeId,
        salary: req.body.salary,
        position: req.body.position,
        performanceRating: req.body.rating
    };
    
    // ruleid: typescript-avoid-sensitive-data-in-cookie
    res.cookie('employeeInfo', JSON.stringify(employeeData));
    res.send('Employee data saved');
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userSSN = req.body.ssn;
    const encryptedSSN = crypto.publicEncrypt(
        {
            key: process.env.PUBLIC_KEY as string,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        Buffer.from(userSSN)
    ).toString('base64');
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('encryptedUserData', encryptedSSN, { httpOnly: true, secure: true });
    res.send('Encrypted SSN stored in cookie');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const creditCardNumber = req.body.ccNumber;
    // Instead of storing sensitive data in a cookie, store it server-side
    // and only put a reference in the cookie
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    // Store in server-side session storage (not shown)
    // storeInSession(sessionId, creditCardNumber);
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('sessionId', sessionId, { httpOnly: true, secure: true });
    res.send('Session created with secure storage');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const password = req.body.password;
    // Don't store password in cookie at all
    // Instead, use a session token after authentication
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('sessionToken', generateSessionToken(), { httpOnly: true, secure: true });
    res.redirect('/dashboard');
}
// {/fact}

function generateSessionToken(): string {
    return crypto.randomBytes(32).toString('hex');
}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const apiKey = 'sk_live_1234567890abcdef';
    // Store API key server-side and use a non-sensitive identifier
    const keyId = 'api_key_reference_' + crypto.randomBytes(8).toString('hex');
    
    // Associate keyId with actual key in secure storage (not shown)
    // storeApiKey(keyId, apiKey);
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('apiKeyId', keyId, { httpOnly: true, secure: true });
    res.json({ status: 'API key reference stored' });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const userData = {
        name: req.body.name,
        email: req.body.email,
        // Don't include sensitive data like SSN
    };
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('userProfile', JSON.stringify(userData));
    
    // Store sensitive data server-side instead
    const userId = req.session.userId;
    // storeSensitiveData(userId, req.body.ssn, req.body.dob);
    
    res.send('Profile saved');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    // Use JWT with appropriate claims instead of storing raw data
    const token = jwt.sign(
        { userId: req.session.userId, access: 'health_data' },
        process.env.JWT_SECRET as string,
        { expiresIn: '1h' }
    );
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('accessToken', token, { httpOnly: true, secure: true });
    res.send('Access token provided');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    // Store only non-sensitive reference data
    const bankAccountReference = {
        accountId: generateReferenceId(),
        lastAccessed: new Date().toISOString()
    };
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('bankRef', JSON.stringify(bankAccountReference), { httpOnly: true, secure: true });
    res.send('Bank reference saved');
}
// {/fact}

function generateReferenceId(): string {
    return 'REF_' + crypto.randomBytes(12).toString('hex');
}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    // Create a one-time token for accessing passport info
    const accessToken = crypto.randomBytes(32).toString('hex');
    
    // Store token mapping server-side (not shown)
    // storeAccessToken(accessToken, req.session.userId, 'passport_access', 15 * 60); // 15 minutes
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('passportAccess', accessToken, { 
        maxAge: 15 * 60 * 1000, // 15 minutes
        httpOnly: true,
        secure: true
    });
    res.send('Access token provided');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    if (req.body.rememberMe) {
        // Generate a secure remember-me token instead of storing credentials
        const rememberToken = crypto.randomBytes(32).toString('hex');
        
        // Store token mapping server-side (not shown)
        // storeRememberToken(rememberToken, req.body.username);
        
        // ok: typescript-avoid-sensitive-data-in-cookie
        res.cookie('rememberMe', rememberToken, { 
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            httpOnly: true,
            secure: true
        });
    }
    res.redirect('/home');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    // Don't store private keys in cookies
    // Instead, store a reference to a key that's kept secure server-side
    const keyReference = `key_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    
    // Store mapping server-side (not shown)
    // storeKeyMapping(keyReference, req.body.privateKey);
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('keyRef', keyReference, { httpOnly: true, secure: true });
    res.send('Key reference stored');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    // For 2FA, store a session indicator that 2FA is required/complete
    // but not the actual secret
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('2faRequired', 'true', { httpOnly: true, secure: true });
    
    // Store the actual secret server-side (not shown)
    // store2FASecret(req.session.userId, req.body.twoFactorSecret);
    
    res.send('2FA status updated');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    // Store only non-sensitive personal info
    const safePersonalInfo = {
        fullName: req.body.name,
        // Exclude sensitive data like address, phone, taxId
    };
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('userBasicInfo', JSON.stringify(safePersonalInfo));
    
    // Store sensitive data server-side with proper encryption (not shown)
    // storePersonalData(req.session.userId, req.body.address, req.body.phone, req.body.taxId);
    
    res.send('Information saved securely');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    // Don't store security question answers in cookies
    // Instead, create a verification session
    const verificationSession = crypto.randomBytes(16).toString('hex');
    
    // Store verification data server-side (not shown)
    // storeVerificationSession(verificationSession, req.session.userId);
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('verificationId', verificationSession, { 
        maxAge: 10 * 60 * 1000, // 10 minutes
        httpOnly: true,
        secure: true
    });
    res.send('Verification session created');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    // For biometric data, only store a verification status, not the data itself
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('biometricVerified', 'true', { 
        maxAge: 30 * 60 * 1000, // 30 minutes
        httpOnly: true,
        secure: true
    });
    res.send('Biometric verification recorded');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    // Store only non-sensitive employee data
    const safeEmployeeData = {
        id: req.body.employeeId,
        position: req.body.position
        // Exclude sensitive data like salary and performance rating
    };
    
    // ok: typescript-avoid-sensitive-data-in-cookie
    res.cookie('employeeBasicInfo', JSON.stringify(safeEmployeeData));
    
    // Store sensitive data server-side (not shown)
    // storeEmployeeSensitiveData(req.body.employeeId, req.body.salary, req.body.rating);
    
    res.send('Employee data saved securely');
}
// {/fact}