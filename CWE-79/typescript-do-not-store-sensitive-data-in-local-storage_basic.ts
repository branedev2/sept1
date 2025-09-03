// File: localStorage_security_examples.ts

// Import necessary libraries
import axios from 'axios';
import * as crypto from 'crypto';

// TRUE POSITIVES - Vulnerable code that should be detected

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const password = "supersecretpassword123";
  // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
  localStorage.setItem('userPassword', password);
  console.log("Password stored in localStorage");
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const creditCardInfo = {
    number: "4111-1111-1111-1111",
    cvv: "123",
    expiry: "12/25"
  };
  // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
  localStorage.setItem('paymentDetails', JSON.stringify(creditCardInfo));
  return "Payment info saved for future use";
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  axios.get('/api/user/profile')
    .then(response => {
      const userData = response.data;
      // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
      localStorage.setItem('userSSN', userData.ssn);
      console.log("User SSN stored locally");
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const apiKey = document.getElementById('apiKey')?.value || '';
  if (apiKey) {
    // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
    localStorage.setItem('apiKey', apiKey);
    console.log("API key saved for future requests");
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const authToken = fetchAuthToken();
  // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
  window.localStorage.setItem('authToken', authToken);
  
  function fetchAuthToken(): string {
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const userForm = document.getElementById('userForm') as HTMLFormElement;
  userForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = new FormData(userForm);
    // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
    localStorage.setItem('personalInfo', JSON.stringify({
      name: formData.get('name'),
      dob: formData.get('dob'),
      ssn: formData.get('ssn')
    }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  class UserAuth {
    storeCredentials(username: string, password: string) {
      // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
      localStorage.setItem('credentials', JSON.stringify({ username, password }));
      return true;
    }
  }
  
  const auth = new UserAuth();
  auth.storeCredentials("admin", "securePassword123");
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const twoFactorCode = prompt("Enter your 2FA code") || '';
  if (twoFactorCode.length === 6) {
    // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
    localStorage['twoFactorCode'] = twoFactorCode;
    verifyCode(twoFactorCode);
  }
  
  function verifyCode(code: string): void {
    console.log(`Verifying code: ${code}`);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  interface HealthData {
    medicalId: string;
    conditions: string[];
    medications: string[];
  }
  
  const patientData: HealthData = {
    medicalId: "PT-12345",
    conditions: ["Hypertension", "Diabetes"],
    medications: ["Lisinopril", "Metformin"]
  };
  
  // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
  localStorage.setItem('healthData', JSON.stringify(patientData));
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  axios.post('/api/login', { username: 'user', password: 'pass' })
    .then(response => {
      // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
      localStorage.setItem('accessToken', response.data.token);
      localStorage.setItem('refreshToken', response.data.refreshToken);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const encryptionKey = crypto.randomBytes(32).toString('hex');
  // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
  localStorage.setItem('encryptionKey', encryptionKey);
  console.log("Encryption key stored locally");
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  function saveBackupCodes(codes: string[]) {
    // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
    localStorage.setItem('backupCodes', JSON.stringify(codes));
  }
  
  saveBackupCodes(['123456', '234567', '345678', '456789']);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
Nsa5kMbv4v2Ye7oEYiYaFTbQU...
-----END PRIVATE KEY-----`;
  
  // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
  localStorage.setItem('privateKey', privateKey);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  let sensitiveUserData: Record<string, any> = {};
  
  function collectAndStoreData() {
    sensitiveUserData = {
      name: "John Doe",
      email: "john@example.com",
      taxId: "123-45-6789"
    };
    
    // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
    for (const [key, value] of Object.entries(sensitiveUserData)) {
      localStorage.setItem(`user_${key}`, value.toString());
    }
  }
  
  collectAndStoreData();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  
  if (token) {
    // ruleid: typescript-do-not-store-sensitive-data-in-local-storage
    localStorage.setItem('authToken', token);
    redirectToSecurePage();
  }
  
  function redirectToSecurePage(): void {
    window.location.href = '/dashboard';
  }
}
// {/fact}

// TRUE NEGATIVES - Secure code that should not be detected

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const password = "supersecretpassword123";
  // ok: typescript-do-not-store-sensitive-data-in-local-storage
  sessionStorage.setItem('tempAuthToken', generateTemporaryToken(password));
  console.log("Temporary token stored in sessionStorage");
  
  function generateTemporaryToken(pwd: string): string {
    return crypto.createHash('sha256').update(pwd + Date.now()).digest('hex');
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const creditCardInfo = {
    number: "4111-1111-1111-1111",
    cvv: "123",
    expiry: "12/25"
  };
  
  // ok: typescript-do-not-store-sensitive-data-in-local-storage
  const tokenizedCard = tokenizeCardData(creditCardInfo);
  localStorage.setItem('paymentToken', tokenizedCard);
  
  function tokenizeCardData(card: any): string {
    // In a real implementation, this would call a secure payment processor API
    return `token_${card.number.slice(-4)}_${Date.now()}`;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  axios.get('/api/user/profile')
    .then(response => {
      const userData = response.data;
      // ok: typescript-do-not-store-sensitive-data-in-local-storage
      document.getElementById('userSSN')!.textContent = userData.ssn;
      // Only store non-sensitive data
      localStorage.setItem('userPreferences', JSON.stringify(userData.preferences));
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const apiKey = document.getElementById('apiKey')?.value || '';
  if (apiKey) {
    // ok: typescript-do-not-store-sensitive-data-in-local-storage
    // Store API key in memory only for the current session
    const apiService = new APIService(apiKey);
    apiService.makeRequest();
  }
  
  class APIService {
    private key: string;
    
    constructor(apiKey: string) {
      this.key = apiKey;
    }
    
    makeRequest() {
      console.log("Making API request with key");
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const authToken = fetchAuthToken();
  
  // ok: typescript-do-not-store-sensitive-data-in-local-storage
  // Store a reference ID instead of the actual token
  const tokenRef = registerTokenWithServer(authToken);
  localStorage.setItem('tokenReference', tokenRef);
  
  function fetchAuthToken(): string {
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
  }
  
  function registerTokenWithServer(token: string): string {
    // In a real implementation, this would register the token with the server
    return `ref_${Date.now()}`;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const userForm = document.getElementById('userForm') as HTMLFormElement;
  userForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = new FormData(userForm);
    
    // ok: typescript-do-not-store-sensitive-data-in-local-storage
    // Only store non-sensitive information
    localStorage.setItem('userDisplayName', formData.get('name')?.toString() || '');
    
    // Send sensitive data to server but don't store locally
    axios.post('/api/submit-personal-info', {
      name: formData.get('name'),
      dob: formData.get('dob'),
      ssn: formData.get('ssn')
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  class UserAuth {
    storeAuthState(username: string, password: string) {
      // ok: typescript-do-not-store-sensitive-data-in-local-storage
      // Only store authentication state, not credentials
      axios.post('/api/login', { username, password })
        .then(response => {
          localStorage.setItem('isAuthenticated', 'true');
          localStorage.setItem('lastLogin', new Date().toISOString());
        });
    }
  }
  
  const auth = new UserAuth();
  auth.storeAuthState("admin", "securePassword123");
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const twoFactorCode = prompt("Enter your 2FA code") || '';
  if (twoFactorCode.length === 6) {
    // ok: typescript-do-not-store-sensitive-data-in-local-storage
    // Use the code immediately without storing it
    verifyCode(twoFactorCode);
  }
  
  function verifyCode(code: string): void {
    axios.post('/api/verify-2fa', { code })
      .then(response => {
        if (response.data.verified) {
          localStorage.setItem('twoFactorVerified', 'true');
        }
      });
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  interface HealthData {
    medicalId: string;
    conditions: string[];
    medications: string[];
  }
  
  const patientData: HealthData = {
    medicalId: "PT-12345",
    conditions: ["Hypertension", "Diabetes"],
    medications: ["Lisinopril", "Metformin"]
  };
  
  // ok: typescript-do-not-store-sensitive-data-in-local-storage
  // Store data on server instead of locally
  axios.post('/api/patient-data', patientData)
    .then(response => {
      // Only store a reference ID locally
      localStorage.setItem('patientDataId', response.data.recordId);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  axios.post('/api/login', { username: 'user', password: 'pass' })
    .then(response => {
      // ok: typescript-do-not-store-sensitive-data-in-local-storage
      // Store tokens in HTTP-only cookies (set by server) instead of localStorage
      console.log("Authentication successful, tokens stored in HTTP-only cookies");
      
      // Only store non-sensitive user preferences
      localStorage.setItem('theme', 'dark');
      localStorage.setItem('language', 'en');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const encryptionKey = crypto.randomBytes(32).toString('hex');
  
  // ok: typescript-do-not-store-sensitive-data-in-local-storage
  // Use the key in memory only, don't persist it
  const encryptedData = encrypt("Sensitive data", encryptionKey);
  sendToServer(encryptedData);
  
  function encrypt(data: string, key: string): string {
    // Simplified encryption example
    return `encrypted_${data}_${key.substring(0, 5)}`;
  }
  
  function sendToServer(data: string): void {
    console.log(`Sending encrypted data: ${data}`);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  function handleBackupCodes(codes: string[]) {
    // ok: typescript-do-not-store-sensitive-data-in-local-storage
    // Display codes to user but don't store them
    const codesList = document.getElementById('backupCodes');
    if (codesList) {
      codes.forEach(code => {
        const li = document.createElement('li');
        li.textContent = code;
        codesList.appendChild(li);
      });
    }
    
    // Only store non-sensitive metadata
    localStorage.setItem('backupCodesGenerated', new Date().toISOString());
    localStorage.setItem('backupCodesCount', codes.length.toString());
  }
  
  handleBackupCodes(['123456', '234567', '345678', '456789']);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
Nsa5kMbv4v2Ye7oEYiYaFTbQU...
-----END PRIVATE KEY-----`;
  
  // ok: typescript-do-not-store-sensitive-data-in-local-storage
  // Use the key in memory for the current operation only
  const signature = signData("message", privateKey);
  console.log(`Signed data: ${signature}`);
  
  function signData(message: string, key: string): string {
    // In a real implementation, this would use a proper signing algorithm
    return `signed_${message}_${Date.now()}`;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  let sensitiveUserData: Record<string, any> = {};
  
  function collectAndProcessData() {
    sensitiveUserData = {
      name: "John Doe",
      email: "john@example.com",
      taxId: "123-45-6789"
    };
    
    // ok: typescript-do-not-store-sensitive-data-in-local-storage
    // Only store non-sensitive data locally
    localStorage.setItem('user_name', sensitiveUserData.name);
    
    // Send sensitive data to server
    axios.post('/api/user-data', {
      email: sensitiveUserData.email,
      taxId: sensitiveUserData.taxId
    });
  }
  
  collectAndProcessData();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  
  if (token) {
    // ok: typescript-do-not-store-sensitive-data-in-local-storage
    // Use the token for the current request without storing it
    validateAndUseToken(token);
  }
  
  function validateAndUseToken(token: string): void {
    axios.post('/api/validate-token', { token })
      .then(response => {
        if (response.data.valid) {
          // Store only session state, not the token itself
          localStorage.setItem('isLoggedIn', 'true');
          window.location.href = '/dashboard';
        }
      });
  }
}
// {/fact}