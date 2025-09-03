const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// True Positives (Vulnerable/Insecure Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1() {
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  // Creating a client with insecure credentials
  // ruleid: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService('localhost:50051', 
    grpc.credentials.createInsecure());
  
  client.getUser({ id: 123 }, (err, response) => {
    console.log('User data:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_2() {
  // Creating a server with insecure credentials
  const server = new grpc.Server();
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  server.addService(serviceProto.ExampleService.service, {
    getUser: (call, callback) => {
      callback(null, { name: 'John', id: call.request.id });
    }
  });
  
  // ruleid: javascript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
    server.start();
    console.log('Server started on port 50051');
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_3() {
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  function createGrpcClient(address) {
    // ruleid: javascript-insecure-grpc-connection
    return new serviceProto.ExampleService(address, grpc.credentials.createInsecure());
  }
  
  const client = createGrpcClient('localhost:50051');
  client.processData({ data: 'sensitive information' }, (err, response) => {
    console.log('Processed:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4() {
  const express = require('express');
  const app = express();
  
  app.get('/connect-service', (req, res) => {
    const serviceAddress = req.query.address || 'localhost:50051';
    const packageDefinition = protoLoader.loadSync('service.proto');
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    // ruleid: javascript-insecure-grpc-connection
    const client = new serviceProto.ExampleService(
      serviceAddress, 
      grpc.credentials.createInsecure()
    );
    
    client.getData({}, (err, response) => {
      res.json(response);
    });
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5() {
  class ServiceConnector {
    constructor(address) {
      const packageDefinition = protoLoader.loadSync('service.proto');
      const serviceProto = grpc.loadPackageDefinition(packageDefinition);
      
      // ruleid: javascript-insecure-grpc-connection
      this.client = new serviceProto.ExampleService(
        address, 
        grpc.credentials.createInsecure()
      );
    }
    
    fetchData(id) {
      return new Promise((resolve, reject) => {
        this.client.getData({ id }, (err, data) => {
          if (err) reject(err);
          else resolve(data);
        });
      });
    }
  }
  
  const connector = new ServiceConnector('localhost:50051');
  connector.fetchData(123).then(console.log);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6() {
  function startServer(port) {
    const server = new grpc.Server();
    const packageDefinition = protoLoader.loadSync('service.proto');
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    server.addService(serviceProto.ExampleService.service, {
      getData: (call, callback) => {
        callback(null, { result: 'data' });
      }
    });
    
    // ruleid: javascript-insecure-grpc-connection
    server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), () => {
      server.start();
      console.log(`Server started on port ${port}`);
    });
    
    return server;
  }
  
  const server = startServer(50051);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7() {
  // Using environment variables but still insecure
  const host = process.env.GRPC_HOST || 'localhost';
  const port = process.env.GRPC_PORT || '50051';
  
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  // ruleid: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    `${host}:${port}`, 
    grpc.credentials.createInsecure()
  );
  
  client.processPayment({ amount: 100 }, (err, response) => {
    console.log('Payment processed:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url === '/api/connect') {
      const packageDefinition = protoLoader.loadSync('service.proto');
      const serviceProto = grpc.loadPackageDefinition(packageDefinition);
      
      // ruleid: javascript-insecure-grpc-connection
      const client = new serviceProto.ExampleService(
        'microservice:50051', 
        grpc.credentials.createInsecure()
      );
      
      client.getData({}, (err, data) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_9() {
  // Dynamic service selection but still insecure
  function getServiceClient(serviceName) {
    const packageDefinition = protoLoader.loadSync(`${serviceName}.proto`);
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    const serviceMap = {
      'users': 'user-service:50051',
      'products': 'product-service:50052',
      'orders': 'order-service:50053'
    };
    
    // ruleid: javascript-insecure-grpc-connection
    return new serviceProto[`${serviceName}Service`](
      serviceMap[serviceName], 
      grpc.credentials.createInsecure()
    );
  }
  
  const userClient = getServiceClient('users');
  userClient.getUser({ id: 123 }, console.log);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10() {
  // Insecure server with multiple services
  const server = new grpc.Server();
  
  const userPackage = protoLoader.loadSync('user.proto');
  const userProto = grpc.loadPackageDefinition(userPackage);
  
  const productPackage = protoLoader.loadSync('product.proto');
  const productProto = grpc.loadPackageDefinition(productPackage);
  
  server.addService(userProto.UserService.service, {
    getUser: (call, callback) => {
      callback(null, { name: 'John', id: call.request.id });
    }
  });
  
  server.addService(productProto.ProductService.service, {
    getProduct: (call, callback) => {
      callback(null, { name: 'Laptop', id: call.request.id });
    }
  });
  
  // ruleid: javascript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
    server.start();
    console.log('Multi-service server started');
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11() {
  // Insecure connection with retry logic
  function connectWithRetry(address, maxRetries = 5) {
    const packageDefinition = protoLoader.loadSync('service.proto');
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    let retries = 0;
    let client;
    
    function tryConnect() {
      if (retries >= maxRetries) {
        throw new Error('Max retries reached');
      }
      
      try {
        // ruleid: javascript-insecure-grpc-connection
        client = new serviceProto.ExampleService(
          address, 
          grpc.credentials.createInsecure()
        );
        
        return client;
      } catch (err) {
        retries++;
        console.log(`Connection failed, retrying (${retries}/${maxRetries})`);
        return tryConnect();
      }
    }
    
    return tryConnect();
  }
  
  const client = connectWithRetry('localhost:50051');
  client.getData({}, console.log);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12() {
  // Using a configuration object but still insecure
  const config = {
    service: {
      address: 'localhost:50051',
      timeout: 5000,
      retries: 3
    }
  };
  
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  // ruleid: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    config.service.address, 
    grpc.credentials.createInsecure(),
    { 'grpc.keepalive_timeout_ms': config.service.timeout }
  );
  
  client.getData({}, (err, response) => {
    console.log('Response:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_13() {
  // Insecure server with health check
  const server = new grpc.Server();
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  const healthPackage = protoLoader.loadSync('health.proto');
  const healthProto = grpc.loadPackageDefinition(healthPackage);
  
  server.addService(serviceProto.ExampleService.service, {
    getData: (call, callback) => {
      callback(null, { result: 'data' });
    }
  });
  
  server.addService(healthProto.Health.service, {
    check: (call, callback) => {
      callback(null, { status: 'SERVING' });
    }
  });
  
  // ruleid: javascript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
    server.start();
    console.log('Server with health check started');
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14() {
  // Insecure connection with metadata
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  // ruleid: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    'localhost:50051', 
    grpc.credentials.createInsecure()
  );
  
  const metadata = new grpc.Metadata();
  metadata.add('authorization', 'Bearer token123');
  
  client.getData({}, metadata, (err, response) => {
    console.log('Response with auth:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15() {
  // Insecure connection in an async function
  async function processUserData(userId) {
    const packageDefinition = protoLoader.loadSync('user.proto');
    const userProto = grpc.loadPackageDefinition(packageDefinition);
    
    // ruleid: javascript-insecure-grpc-connection
    const client = new userProto.UserService(
      'user-service:50051', 
      grpc.credentials.createInsecure()
    );
    
    return new Promise((resolve, reject) => {
      client.getUser({ id: userId }, (err, user) => {
        if (err) reject(err);
        else resolve(user);
      });
    });
  }
  
  processUserData(123)
    .then(user => console.log('User:', user))
    .catch(err => console.error('Error:', err));
}
// {/fact}

// True Negatives (Safe/Secure Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1() {
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  // Using SSL/TLS credentials
  const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
  
  // ok: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    'localhost:50051',
    grpc.credentials.createSsl(rootCert)
  );
  
  client.getUser({ id: 123 }, (err, response) => {
    console.log('User data:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2() {
  // Creating a secure server
  const server = new grpc.Server();
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  server.addService(serviceProto.ExampleService.service, {
    getUser: (call, callback) => {
      callback(null, { name: 'John', id: call.request.id });
    }
  });
  
  const privateKey = fs.readFileSync(path.resolve(__dirname, 'certs/server.key'));
  const certChain = fs.readFileSync(path.resolve(__dirname, 'certs/server.crt'));
  
  // ok: javascript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', 
    grpc.ServerCredentials.createSsl(null, [{
      private_key: privateKey,
      cert_chain: certChain
    }], false), 
    () => {
      server.start();
      console.log('Secure server started on port 50051');
    }
  );
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_3() {
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  function createSecureGrpcClient(address) {
    const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
    const clientKey = fs.readFileSync(path.resolve(__dirname, 'certs/client.key'));
    const clientCert = fs.readFileSync(path.resolve(__dirname, 'certs/client.crt'));
    
    // ok: javascript-insecure-grpc-connection
    return new serviceProto.ExampleService(
      address,
      grpc.credentials.createSsl(rootCert, clientKey, clientCert)
    );
  }
  
  const client = createSecureGrpcClient('localhost:50051');
  client.processData({ data: 'sensitive information' }, (err, response) => {
    console.log('Processed:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_4() {
  const express = require('express');
  const app = express();
  
  app.get('/connect-service', (req, res) => {
    const serviceAddress = req.query.address || 'localhost:50051';
    const packageDefinition = protoLoader.loadSync('service.proto');
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
    
    // ok: javascript-insecure-grpc-connection
    const client = new serviceProto.ExampleService(
      serviceAddress, 
      grpc.credentials.createSsl(rootCert)
    );
    
    client.getData({}, (err, response) => {
      res.json(response);
    });
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5() {
  class SecureServiceConnector {
    constructor(address) {
      const packageDefinition = protoLoader.loadSync('service.proto');
      const serviceProto = grpc.loadPackageDefinition(packageDefinition);
      
      const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
      
      // ok: javascript-insecure-grpc-connection
      this.client = new serviceProto.ExampleService(
        address, 
        grpc.credentials.createSsl(rootCert)
      );
    }
    
    fetchData(id) {
      return new Promise((resolve, reject) => {
        this.client.getData({ id }, (err, data) => {
          if (err) reject(err);
          else resolve(data);
        });
      });
    }
  }
  
  const connector = new SecureServiceConnector('localhost:50051');
  connector.fetchData(123).then(console.log);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6() {
  function startSecureServer(port) {
    const server = new grpc.Server();
    const packageDefinition = protoLoader.loadSync('service.proto');
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    server.addService(serviceProto.ExampleService.service, {
      getData: (call, callback) => {
        callback(null, { result: 'data' });
      }
    });
    
    const privateKey = fs.readFileSync(path.resolve(__dirname, 'certs/server.key'));
    const certChain = fs.readFileSync(path.resolve(__dirname, 'certs/server.crt'));
    
    // ok: javascript-insecure-grpc-connection
    server.bindAsync(`0.0.0.0:${port}`, 
      grpc.ServerCredentials.createSsl(null, [{
        private_key: privateKey,
        cert_chain: certChain
      }], false), 
      () => {
        server.start();
        console.log(`Secure server started on port ${port}`);
      }
    );
    
    return server;
  }
  
  const server = startSecureServer(50051);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7() {
  // Using environment variables with secure connection
  const host = process.env.GRPC_HOST || 'localhost';
  const port = process.env.GRPC_PORT || '50051';
  
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
  
  // ok: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    `${host}:${port}`, 
    grpc.credentials.createSsl(rootCert)
  );
  
  client.processPayment({ amount: 100 }, (err, response) => {
    console.log('Payment processed:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8() {
  const http = require('http');
  
  http.createServer((req, res) => {
    if (req.url === '/api/connect') {
      const packageDefinition = protoLoader.loadSync('service.proto');
      const serviceProto = grpc.loadPackageDefinition(packageDefinition);
      
      const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
      
      // ok: javascript-insecure-grpc-connection
      const client = new serviceProto.ExampleService(
        'microservice:50051', 
        grpc.credentials.createSsl(rootCert)
      );
      
      client.getData({}, (err, data) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9() {
  // Dynamic service selection with secure connections
  function getSecureServiceClient(serviceName) {
    const packageDefinition = protoLoader.loadSync(`${serviceName}.proto`);
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    const serviceMap = {
      'users': 'user-service:50051',
      'products': 'product-service:50052',
      'orders': 'order-service:50053'
    };
    
    const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
    
    // ok: javascript-insecure-grpc-connection
    return new serviceProto[`${serviceName}Service`](
      serviceMap[serviceName], 
      grpc.credentials.createSsl(rootCert)
    );
  }
  
  const userClient = getSecureServiceClient('users');
  userClient.getUser({ id: 123 }, console.log);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10() {
  // Secure server with multiple services
  const server = new grpc.Server();
  
  const userPackage = protoLoader.loadSync('user.proto');
  const userProto = grpc.loadPackageDefinition(userPackage);
  
  const productPackage = protoLoader.loadSync('product.proto');
  const productProto = grpc.loadPackageDefinition(productPackage);
  
  server.addService(userProto.UserService.service, {
    getUser: (call, callback) => {
      callback(null, { name: 'John', id: call.request.id });
    }
  });
  
  server.addService(productProto.ProductService.service, {
    getProduct: (call, callback) => {
      callback(null, { name: 'Laptop', id: call.request.id });
    }
  });
  
  const privateKey = fs.readFileSync(path.resolve(__dirname, 'certs/server.key'));
  const certChain = fs.readFileSync(path.resolve(__dirname, 'certs/server.crt'));
  
  // ok: javascript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', 
    grpc.ServerCredentials.createSsl(null, [{
      private_key: privateKey,
      cert_chain: certChain
    }], false), 
    () => {
      server.start();
      console.log('Secure multi-service server started');
    }
  );
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11() {
  // Secure connection with retry logic
  function connectSecureWithRetry(address, maxRetries = 5) {
    const packageDefinition = protoLoader.loadSync('service.proto');
    const serviceProto = grpc.loadPackageDefinition(packageDefinition);
    
    let retries = 0;
    let client;
    
    function tryConnect() {
      if (retries >= maxRetries) {
        throw new Error('Max retries reached');
      }
      
      try {
        const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
        
        // ok: javascript-insecure-grpc-connection
        client = new serviceProto.ExampleService(
          address, 
          grpc.credentials.createSsl(rootCert)
        );
        
        return client;
      } catch (err) {
        retries++;
        console.log(`Connection failed, retrying (${retries}/${maxRetries})`);
        return tryConnect();
      }
    }
    
    return tryConnect();
  }
  
  const client = connectSecureWithRetry('localhost:50051');
  client.getData({}, console.log);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12() {
  // Using a configuration object with secure connection
  const config = {
    service: {
      address: 'localhost:50051',
      timeout: 5000,
      retries: 3,
      certPath: path.resolve(__dirname, 'certs/ca.pem')
    }
  };
  
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  const rootCert = fs.readFileSync(config.service.certPath);
  
  // ok: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    config.service.address, 
    grpc.credentials.createSsl(rootCert),
    { 'grpc.keepalive_timeout_ms': config.service.timeout }
  );
  
  client.getData({}, (err, response) => {
    console.log('Response:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13() {
  // Secure server with health check
  const server = new grpc.Server();
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  const healthPackage = protoLoader.loadSync('health.proto');
  const healthProto = grpc.loadPackageDefinition(healthPackage);
  
  server.addService(serviceProto.ExampleService.service, {
    getData: (call, callback) => {
      callback(null, { result: 'data' });
    }
  });
  
  server.addService(healthProto.Health.service, {
    check: (call, callback) => {
      callback(null, { status: 'SERVING' });
    }
  });
  
  const privateKey = fs.readFileSync(path.resolve(__dirname, 'certs/server.key'));
  const certChain = fs.readFileSync(path.resolve(__dirname, 'certs/server.crt'));
  
  // ok: javascript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', 
    grpc.ServerCredentials.createSsl(null, [{
      private_key: privateKey,
      cert_chain: certChain
    }], false), 
    () => {
      server.start();
      console.log('Secure server with health check started');
    }
  );
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14() {
  // Secure connection with metadata
  const packageDefinition = protoLoader.loadSync('service.proto');
  const serviceProto = grpc.loadPackageDefinition(packageDefinition);
  
  const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
  
  // ok: javascript-insecure-grpc-connection
  const client = new serviceProto.ExampleService(
    'localhost:50051', 
    grpc.credentials.createSsl(rootCert)
  );
  
  const metadata = new grpc.Metadata();
  metadata.add('authorization', 'Bearer token123');
  
  client.getData({}, metadata, (err, response) => {
    console.log('Response with auth:', response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15() {
  // Secure connection in an async function
  async function processUserDataSecurely(userId) {
    const packageDefinition = protoLoader.loadSync('user.proto');
    const userProto = grpc.loadPackageDefinition(packageDefinition);
    
    const rootCert = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
    
    // ok: javascript-insecure-grpc-connection
    const client = new userProto.UserService(
      'user-service:50051', 
      grpc.credentials.createSsl(rootCert)
    );
    
    return new Promise((resolve, reject) => {
      client.getUser({ id: userId }, (err, user) => {
        if (err) reject(err);
        else resolve(user);
      });
    });
  }
  
  processUserDataSecurely(123)
    .then(user => console.log('User:', user))
    .catch(err => console.error('Error:', err));
}
// {/fact}