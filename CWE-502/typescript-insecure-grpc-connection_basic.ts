import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as fs from 'fs';
import * as path from 'path';

// True Positive Examples (Insecure gRPC connections)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1() {
  // Creating an insecure gRPC client connection
  // ruleid: typescript-insecure-grpc-connection
  const client = new grpc.Client('localhost:50051', grpc.credentials.createInsecure());
  client.connect();
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_2() {
  // Creating an insecure gRPC server
  const server = new grpc.Server();
  // ruleid: typescript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
    server.start();
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_3() {
  const packageDefinition = protoLoader.loadSync('service.proto');
  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
  const service = protoDescriptor.MyService;
  
  // ruleid: typescript-insecure-grpc-connection
  const client = new service('localhost:50051', grpc.credentials.createInsecure());
  client.myMethod({name: 'test'}, (err: any, response: any) => {
    console.log(response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4() {
  const options = {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  };
  
  const packageDefinition = protoLoader.loadSync('service.proto', options);
  const serviceProto = grpc.loadPackageDefinition(packageDefinition).service;
  
  // ruleid: typescript-insecure-grpc-connection
  const server = new grpc.Server();
  server.addService(serviceProto.service, {
    myMethod: (call: any, callback: any) => {
      callback(null, { message: 'Response' });
    }
  });
  server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
    server.start();
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5() {
  function createGrpcClient(address: string) {
    // ruleid: typescript-insecure-grpc-connection
    return new grpc.Client(address, grpc.credentials.createInsecure());
  }
  
  const client = createGrpcClient('localhost:50051');
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6() {
  const serverOptions = {
    'grpc.max_receive_message_length': 1024 * 1024 * 100,
    'grpc.max_send_message_length': 1024 * 1024 * 100
  };
  
  const server = new grpc.Server(serverOptions);
  // ruleid: typescript-insecure-grpc-connection
  const bindPromise = server.bindAsync(
    '0.0.0.0:50051', 
    grpc.ServerCredentials.createInsecure(),
    () => {
      console.log('Server running at 0.0.0.0:50051');
      server.start();
    }
  );
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7() {
  class GrpcService {
    private client: any;
    
    constructor(serviceUrl: string) {
      const packageDefinition = protoLoader.loadSync('service.proto');
      const service = grpc.loadPackageDefinition(packageDefinition).MyService;
      // ruleid: typescript-insecure-grpc-connection
      this.client = new service(serviceUrl, grpc.credentials.createInsecure());
    }
    
    callService(data: any): Promise<any> {
      return new Promise((resolve, reject) => {
        this.client.processData(data, (err: any, response: any) => {
          if (err) reject(err);
          else resolve(response);
        });
      });
    }
  }
  
  const service = new GrpcService('localhost:50051');
  return service;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8() {
  // Creating multiple insecure connections in a loop
  const servers = ['server1:50051', 'server2:50051', 'server3:50051'];
  const clients = servers.map(server => {
    // ruleid: typescript-insecure-grpc-connection
    return new grpc.Client(server, grpc.credentials.createInsecure());
  });
  
  return clients;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_9() {
  const config = {
    host: 'localhost',
    port: 50051,
    useSecure: false
  };
  
  let credentials;
  if (config.useSecure) {
    const rootCert = fs.readFileSync('root.pem');
    credentials = grpc.credentials.createSsl(rootCert);
  } else {
    // ruleid: typescript-insecure-grpc-connection
    credentials = grpc.credentials.createInsecure();
  }
  
  const client = new grpc.Client(`${config.host}:${config.port}`, credentials);
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10() {
  function setupGrpcServer(port: number, secure: boolean) {
    const server = new grpc.Server();
    
    if (secure) {
      const privateKey = fs.readFileSync('server.key');
      const certChain = fs.readFileSync('server.crt');
      const creds = grpc.ServerCredentials.createSsl(null, [{
        private_key: privateKey,
        cert_chain: certChain
      }]);
      server.bindAsync(`0.0.0.0:${port}`, creds, () => server.start());
    } else {
      // ruleid: typescript-insecure-grpc-connection
      server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), () => server.start());
    }
    
    return server;
  }
  
  return setupGrpcServer(50051, false);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11() {
  const isProduction = process.env.NODE_ENV === 'production';
  
  function getCredentials() {
    if (isProduction) {
      const rootCert = fs.readFileSync('root.pem');
      return grpc.credentials.createSsl(rootCert);
    } else {
      // ruleid: typescript-insecure-grpc-connection
      return grpc.credentials.createInsecure();
    }
  }
  
  const client = new grpc.Client('localhost:50051', getCredentials());
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12() {
  // Creating an insecure gRPC client with channel options
  const options = {
    'grpc.keepalive_time_ms': 10000,
    'grpc.keepalive_timeout_ms': 5000,
    'grpc.keepalive_permit_without_calls': 1
  };
  
  // ruleid: typescript-insecure-grpc-connection
  const client = new grpc.Client('localhost:50051', grpc.credentials.createInsecure(), options);
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_13() {
  // Using a factory function to create insecure credentials
  function createCredentials(useSecure: boolean) {
    if (useSecure) {
      const rootCert = fs.readFileSync('root.pem');
      return grpc.credentials.createSsl(rootCert);
    }
    // ruleid: typescript-insecure-grpc-connection
    return grpc.credentials.createInsecure();
  }
  
  const client = new grpc.Client('localhost:50051', createCredentials(false));
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14() {
  // Creating an insecure gRPC server with multiple services
  const server = new grpc.Server();
  
  const packageDefinition1 = protoLoader.loadSync('service1.proto');
  const packageDefinition2 = protoLoader.loadSync('service2.proto');
  
  const service1 = grpc.loadPackageDefinition(packageDefinition1).Service1;
  const service2 = grpc.loadPackageDefinition(packageDefinition2).Service2;
  
  server.addService(service1.service, {
    method1: (call: any, callback: any) => {
      callback(null, { result: 'Service 1 response' });
    }
  });
  
  server.addService(service2.service, {
    method2: (call: any, callback: any) => {
      callback(null, { result: 'Service 2 response' });
    }
  });
  
  // ruleid: typescript-insecure-grpc-connection
  server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
    server.start();
    console.log('Server started on port 50051');
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15() {
  // Using insecure connection with async/await pattern
  async function callGrpcService(data: any) {
    const packageDefinition = protoLoader.loadSync('service.proto');
    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const service = protoDescriptor.MyService;
    
    // ruleid: typescript-insecure-grpc-connection
    const client = new service('localhost:50051', grpc.credentials.createInsecure());
    
    return new Promise((resolve, reject) => {
      client.processData(data, (err: any, response: any) => {
        if (err) reject(err);
        else resolve(response);
      });
    });
  }
  
  return callGrpcService({ input: 'test data' });
}
// {/fact}

// True Negative Examples (Secure gRPC connections)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1() {
  // Creating a secure gRPC client connection with SSL
  const rootCerts = fs.readFileSync(path.resolve(__dirname, 'certs/ca.pem'));
  // ok: typescript-insecure-grpc-connection
  const secureCredentials = grpc.credentials.createSsl(rootCerts);
  const client = new grpc.Client('localhost:50051', secureCredentials);
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2() {
  // Creating a secure gRPC server with SSL
  const server = new grpc.Server();
  
  const privateKey = fs.readFileSync('server.key');
  const certChain = fs.readFileSync('server.crt');
  // ok: typescript-insecure-grpc-connection
  const creds = grpc.ServerCredentials.createSsl(null, [{
    private_key: privateKey,
    cert_chain: certChain
  }]);
  
  server.bindAsync('0.0.0.0:50051', creds, () => {
    server.start();
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_3() {
  const packageDefinition = protoLoader.loadSync('service.proto');
  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
  const service = protoDescriptor.MyService;
  
  const rootCerts = fs.readFileSync('ca.pem');
  const clientKey = fs.readFileSync('client.key');
  const clientCert = fs.readFileSync('client.crt');
  
  // ok: typescript-insecure-grpc-connection
  const sslCreds = grpc.credentials.createSsl(rootCerts, clientKey, clientCert);
  const client = new service('localhost:50051', sslCreds);
  
  client.myMethod({name: 'test'}, (err: any, response: any) => {
    console.log(response);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_4() {
  const options = {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  };
  
  const packageDefinition = protoLoader.loadSync('service.proto', options);
  const serviceProto = grpc.loadPackageDefinition(packageDefinition).service;
  
  const server = new grpc.Server();
  server.addService(serviceProto.service, {
    myMethod: (call: any, callback: any) => {
      callback(null, { message: 'Response' });
    }
  });
  
  const privateKey = fs.readFileSync('server.key');
  const certChain = fs.readFileSync('server.crt');
  // ok: typescript-insecure-grpc-connection
  const sslCreds = grpc.ServerCredentials.createSsl(null, [{
    private_key: privateKey,
    cert_chain: certChain
  }], true); // Require client certificate
  
  server.bindAsync('0.0.0.0:50051', sslCreds, () => {
    server.start();
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5() {
  function createSecureGrpcClient(address: string) {
    const rootCerts = fs.readFileSync('ca.pem');
    // ok: typescript-insecure-grpc-connection
    return new grpc.Client(address, grpc.credentials.createSsl(rootCerts));
  }
  
  const client = createSecureGrpcClient('localhost:50051');
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6() {
  const serverOptions = {
    'grpc.max_receive_message_length': 1024 * 1024 * 100,
    'grpc.max_send_message_length': 1024 * 1024 * 100
  };
  
  const server = new grpc.Server(serverOptions);
  
  const privateKey = fs.readFileSync('server.key');
  const certChain = fs.readFileSync('server.crt');
  // ok: typescript-insecure-grpc-connection
  const sslCreds = grpc.ServerCredentials.createSsl(null, [{
    private_key: privateKey,
    cert_chain: certChain
  }]);
  
  const bindPromise = server.bindAsync(
    '0.0.0.0:50051', 
    sslCreds,
    () => {
      console.log('Secure server running at 0.0.0.0:50051');
      server.start();
    }
  );
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7() {
  class SecureGrpcService {
    private client: any;
    
    constructor(serviceUrl: string) {
      const packageDefinition = protoLoader.loadSync('service.proto');
      const service = grpc.loadPackageDefinition(packageDefinition).MyService;
      
      const rootCerts = fs.readFileSync('ca.pem');
      const clientKey = fs.readFileSync('client.key');
      const clientCert = fs.readFileSync('client.crt');
      
      // ok: typescript-insecure-grpc-connection
      const sslCreds = grpc.credentials.createSsl(rootCerts, clientKey, clientCert);
      this.client = new service(serviceUrl, sslCreds);
    }
    
    callService(data: any): Promise<any> {
      return new Promise((resolve, reject) => {
        this.client.processData(data, (err: any, response: any) => {
          if (err) reject(err);
          else resolve(response);
        });
      });
    }
  }
  
  const service = new SecureGrpcService('localhost:50051');
  return service;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8() {
  // Creating multiple secure connections in a loop
  const servers = ['server1:50051', 'server2:50051', 'server3:50051'];
  const rootCerts = fs.readFileSync('ca.pem');
  
  // ok: typescript-insecure-grpc-connection
  const secureCredentials = grpc.credentials.createSsl(rootCerts);
  
  const clients = servers.map(server => {
    return new grpc.Client(server, secureCredentials);
  });
  
  return clients;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9() {
  const config = {
    host: 'localhost',
    port: 50051,
    useSecure: true
  };
  
  let credentials;
  if (config.useSecure) {
    const rootCert = fs.readFileSync('root.pem');
    // ok: typescript-insecure-grpc-connection
    credentials = grpc.credentials.createSsl(rootCert);
  } else {
    credentials = grpc.credentials.createInsecure();
  }
  
  const client = new grpc.Client(`${config.host}:${config.port}`, credentials);
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10() {
  function setupGrpcServer(port: number, secure: boolean) {
    const server = new grpc.Server();
    
    if (secure) {
      const privateKey = fs.readFileSync('server.key');
      const certChain = fs.readFileSync('server.crt');
      // ok: typescript-insecure-grpc-connection
      const creds = grpc.ServerCredentials.createSsl(null, [{
        private_key: privateKey,
        cert_chain: certChain
      }]);
      server.bindAsync(`0.0.0.0:${port}`, creds, () => server.start());
    } else {
      server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), () => server.start());
    }
    
    return server;
  }
  
  return setupGrpcServer(50051, true);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11() {
  // Using mutual TLS authentication
  const rootCerts = fs.readFileSync('ca.pem');
  const privateKey = fs.readFileSync('client.key');
  const certChain = fs.readFileSync('client.crt');
  
  // ok: typescript-insecure-grpc-connection
  const credentials = grpc.credentials.createSsl(rootCerts, privateKey, certChain);
  
  const packageDefinition = protoLoader.loadSync('service.proto');
  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
  const service = protoDescriptor.MyService;
  
  const client = new service('localhost:50051', credentials);
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12() {
  // Creating a secure gRPC client with channel options
  const options = {
    'grpc.ssl_target_name_override': 'localhost',
    'grpc.default_authority': 'localhost',
    'grpc.keepalive_time_ms': 10000
  };
  
  const rootCerts = fs.readFileSync('ca.pem');
  // ok: typescript-insecure-grpc-connection
  const secureCredentials = grpc.credentials.createSsl(rootCerts);
  
  const client = new grpc.Client('localhost:50051', secureCredentials, options);
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13() {
  // Using a factory function to create secure credentials
  function createCredentials(useSecure: boolean) {
    if (useSecure) {
      const rootCert = fs.readFileSync('root.pem');
      // ok: typescript-insecure-grpc-connection
      return grpc.credentials.createSsl(rootCert);
    }
    return grpc.credentials.createInsecure();
  }
  
  const client = new grpc.Client('localhost:50051', createCredentials(true));
  return client;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14() {
  // Creating a secure gRPC server with multiple services
  const server = new grpc.Server();
  
  const packageDefinition1 = protoLoader.loadSync('service1.proto');
  const packageDefinition2 = protoLoader.loadSync('service2.proto');
  
  const service1 = grpc.loadPackageDefinition(packageDefinition1).Service1;
  const service2 = grpc.loadPackageDefinition(packageDefinition2).Service2;
  
  server.addService(service1.service, {
    method1: (call: any, callback: any) => {
      callback(null, { result: 'Service 1 response' });
    }
  });
  
  server.addService(service2.service, {
    method2: (call: any, callback: any) => {
      callback(null, { result: 'Service 2 response' });
    }
  });
  
  const privateKey = fs.readFileSync('server.key');
  const certChain = fs.readFileSync('server.crt');
  // ok: typescript-insecure-grpc-connection
  const sslCreds = grpc.ServerCredentials.createSsl(null, [{
    private_key: privateKey,
    cert_chain: certChain
  }]);
  
  server.bindAsync('0.0.0.0:50051', sslCreds, () => {
    server.start();
    console.log('Secure server started on port 50051');
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15() {
  // Using secure connection with async/await pattern
  async function callSecureGrpcService(data: any) {
    const packageDefinition = protoLoader.loadSync('service.proto');
    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const service = protoDescriptor.MyService;
    
    const rootCerts = fs.readFileSync('ca.pem');
    // ok: typescript-insecure-grpc-connection
    const secureCredentials = grpc.credentials.createSsl(rootCerts);
    
    const client = new service('localhost:50051', secureCredentials);
    
    return new Promise((resolve, reject) => {
      client.processData(data, (err: any, response: any) => {
        if (err) reject(err);
        else resolve(response);
      });
    });
  }
  
  return callSecureGrpcService({ input: 'test data' });
}
// {/fact}