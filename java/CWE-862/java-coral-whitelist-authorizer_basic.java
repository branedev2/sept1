package com.example.authorization;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.example.auth.WhitelistAuthorizer;
import com.example.auth.StrictAuthorizer;
import com.example.auth.Authorizer;
import com.example.auth.Operation;

public class AuthorizerExamples {

    // True Positive Examples (Vulnerable)

// {fact rule=missing-authorization@v1.0 defects=1}
    public void bad_case_1() {
        // Creating a WhitelistAuthorizer with non-healthcheck operations
        Set<Operation> operations = new HashSet<>();
        operations.add(new Operation("GetUserData"));
        operations.add(new Operation("UpdateUserProfile"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        authorizer.authorize("user123", "GetUserData");
    }

    public void bad_case_2() {
        // Using WhitelistAuthorizer for sensitive data operations
        Set<Operation> operations = new HashSet<>();
        operations.add(new Operation("ViewPaymentHistory"));
        operations.add(new Operation("ProcessPayment"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        authorizer.authorize("merchant", "ProcessPayment");
    }

    public void bad_case_3() {
        // WhitelistAuthorizer with admin operations
        Operation deleteUser = new Operation("DeleteUser");
        Operation createUser = new Operation("CreateUser");
        Set<Operation> adminOps = new HashSet<>(Arrays.asList(deleteUser, createUser));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer adminAuthorizer = new WhitelistAuthorizer(adminOps);
        adminAuthorizer.authorize("admin", "DeleteUser");
    }

    public void bad_case_4() {
        // Using WhitelistAuthorizer for file operations
        Set<Operation> fileOps = new HashSet<>();
        fileOps.add(new Operation("ReadFile"));
        fileOps.add(new Operation("WriteFile"));
        fileOps.add(new Operation("DeleteFile"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer fileAuthorizer = new WhitelistAuthorizer(fileOps);
        fileAuthorizer.authorize("user", "WriteFile");
    }

    public void bad_case_5() {
        // WhitelistAuthorizer with database operations
        Operation readData = new Operation("ReadData");
        Operation writeData = new Operation("WriteData");
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer dbAuthorizer = new WhitelistAuthorizer(
            new HashSet<>(Arrays.asList(readData, writeData))
        );
        dbAuthorizer.authorize("dbUser", "WriteData");
    }

    public void bad_case_6() {
        // WhitelistAuthorizer with API operations
        Set<Operation> apiOps = new HashSet<>();
        apiOps.add(new Operation("GetResource"));
        apiOps.add(new Operation("CreateResource"));
        apiOps.add(new Operation("DeleteResource"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer apiAuthorizer = new WhitelistAuthorizer(apiOps);
        apiAuthorizer.authorize("apiUser", "GetResource");
    }

    public void bad_case_7() {
        // WhitelistAuthorizer with mixed operations including non-healthcheck
        Set<Operation> mixedOps = new HashSet<>();
        mixedOps.add(new Operation("HealthCheck"));
        mixedOps.add(new Operation("Status"));
        mixedOps.add(new Operation("AdminOperation"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer mixedAuthorizer = new WhitelistAuthorizer(mixedOps);
        mixedAuthorizer.authorize("user", "Status");
    }

    public void bad_case_8() {
        // WhitelistAuthorizer with dynamically added operations
        Set<Operation> dynamicOps = new HashSet<>();
        dynamicOps.add(new Operation("HealthCheck"));
        
        // Adding non-healthcheck operation
        dynamicOps.add(new Operation("UserManagement"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer dynamicAuthorizer = new WhitelistAuthorizer(dynamicOps);
        dynamicAuthorizer.authorize("user", "UserManagement");
    }

    public void bad_case_9() {
        // WhitelistAuthorizer in a Lambda function handler
        Set<Operation> lambdaOps = new HashSet<>();
        lambdaOps.add(new Operation("ProcessAPIRequest"));
        lambdaOps.add(new Operation("HandleCallback"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer lambdaAuthorizer = new WhitelistAuthorizer(lambdaOps);
        lambdaAuthorizer.authorize("apiGateway", "ProcessAPIRequest");
    }

    public void bad_case_10() {
        // WhitelistAuthorizer with conditional operation addition
        Set<Operation> conditionalOps = new HashSet<>();
        conditionalOps.add(new Operation("HealthCheck"));
        
        boolean isAdmin = true;
        if (isAdmin) {
            conditionalOps.add(new Operation("AdminDashboard"));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer conditionalAuthorizer = new WhitelistAuthorizer(conditionalOps);
        conditionalAuthorizer.authorize("admin", "AdminDashboard");
    }

    public void bad_case_11() {
        // WhitelistAuthorizer with operations from external source
        Set<Operation> externalOps = getOperationsFromConfig();
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer externalAuthorizer = new WhitelistAuthorizer(externalOps);
        externalAuthorizer.authorize("user", "ConfiguredOperation");
    }

    private Set<Operation> getOperationsFromConfig() {
        // This would typically load from a config file or database
        Set<Operation> ops = new HashSet<>();
        ops.add(new Operation("ConfiguredOperation"));
        ops.add(new Operation("AnotherOperation"));
        return ops;
    }

    public void bad_case_12() {
        // WhitelistAuthorizer with operations in a loop
        String[] opNames = {"ViewReport", "GenerateReport", "ExportReport"};
        Set<Operation> reportOps = new HashSet<>();
        
        for (String opName : opNames) {
            reportOps.add(new Operation(opName));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer reportAuthorizer = new WhitelistAuthorizer(reportOps);
        reportAuthorizer.authorize("analyst", "GenerateReport");
    }

    public void bad_case_13() {
        // WhitelistAuthorizer with operations as method parameters
        Operation op1 = new Operation("ModifySettings");
        Operation op2 = new Operation("ViewSettings");
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer settingsAuthorizer = createAuthorizer(op1, op2);
        settingsAuthorizer.authorize("user", "ModifySettings");
    }
    
    private WhitelistAuthorizer createAuthorizer(Operation... operations) {
        Set<Operation> ops = new HashSet<>(Arrays.asList(operations));
        return new WhitelistAuthorizer(ops);
    }

    public void bad_case_14() {
        // WhitelistAuthorizer with operations from a builder pattern
        OperationSetBuilder builder = new OperationSetBuilder();
        Set<Operation> userOps = builder
            .add("ViewProfile")
            .add("EditProfile")
            .add("DeleteProfile")
            .build();
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer userAuthorizer = new WhitelistAuthorizer(userOps);
        userAuthorizer.authorize("user", "EditProfile");
    }
    
    class OperationSetBuilder {
        private Set<Operation> operations = new HashSet<>();
        
        public OperationSetBuilder add(String name) {
            operations.add(new Operation(name));
            return this;
        }
        
        public Set<Operation> build() {
            return operations;
        }
    }

    public void bad_case_15() {
        // WhitelistAuthorizer with operations from a stream
        Set<Operation> streamOps = Arrays.asList("SearchProducts", "ViewProduct", "PurchaseProduct")
            .stream()
            .map(Operation::new)
            .collect(java.util.stream.Collectors.toSet());
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer productAuthorizer = new WhitelistAuthorizer(streamOps);
        productAuthorizer.authorize("customer", "PurchaseProduct");
    }

    // True Negative Examples (Safe)

    public void good_case_1() {
        // Using WhitelistAuthorizer only for healthcheck operations
        Set<Operation> healthOps = new HashSet<>();
        healthOps.add(new Operation("HealthCheck"));
        healthOps.add(new Operation("PingService"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(healthOps);
        healthAuthorizer.authorize("monitor", "HealthCheck");
    }

    public void good_case_2() {
        // Using StrictAuthorizer for sensitive operations instead of WhitelistAuthorizer
        Set<Operation> sensitiveOps = new HashSet<>();
        sensitiveOps.add(new Operation("ViewPaymentHistory"));
        sensitiveOps.add(new Operation("ProcessPayment"));
        
        // ok: java-coral-whitelist-authorizer
        StrictAuthorizer authorizer = new StrictAuthorizer(sensitiveOps);
        authorizer.authorize("merchant", "ProcessPayment");
    }

    public void good_case_3() {
        // Using proper authorizer for admin operations
        Operation deleteUser = new Operation("DeleteUser");
        Operation createUser = new Operation("CreateUser");
        Set<Operation> adminOps = new HashSet<>(Arrays.asList(deleteUser, createUser));
        
        // ok: java-coral-whitelist-authorizer
        Authorizer adminAuthorizer = new StrictAuthorizer(adminOps);
        adminAuthorizer.authorize("admin", "DeleteUser");
    }

    public void good_case_4() {
        // Using WhitelistAuthorizer for only health operations and StrictAuthorizer for others
        Set<Operation> healthOps = new HashSet<>();
        healthOps.add(new Operation("HealthCheck"));
        
        Set<Operation> fileOps = new HashSet<>();
        fileOps.add(new Operation("ReadFile"));
        fileOps.add(new Operation("WriteFile"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(healthOps);
        StrictAuthorizer fileAuthorizer = new StrictAuthorizer(fileOps);
        
        healthAuthorizer.authorize("monitor", "HealthCheck");
        fileAuthorizer.authorize("user", "WriteFile");
    }

    public void good_case_5() {
        // Using empty set with WhitelistAuthorizer (no operations allowed)
        Set<Operation> emptySet = Collections.emptySet();
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer emptyAuthorizer = new WhitelistAuthorizer(emptySet);
        // This will deny all operations since the set is empty
        boolean isAuthorized = emptyAuthorizer.authorize("user", "AnyOperation");
        assert(!isAuthorized);
    }

    public void good_case_6() {
        // Using WhitelistAuthorizer with only monitoring operations
        Set<Operation> monitoringOps = new HashSet<>();
        monitoringOps.add(new Operation("HealthCheck"));
        monitoringOps.add(new Operation("ServiceStatus"));
        monitoringOps.add(new Operation("MetricsCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer monitoringAuthorizer = new WhitelistAuthorizer(monitoringOps);
        monitoringAuthorizer.authorize("monitor", "ServiceStatus");
    }

    public void good_case_7() {
        // Using appropriate authorizers for different operation types
        Set<Operation> healthOps = new HashSet<>();
        healthOps.add(new Operation("HealthCheck"));
        
        Set<Operation> userOps = new HashSet<>();
        userOps.add(new Operation("UserProfile"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(healthOps);
        StrictAuthorizer userAuthorizer = new StrictAuthorizer(userOps);
        
        if (isHealthOperation("HealthCheck")) {
            healthAuthorizer.authorize("system", "HealthCheck");
        } else {
            userAuthorizer.authorize("user", "UserProfile");
        }
    }
    
    private boolean isHealthOperation(String operation) {
        return operation.equals("HealthCheck") || operation.equals("ServiceStatus");
    }

    public void good_case_8() {
        // Using WhitelistAuthorizer for diagnostic operations only
        Set<Operation> diagnosticOps = new HashSet<>();
        diagnosticOps.add(new Operation("HealthCheck"));
        diagnosticOps.add(new Operation("DiagnosticCheck"));
        diagnosticOps.add(new Operation("SystemStatus"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer diagnosticAuthorizer = new WhitelistAuthorizer(diagnosticOps);
        diagnosticAuthorizer.authorize("system", "DiagnosticCheck");
    }

    public void good_case_9() {
        // Using factory method to create appropriate authorizer based on operation type
        Set<Operation> healthOps = new HashSet<>();
        healthOps.add(new Operation("HealthCheck"));
        
        Set<Operation> adminOps = new HashSet<>();
        adminOps.add(new Operation("AdminOperation"));
        
        String operationType = "HealthCheck";
        
        // ok: java-coral-whitelist-authorizer
        Authorizer authorizer = createAppropriateAuthorizer(operationType, healthOps, adminOps);
        authorizer.authorize("user", operationType);
    }
    
    private Authorizer createAppropriateAuthorizer(String operationType, 
                                                  Set<Operation> healthOps, 
                                                  Set<Operation> adminOps) {
        if (healthOps.contains(new Operation(operationType))) {
            return new WhitelistAuthorizer(healthOps);
        } else {
            return new StrictAuthorizer(adminOps);
        }
    }

    public void good_case_10() {
        // Using WhitelistAuthorizer with singleton health operation
        Operation healthCheck = new Operation("HealthCheck");
        Set<Operation> singletonSet = Collections.singleton(healthCheck);
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(singletonSet);
        healthAuthorizer.authorize("monitor", "HealthCheck");
    }

    public void good_case_11() {
        // Using WhitelistAuthorizer in a Lambda function handler for health checks only
        class HealthCheckHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
            private final WhitelistAuthorizer authorizer;
            
            public HealthCheckHandler() {
                Set<Operation> healthOps = new HashSet<>();
                healthOps.add(new Operation("HealthCheck"));
                
                // ok: java-coral-whitelist-authorizer
                this.authorizer = new WhitelistAuthorizer(healthOps);
            }
            
            @Override
            public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
                boolean isAuthorized = authorizer.authorize("system", "HealthCheck");
                
                APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
                if (isAuthorized) {
                    response.setStatusCode(200);
                    response.setBody("{\"status\":\"healthy\"}");
                } else {
                    response.setStatusCode(403);
                }
                return response;
            }
        }
        
        new HealthCheckHandler();
    }

    public void good_case_12() {
        // Using WhitelistAuthorizer with operations filtered to only include health checks
        Set<Operation> allOps = new HashSet<>();
        allOps.add(new Operation("HealthCheck"));
        allOps.add(new Operation("Status"));
        allOps.add(new Operation("AdminOperation"));
        
        Set<Operation> healthOpsOnly = allOps.stream()
            .filter(op -> op.getName().equals("HealthCheck") || op.getName().equals("Status"))
            .collect(java.util.stream.Collectors.toSet());
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(healthOpsOnly);
        healthAuthorizer.authorize("monitor", "Status");
    }

    public void good_case_13() {
        // Using WhitelistAuthorizer with operations from a health check configuration
        Set<Operation> healthOps = getHealthCheckOperations();
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(healthOps);
        healthAuthorizer.authorize("system", "SystemHealthCheck");
    }
    
    private Set<Operation> getHealthCheckOperations() {
        // This would typically load health check operations from configuration
        Set<Operation> ops = new HashSet<>();
        ops.add(new Operation("SystemHealthCheck"));
        ops.add(new Operation("DatabaseHealthCheck"));
        return ops;
    }

    public void good_case_14() {
        // Using WhitelistAuthorizer with immutable set of health operations
        Set<Operation> mutableHealthOps = new HashSet<>();
        mutableHealthOps.add(new Operation("HealthCheck"));
        mutableHealthOps.add(new Operation("PingService"));
        
        Set<Operation> immutableHealthOps = Collections.unmodifiableSet(mutableHealthOps);
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthAuthorizer = new WhitelistAuthorizer(immutableHealthOps);
        healthAuthorizer.authorize("monitor", "PingService");
    }

    public void good_case_15() {
        // Using WhitelistAuthorizer with health operations in a microservice architecture
        class HealthService {
            private final WhitelistAuthorizer authorizer;
            
            public HealthService() {
                Set<Operation> healthOps = new HashSet<>();
                healthOps.add(new Operation("ServiceHealthCheck"));
                healthOps.add(new Operation("DependencyHealthCheck"));
                
                // ok: java-coral-whitelist-authorizer
                this.authorizer = new WhitelistAuthorizer(healthOps);
            }
            
            public String checkHealth(String user, String operation) {
                if (authorizer.authorize(user, operation)) {
                    return "Service is healthy";
                }
                return "Unauthorized";
            }
        }
        
        HealthService service = new HealthService();
        service.checkHealth("monitor", "ServiceHealthCheck");
    }
}
// {/fact}