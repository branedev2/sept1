import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

// True Positive Examples (vulnerable/insecure code that MUST be detected)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'MyTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    // Using default billing mode which is PROVISIONED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'UserTable', {
    partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'timestamp', type: dynamodb.AttributeType.NUMBER },
    billingMode: dynamodb.BillingMode.PROVISIONED,
    readCapacity: 5,
    writeCapacity: 5,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const stack = new cdk.Stack();
  const app = new cdk.App();
  
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript-cdk-aws-dynamodb-billing-mode
      const table = new dynamodb.Table(this, 'ProductCatalog', {
        partitionKey: { name: 'productId', type: dynamodb.AttributeType.STRING },
        billingMode: dynamodb.BillingMode.PROVISIONED,
        readCapacity: 10,
        writeCapacity: 5,
      });
    }
  }
  
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  const table = new dynamodb.Table(stack, 'OrdersTable', {
    partitionKey: { name: 'orderId', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'customerId', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PROVISIONED,
    readCapacity: 20,
    writeCapacity: 10,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  const billingModeType = dynamodb.BillingMode.PROVISIONED;
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'EventsTable', {
    partitionKey: { name: 'eventId', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'eventDate', type: dynamodb.AttributeType.STRING },
    billingMode: billingModeType,
    readCapacity: 15,
    writeCapacity: 10,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const stack = new cdk.Stack();
  
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript-cdk-aws-dynamodb-billing-mode
    new dynamodb.Table(stack, `RegionTable-${i}`, {
      partitionKey: { name: 'regionId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PROVISIONED,
      readCapacity: 5,
      writeCapacity: 5,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const stack = new cdk.Stack();
  const tableProps = {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PROVISIONED,
    readCapacity: 5,
    writeCapacity: 5,
  };
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'ConfigTable', tableProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript-cdk-aws-dynamodb-billing-mode
      const logsTable = new dynamodb.Table(this, 'LogsTable', {
        partitionKey: { name: 'logId', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'timestamp', type: dynamodb.AttributeType.NUMBER },
        billingMode: dynamodb.BillingMode.PROVISIONED,
        readCapacity: 10,
        writeCapacity: 10,
        timeToLiveAttribute: 'expiryTime',
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  
  if (process.env.NODE_ENV === 'production') {
    // ruleid: typescript-cdk-aws-dynamodb-billing-mode
    new dynamodb.Table(stack, 'HighTrafficTable', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PROVISIONED,
      readCapacity: 100,
      writeCapacity: 50,
    });
  } else {
    // This would also be detected, but we're focusing on the production case
    new dynamodb.Table(stack, 'LowTrafficTable', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PROVISIONED,
      readCapacity: 5,
      writeCapacity: 5,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const stack = new cdk.Stack();
  
  function createTable(tableName: string) {
    // ruleid: typescript-cdk-aws-dynamodb-billing-mode
    return new dynamodb.Table(stack, tableName, {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PROVISIONED,
      readCapacity: 5,
      writeCapacity: 5,
    });
  }
  
  const usersTable = createTable('UsersTable');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  const tableParams = {
    tableName: 'AnalyticsTable',
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
  };
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, tableParams.tableName, {
    ...tableParams,
    billingMode: dynamodb.BillingMode.PROVISIONED,
    readCapacity: 10,
    writeCapacity: 10,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  const table = new dynamodb.Table(stack, 'GlobalTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PROVISIONED,
    readCapacity: 10,
    writeCapacity: 10,
    replicationRegions: ['us-east-2', 'us-west-2'],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  const table = new dynamodb.Table(stack, 'BackupTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PROVISIONED,
    readCapacity: 5,
    writeCapacity: 5,
    pointInTimeRecovery: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  const billingModes = [dynamodb.BillingMode.PROVISIONED, dynamodb.BillingMode.PAY_PER_REQUEST];
  const selectedMode = billingModes[0]; // Selecting PROVISIONED
  
  // ruleid: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'DynamicTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: selectedMode,
    readCapacity: 5,
    writeCapacity: 5,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  
  class TableFactory {
    static createTable(id: string) {
      // ruleid: typescript-cdk-aws-dynamodb-billing-mode
      return new dynamodb.Table(stack, id, {
        partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
        billingMode: dynamodb.BillingMode.PROVISIONED,
        readCapacity: 5,
        writeCapacity: 5,
      });
    }
  }
  
  const table = TableFactory.createTable('FactoryCreatedTable');
}
// {/fact}

// True Negative Examples (safe/secure code that MUST NOT be detected)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'MyTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'UserTable', {
    partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'timestamp', type: dynamodb.AttributeType.NUMBER },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const stack = new cdk.Stack();
  const app = new cdk.App();
  
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ok: typescript-cdk-aws-dynamodb-billing-mode
      const table = new dynamodb.Table(this, 'ProductCatalog', {
        partitionKey: { name: 'productId', type: dynamodb.AttributeType.STRING },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      });
    }
  }
  
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  const table = new dynamodb.Table(stack, 'OrdersTable', {
    partitionKey: { name: 'orderId', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'customerId', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  const billingModeType = dynamodb.BillingMode.PAY_PER_REQUEST;
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'EventsTable', {
    partitionKey: { name: 'eventId', type: dynamodb.AttributeType.STRING },
    sortKey: { name: 'eventDate', type: dynamodb.AttributeType.STRING },
    billingMode: billingModeType,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const stack = new cdk.Stack();
  
  for (let i = 0; i < 3; i++) {
    // ok: typescript-cdk-aws-dynamodb-billing-mode
    new dynamodb.Table(stack, `RegionTable-${i}`, {
      partitionKey: { name: 'regionId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const stack = new cdk.Stack();
  const tableProps = {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  };
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'ConfigTable', tableProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript-cdk-aws-dynamodb-billing-mode
      const logsTable = new dynamodb.Table(this, 'LogsTable', {
        partitionKey: { name: 'logId', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'timestamp', type: dynamodb.AttributeType.NUMBER },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        timeToLiveAttribute: 'expiryTime',
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  
  if (process.env.NODE_ENV === 'production') {
    // ok: typescript-cdk-aws-dynamodb-billing-mode
    new dynamodb.Table(stack, 'HighTrafficTable', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    });
  } else {
    new dynamodb.Table(stack, 'LowTrafficTable', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  function createTable(tableName: string) {
    // ok: typescript-cdk-aws-dynamodb-billing-mode
    return new dynamodb.Table(stack, tableName, {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    });
  }
  
  const usersTable = createTable('UsersTable');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  const tableParams = {
    tableName: 'AnalyticsTable',
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
  };
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, tableParams.tableName, {
    ...tableParams,
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  const table = new dynamodb.Table(stack, 'GlobalTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    replicationRegions: ['us-east-2', 'us-west-2'],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  const table = new dynamodb.Table(stack, 'BackupTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    pointInTimeRecovery: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  const billingModes = [dynamodb.BillingMode.PROVISIONED, dynamodb.BillingMode.PAY_PER_REQUEST];
  const selectedMode = billingModes[1]; // Selecting PAY_PER_REQUEST
  
  // ok: typescript-cdk-aws-dynamodb-billing-mode
  new dynamodb.Table(stack, 'DynamicTable', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: selectedMode,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  
  class TableFactory {
    static createTable(id: string) {
      // ok: typescript-cdk-aws-dynamodb-billing-mode
      return new dynamodb.Table(stack, id, {
        partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      });
    }
  }
  
  const table = TableFactory.createTable('FactoryCreatedTable');
}
// {/fact}