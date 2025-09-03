import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

class OpenSearchExamples {
  // True positive examples (vulnerable code)
  
  public bad_case_1(scope: Construct) {
    // Creating an OpenSearch domain without dedicated master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'Domain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      }
    });
  }

  public bad_case_2(scope: Construct) {
    // Creating an OpenSearch domain with dedicated master nodes explicitly disabled
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'Domain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 5,
        masterNodes: 0
      }
    });
  }

  public bad_case_3(scope: Construct, vpc: ec2.Vpc) {
    // Creating a VPC-based OpenSearch domain without dedicated master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'VpcDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 3
      },
      vpc,
      vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }]
    });
  }

  public bad_case_4(scope: Construct) {
    // Creating an OpenSearch domain with minimal configuration
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'MinimalDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0
    });
  }

  public bad_case_5(scope: Construct) {
    // Creating an OpenSearch domain with only data node configuration
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'DataNodeOnlyDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodeInstanceType: 'r5.large.search',
        dataNodes: 4
      }
    });
  }

  public bad_case_6(scope: Construct) {
    // Creating an OpenSearch domain with advanced settings but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'AdvancedDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 3,
        warmNodes: 2,
        warmInstanceType: 'ultrawarm1.medium.search'
      },
      ebs: {
        volumeSize: 100
      }
    });
  }

  public bad_case_7(scope: Construct) {
    // Creating an OpenSearch domain with encryption but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'EncryptedDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      encryptionAtRest: {
        enabled: true
      },
      nodeToNodeEncryption: true
    });
  }

  public bad_case_8(scope: Construct) {
    // Creating an OpenSearch domain with fine-grained access control but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'FineGrainedDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      enforceHttps: true,
      fineGrainedAccessControl: {
        masterUserName: 'admin'
      }
    });
  }

  public bad_case_9(scope: Construct) {
    // Creating an OpenSearch domain with custom endpoint but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'CustomEndpointDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      customEndpoint: {
        domainName: 'search.example.com'
      }
    });
  }

  public bad_case_10(scope: Construct) {
    // Creating an OpenSearch domain with zone awareness but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'ZoneAwarenessDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 4
      },
      zoneAwareness: {
        enabled: true
      }
    });
  }

  public bad_case_11(scope: Construct) {
    // Creating an OpenSearch domain with logging but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'LoggingDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      logging: {
        slowSearchLogEnabled: true,
        appLogEnabled: true
      }
    });
  }

  public bad_case_12(scope: Construct) {
    // Creating an OpenSearch domain with advanced options but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'AdvancedOptionsDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      advancedOptions: {
        'rest.action.multi.allow_explicit_index': 'true'
      }
    });
  }

  public bad_case_13(scope: Construct) {
    // Creating an OpenSearch domain with UltraWarm but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'UltraWarmDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        warmEnabled: true,
        warmCount: 2
      }
    });
  }

  public bad_case_14(scope: Construct) {
    // Creating an OpenSearch domain with SAML authentication but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SamlDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      advancedSecurityOptions: {
        samlOptions: {
          enabled: true,
          idpEntityId: 'entity-id',
          idpMetadataContent: 'metadata-content'
        }
      }
    });
  }

  public bad_case_15(scope: Construct) {
    // Creating an OpenSearch domain with cognito authentication but no master nodes
    // ruleid: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'CognitoDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2
      },
      cognitoDashboardsAuth: {
        identityPoolId: 'identity-pool-id',
        userPoolId: 'user-pool-id',
        role: new cdk.aws_iam.Role(scope, 'CognitoRole', {
          assumedBy: new cdk.aws_iam.ServicePrincipal('opensearchservice.amazonaws.com')
        })
      }
    });
  }

  // True negative examples (secure code)
  
  public good_case_1(scope: Construct) {
    // Creating an OpenSearch domain with dedicated master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      }
    });
  }

  public good_case_2(scope: Construct) {
    // Creating an OpenSearch domain with dedicated master nodes and instance type
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureDomainWithInstanceType', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 5,
        masterNodes: 3,
        masterNodeInstanceType: 'r5.large.search'
      }
    });
  }

  public good_case_3(scope: Construct, vpc: ec2.Vpc) {
    // Creating a VPC-based OpenSearch domain with dedicated master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureVpcDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 3,
        masterNodes: 3
      },
      vpc,
      vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }]
    });
  }

  public good_case_4(scope: Construct) {
    // Creating an OpenSearch domain with minimal configuration but with master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureMinimalDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        masterNodes: 3
      }
    });
  }

  public good_case_5(scope: Construct) {
    // Creating an OpenSearch domain with both data and master node configuration
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureDataAndMasterDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodeInstanceType: 'r5.large.search',
        dataNodes: 4,
        masterNodeInstanceType: 'r5.large.search',
        masterNodes: 3
      }
    });
  }

  public good_case_6(scope: Construct) {
    // Creating an OpenSearch domain with advanced settings and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureAdvancedDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 3,
        masterNodes: 3,
        warmNodes: 2,
        warmInstanceType: 'ultrawarm1.medium.search'
      },
      ebs: {
        volumeSize: 100
      }
    });
  }

  public good_case_7(scope: Construct) {
    // Creating an OpenSearch domain with encryption and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureEncryptedDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      },
      encryptionAtRest: {
        enabled: true
      },
      nodeToNodeEncryption: true
    });
  }

  public good_case_8(scope: Construct) {
    // Creating an OpenSearch domain with fine-grained access control and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureFineGrainedDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      },
      enforceHttps: true,
      fineGrainedAccessControl: {
        masterUserName: 'admin'
      }
    });
  }

  public good_case_9(scope: Construct) {
    // Creating an OpenSearch domain with custom endpoint and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureCustomEndpointDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      },
      customEndpoint: {
        domainName: 'search.example.com'
      }
    });
  }

  public good_case_10(scope: Construct) {
    // Creating an OpenSearch domain with zone awareness and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureZoneAwarenessDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 4,
        masterNodes: 3
      },
      zoneAwareness: {
        enabled: true
      }
    });
  }

  public good_case_11(scope: Construct) {
    // Creating an OpenSearch domain with logging and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureLoggingDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      },
      logging: {
        slowSearchLogEnabled: true,
        appLogEnabled: true
      }
    });
  }

  public good_case_12(scope: Construct) {
    // Creating an OpenSearch domain with advanced options and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureAdvancedOptionsDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      },
      advancedOptions: {
        'rest.action.multi.allow_explicit_index': 'true'
      }
    });
  }

  public good_case_13(scope: Construct) {
    // Creating an OpenSearch domain with UltraWarm and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureUltraWarmDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3,
        warmEnabled: true,
        warmCount: 2
      }
    });
  }

  public good_case_14(scope: Construct) {
    // Creating an OpenSearch domain with SAML authentication and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureSamlDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 5
      },
      advancedSecurityOptions: {
        samlOptions: {
          enabled: true,
          idpEntityId: 'entity-id',
          idpMetadataContent: 'metadata-content'
        }
      }
    });
  }

  public good_case_15(scope: Construct) {
    // Creating an OpenSearch domain with cognito authentication and master nodes
    // ok: typescript-cdk-open-search-dedicated-master-node
    const domain = new opensearch.Domain(scope, 'SecureCognitoDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        masterNodes: 3
      },
      cognitoDashboardsAuth: {
        identityPoolId: 'identity-pool-id',
        userPoolId: 'user-pool-id',
        role: new cdk.aws_iam.Role(scope, 'CognitoRole', {
          assumedBy: new cdk.aws_iam.ServicePrincipal('opensearchservice.amazonaws.com')
        })
      }
    });
  }
}