import * as cdk from '@aws-cdk/core';

import type * as ec2 from '@aws-cdk/aws-ec2';
import type * as iam from '@aws-cdk/aws-iam';
import * as s3 from '@aws-cdk/aws-s3';

export enum NetworkOrigin{
    VPC = 'VPC',
    INTERNET = 'Internet',
}

export interface AccessPointProps {
    readonly bucket: s3.IBucket;

    readonly name?: string;

    readonly policy?: iam.PolicyDocument;

    readonly publicAccessBlockConfiguration?: s3.CfnAccessPoint.PublicAccessBlockConfigurationProperty;

    readonly vpc?: ec2.IVpc;
}

export class AccessPoint extends cdk.Construct {
    public readonly name: string;

    public readonly arn: string;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public readonly policyStatementCondition: Record<string, any>;

    public readonly networkOrigin: NetworkOrigin;

    public constructor(scope: cdk.Construct, id: string, props: AccessPointProps) {
        super(scope, id);

        const accessPoint = new s3.CfnAccessPoint(this, 'access-point', {
            bucket:                         props.bucket.bucketName,
            name:                           props.name,
            policy:                         JSON.stringify(props.policy),
            publicAccessBlockConfiguration: props.publicAccessBlockConfiguration,
            vpcConfiguration:               {vpcId: props.vpc?.vpcId},
        });

        this.name = props.name ?? accessPoint.ref;

        this.arn = cdk.Arn.format({
            service:      's3',
            resource:     'accesspoint',
            resourceName: this.name,
        }, cdk.Stack.of(this));

        this.policyStatementCondition = {
            /* eslint-disable @typescript-eslint/naming-convention */
            StringEquals: {
                's3:DataAccessPointArn': this.arn,
            },
            /* eslint-enable @typescript-eslint/naming-convention */
        };

        this.networkOrigin = props.vpc ? NetworkOrigin.VPC : NetworkOrigin.INTERNET;
    }
}