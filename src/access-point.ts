import type {
    aws_ec2 as cdkEc2,
    aws_iam as cdkIam,
} from 'aws-cdk-lib';
import {
    Construct as AwsConstruct,
} from 'constructs';
import {
    aws_s3 as cdkS3,
} from 'aws-cdk-lib';

export enum NetworkOrigin {
    VPC = 'VPC',
    INTERNET = 'Internet',
}

export interface AccessPointProps {
    readonly bucket: cdkS3.IBucket;

    readonly policy?: cdkIam.PolicyDocument;

    readonly publicAccessBlockConfiguration?: cdkS3.CfnAccessPoint.PublicAccessBlockConfigurationProperty;

    readonly vpc?: cdkEc2.IVpc;
}

export class AccessPoint extends AwsConstruct {
    public readonly name: string;

    public readonly arn: string;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public readonly policyStatementCondition: Record<string, any>;

    public readonly networkOrigin: NetworkOrigin;

    public constructor(scope: AwsConstruct, id: string, props: AccessPointProps) {
        super(scope, id);

        const accessPoint = new cdkS3.CfnAccessPoint(this, 'access-point', {
            bucket:                         props.bucket.bucketName,
            policy:                         JSON.stringify(props.policy),
            publicAccessBlockConfiguration: props.publicAccessBlockConfiguration,
            vpcConfiguration:               {vpcId: props.vpc?.vpcId},
        });
        this.name = accessPoint.attrName;
        this.arn = accessPoint.attrArn;

        this.policyStatementCondition = {
            /* eslint-disable @typescript-eslint/naming-convention */
            StringEquals: {
                's3:DataAccessPointArn': accessPoint.attrArn,
            },
            /* eslint-enable @typescript-eslint/naming-convention */
        };

        this.networkOrigin = props.vpc ? NetworkOrigin.VPC : NetworkOrigin.INTERNET;
    }
}
