import {
    Stack as CdkStack,
    custom_resources as cdkCustomResources,
    aws_iam as cdkIam,
} from 'aws-cdk-lib';
import type {
    Construct as AwsConstruct,
} from 'constructs';

import {AccessPoint} from './access-point';
import type {AccessPointProps} from './access-point';

export interface ObjectAccessPointProps extends AccessPointProps {
    readonly key: string;

    readonly policyStatements: cdkIam.PolicyStatement[];
}

export class ObjectAccessPoint extends AccessPoint {
    public readonly key: string;

    public constructor(scope: AwsConstruct, id: string, props: ObjectAccessPointProps) {
        props.policyStatements.forEach((v) => {
            if (v.hasResource) throw new Error('Customized resource is not supported by object Access Points.');
        });

        super(scope, id, props);

        props.policyStatements.forEach((v) => {
            v.addResources(`${this.arn}/object/${props.key}`);
        });

        const sdkCall: cdkCustomResources.AwsSdkCall = {
            service:    'S3Control',
            action:     'putAccessPointPolicy',
            parameters: {
                /* eslint-disable @typescript-eslint/naming-convention */
                AccountId: CdkStack.of(this).account,
                Name:      this.name,
                Policy:    JSON.stringify(new cdkIam.PolicyDocument({statements: props.policyStatements})),
                /* eslint-enable @typescript-eslint/naming-convention */
            },
            physicalResourceId: cdkCustomResources.PhysicalResourceId.of(this.node.addr),
        };

        // eslint-disable-next-line no-new
        new cdkCustomResources.AwsCustomResource(this, 'policy', {
            resourceType: 'Custom::S3Control-putAccessPointPolicy',
            onCreate:     sdkCall,
            onUpdate:     sdkCall,
            policy:       cdkCustomResources.AwsCustomResourcePolicy.fromStatements([
                new cdkIam.PolicyStatement({
                    effect:  cdkIam.Effect.ALLOW,
                    actions: [
                        's3:PutAccessPointPolicy',
                    ],
                    resources: [
                        this.arn,
                    ],
                }),
            ]),
        });

        this.key = props.key;
    }
}
