import * as cdk from '@aws-cdk/core';

import * as customResources from '@aws-cdk/custom-resources';
import * as iam from '@aws-cdk/aws-iam';

import {AccessPoint} from './access-point';
import type {AccessPointProps} from './access-point';

export interface ObjectAccessPointProps extends AccessPointProps {
    readonly key: string;

    readonly policyStatements: iam.PolicyStatement[];
}

export class ObjectAccessPoint extends AccessPoint {
    public readonly key: string;

    public constructor(scope: cdk.Construct, id: string, props: ObjectAccessPointProps) {
        props.policyStatements.forEach((v) => {
            if (v.hasResource) throw new Error('Customized resource is not supported by object Access Points.');
        });

        super(scope, id, props);

        props.policyStatements.forEach((v) => {
            v.addResources(`${this.arn}/object/${props.key}`);
        });

        const sdkCall: customResources.AwsSdkCall = {
            service:    'S3Control',
            action:     'putAccessPointPolicy',
            parameters: {
                /* eslint-disable @typescript-eslint/naming-convention */
                AccountId: cdk.Stack.of(this).account,
                Name:      this.name,
                Policy:    JSON.stringify(new iam.PolicyDocument({statements: props.policyStatements})),
                /* eslint-enable @typescript-eslint/naming-convention */
            },
            physicalResourceId: customResources.PhysicalResourceId.of(this.node.addr),
        };

        // eslint-disable-next-line no-new
        new customResources.AwsCustomResource(this, 'policy', {
            resourceType: 'Custom::S3Control-putAccessPointPolicy',
            onCreate:     sdkCall,
            onUpdate:     sdkCall,
            policy:       customResources.AwsCustomResourcePolicy.fromStatements([
                new iam.PolicyStatement({
                    effect:  iam.Effect.ALLOW,
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
