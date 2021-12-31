import {
    aws_ec2 as cdkEc2,
} from 'aws-cdk-lib';

import * as file from '../file/';

export function service(config: file.clam.Config): cdkEc2.InitConfig {
    const handle = new cdkEc2.InitServiceRestartHandle();
    return new cdkEc2.InitConfig([
        cdkEc2.InitPackage.yum('clamd'),
        cdkEc2.InitPackage.yum('clamav'),
        cdkEc2.InitPackage.yum('clamav-update'),
        cdkEc2.InitPackage.yum('ruby'),
        cdkEc2.InitPackage.rubyGem('aws-sdk-sqs', {
            version: ['1.23.1'],
        }),
        cdkEc2.InitPackage.rubyGem('aws-sdk-sns', {
            version: ['1.20.0'],
        }),
        cdkEc2.InitPackage.rubyGem('aws-sdk-s3', {
            version: ['1.54.0'],
        }),
        cdkEc2.InitPackage.rubyGem('daemons', {
            version: ['1.3.1'],
        }),
        cdkEc2.InitPackage.rubyGem('rubysl-securerandom', {
            version: ['2.0.0'],
        }),
        file.clam.daemon([handle]),
        file.clam.worker([handle]),
        file.clam.config(config, [handle]),
        file.clam.service([handle]),
        cdkEc2.InitCommand.shellCommand('sed -i "s/^FRESHCLAM_DELAY/#FRESHCLAM_DELAY/g" /etc/sysconfig/freshclam'),
        cdkEc2.InitCommand.shellCommand('sed -i "s/^Example/#Example/g" /etc/freshclam.conf'),
        cdkEc2.InitCommand.shellCommand('mkdir /var/run/clamd.scan && chown clamscan:clamscan /var/run/clamd.scan', {
            testCmd: '[ ! -d /var/run/clamd.scan ]',
        }),
        cdkEc2.InitCommand.shellCommand('sed -i "s/^Example/#Example/g;s/^#LocalSocket /LocalSocket /g" /etc/clamd.d/scan.conf'),
        cdkEc2.InitCommand.shellCommand('ln -s /etc/clamd.d/scan.conf /etc/clamd.conf', {
            testCmd: '[ ! -f /etc/clamd.conf ]',
        }),
        cdkEc2.InitCommand.shellCommand('freshclam'),
        cdkEc2.InitCommand.shellCommand('systemctl enable clamd@scan', {
            testCmd: '! systemctl is-enabled clamd@scan',
        }),
        cdkEc2.InitCommand.shellCommand('systemctl start clamd@scan', {
            testCmd: '! systemctl is-active clamd@scan',
        }),
        cdkEc2.InitService.enable('s3-virus-scan', {
            serviceRestartHandle: handle,
        }),
    ]);
}
