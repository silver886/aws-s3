import {
    App as CdkApp,
} from 'aws-cdk-lib';

import * as src from '../src/';

describe('Access Point', () => {
    // GIVEN
    const app = new CdkApp();

    // WHEN

    // THEN
    describe('should pass', () => {
        it('mock', () => {
            expect(true).toBeTruthy();
        });
    });
});
