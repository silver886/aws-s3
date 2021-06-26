import * as path from 'path';
import type * as webpack from 'webpack';

const CONFIG: webpack.Configuration = {
    mode:   'production',
    entry:  path.resolve('./src/index.ts'),
    output: {
        path:     path.resolve('./dist'),
        filename: 'bundle.js',
    },
    module: {
        rules: [{
            use:     'ts-loader',
            exclude: /node_modules/u,
        }],
    },
    resolve: {
        modules: [
            path.resolve('node_modules'),
            path.resolve('../../../../lambda/jenkins'),
        ],
        preferRelative: true,
        extensions:     ['.ts', '.js'],
        fallback:       {
            stream:  false,
            https:   false,
            process: false,
        },
    },
};

export default CONFIG;
