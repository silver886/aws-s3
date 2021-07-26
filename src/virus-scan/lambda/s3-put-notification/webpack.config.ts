import * as path from 'path';
import type * as webpack from 'webpack';

const CONFIG: webpack.Configuration = {
    mode:   'production',
    target: 'node14',
    entry:  path.resolve('./src/index.ts'),
    output: {
        path:          path.resolve('./dist'),
        filename:      'bundle.js',
        libraryTarget: 'commonjs',
    },
    module: {
        rules: [{
            test:    /\.tsx?$/u,
            loader:  'ts-loader',
            exclude: /node_modules|lib(?:\/|\\)lambda/u,
        }],
    },
    resolve: {
        extensions: ['.ts', '.js'],
    },
};

export default CONFIG;
