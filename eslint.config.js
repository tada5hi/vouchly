import config from '@tada5hi/eslint-config';

export default [
    ...await config(),
    { ignores: ['dist/**'] },
    // Promise.try requires Node 24; this package supports Node 22. Preserve support for Node 22 and existing browsers.
    {
        rules: {
            'unicorn/prefer-promise-try': 'off',
            'unicorn/prefer-uint8array-base64': 'off',
        },
    },
    // Preserve the published Node 20/22 runtime floor.
    { rules: { 'unicorn/prefer-error-is-error': 'off' } },
];
