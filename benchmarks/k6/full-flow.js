import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics.
const discoveryLatency = new Trend('discovery_latency', true);
const jwksLatency = new Trend('jwks_latency', true);
const tokenLatency = new Trend('token_latency', true);
const introspectLatency = new Trend('introspect_latency', true);
const flowSuccess = new Rate('flow_success');

// Test configuration.
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'load-test-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'load-test-secret';

export const options = {
    scenarios: {
        full_flow: {
            executor: 'ramping-vus',
            startVUs: 1,
            stages: [
                { duration: '20s', target: 20 },
                { duration: '1m', target: 20 },
                { duration: '20s', target: 50 },
                { duration: '1m', target: 50 },
                { duration: '20s', target: 0 },
            ],
        },
    },
    thresholds: {
        'discovery_latency': ['p(50)<1', 'p(99)<5'],
        'jwks_latency': ['p(50)<1', 'p(99)<5'],
        'token_latency': ['p(50)<5', 'p(99)<20'],
        'introspect_latency': ['p(50)<2', 'p(99)<10'],
        'flow_success': ['rate>0.95'],
    },
};

export default function () {
    let allPassed = true;

    // Step 1: Discovery.
    group('discovery', () => {
        const res = http.get(`${BASE_URL}/.well-known/openid-configuration`);
        discoveryLatency.add(res.timings.duration);

        const ok = check(res, {
            'discovery: status 200': (r) => r.status === 200,
            'discovery: has issuer': (r) => {
                try {
                    return JSON.parse(r.body).issuer !== undefined;
                } catch (e) {
                    return false;
                }
            },
        });
        if (!ok) allPassed = false;
    });

    // Step 2: JWKS.
    group('jwks', () => {
        const res = http.get(`${BASE_URL}/.well-known/jwks.json`);
        jwksLatency.add(res.timings.duration);

        const ok = check(res, {
            'jwks: status 200': (r) => r.status === 200,
            'jwks: has keys': (r) => {
                try {
                    return JSON.parse(r.body).keys.length > 0;
                } catch (e) {
                    return false;
                }
            },
        });
        if (!ok) allPassed = false;
    });

    // Step 3: Token issuance (client_credentials).
    let accessToken = '';
    group('token', () => {
        const payload = [
            `grant_type=client_credentials`,
            `client_id=${encodeURIComponent(CLIENT_ID)}`,
            `client_secret=${encodeURIComponent(CLIENT_SECRET)}`,
            `scope=openid`,
        ].join('&');

        const res = http.post(`${BASE_URL}/token`, payload, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        tokenLatency.add(res.timings.duration);

        const ok = check(res, {
            'token: status 200': (r) => r.status === 200,
            'token: has access_token': (r) => {
                try {
                    const body = JSON.parse(r.body);
                    accessToken = body.access_token || '';
                    return accessToken !== '';
                } catch (e) {
                    return false;
                }
            },
        });
        if (!ok) allPassed = false;
    });

    // Step 4: Token introspection.
    if (accessToken) {
        group('introspect', () => {
            const basicAuth = `${CLIENT_ID}:${CLIENT_SECRET}`;
            const encoded = __ENV.K6_NO_BTOA
                ? basicAuth
                : encoding.b64encode(basicAuth);

            const payload = `token=${encodeURIComponent(accessToken)}`;

            const res = http.post(`${BASE_URL}/introspect`, payload, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${encoded}`,
                },
            });
            introspectLatency.add(res.timings.duration);

            const ok = check(res, {
                'introspect: status 200': (r) => r.status === 200,
                'introspect: active true': (r) => {
                    try {
                        return JSON.parse(r.body).active === true;
                    } catch (e) {
                        return false;
                    }
                },
            });
            if (!ok) allPassed = false;
        });
    }

    flowSuccess.add(allPassed);
    sleep(0.05); // 50ms think time
}
