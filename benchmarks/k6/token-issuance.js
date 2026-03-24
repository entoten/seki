import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics.
const tokenLatency = new Trend('token_latency', true);
const tokenSuccess = new Rate('token_success');

// Test configuration.
// Override BASE_URL via environment: k6 run -e BASE_URL=http://localhost:8080 token-issuance.js
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'load-test-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'load-test-secret';

export const options = {
    scenarios: {
        // Ramp-up load test.
        ramp_up: {
            executor: 'ramping-vus',
            startVUs: 1,
            stages: [
                { duration: '30s', target: 50 },   // ramp up to 50 VUs
                { duration: '1m', target: 50 },     // hold at 50 VUs
                { duration: '30s', target: 100 },   // ramp up to 100 VUs
                { duration: '1m', target: 100 },    // hold at 100 VUs
                { duration: '30s', target: 0 },     // ramp down
            ],
        },
    },
    thresholds: {
        'token_latency': ['p(50)<5', 'p(99)<20'],   // p50 < 5ms, p99 < 20ms
        'token_success': ['rate>0.99'],               // 99% success rate
        'http_req_duration': ['p(95)<50'],             // overall p95 < 50ms
    },
};

export default function () {
    const payload = {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: 'openid',
    };

    const params = {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
    };

    // Build form-encoded body.
    const body = Object.entries(payload)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

    const res = http.post(`${BASE_URL}/token`, body, params);

    tokenLatency.add(res.timings.duration);

    const success = check(res, {
        'status is 200': (r) => r.status === 200,
        'has access_token': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.access_token !== undefined;
            } catch (e) {
                return false;
            }
        },
        'token_type is Bearer': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.token_type === 'Bearer';
            } catch (e) {
                return false;
            }
        },
    });

    tokenSuccess.add(success);

    sleep(0.01); // 10ms think time
}
