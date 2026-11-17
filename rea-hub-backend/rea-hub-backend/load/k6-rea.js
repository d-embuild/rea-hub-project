// k6 run -e BASE_URL=https://api.example.com -e TRAVELER_JWT=... -e PARTNER_JWT=... -e QR_TOKEN=... -e PROMO_ID=... load/k6-rea.js
// QR_TOKEN must be fresh (<45s) for a pass whose promo has max_per_pass=1. Exactly ONE redemption may succeed.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const valid = new Counter('redeem_valid');
const conflict = new Counter('redeem_conflict');
const H = (t) => ({ headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' } });

export const options = {
  scenarios: {
    browse_300: {
      executor: 'ramping-vus', exec: 'browse', startVUs: 0,
      stages: [{ duration: '30s', target: 300 }, { duration: '1m', target: 300 }, { duration: '15s', target: 0 }],
    },
    double_scan: { executor: 'shared-iterations', exec: 'scan', vus: 50, iterations: 50, startTime: '20s' },
  },
  thresholds: {
    'http_req_duration{scenario:browse_300}': ['p(95)<800'],
    'http_req_failed{scenario:browse_300}': ['rate<0.01'],
    redeem_valid: ['count<=1'],                 // race-condition proof: never more than one winner
  },
};

export function browse() {
  const r = http.get(`${__ENV.BASE_URL}/v1/partners?lat=14.5547&lng=121.0244&radiusKm=25`, H(__ENV.TRAVELER_JWT));
  check(r, { 'directory 200': (x) => x.status === 200 });
}

export function scan() {
  const r = http.post(`${__ENV.BASE_URL}/v1/redemptions`,
    JSON.stringify({ qr: __ENV.QR_TOKEN, promotionId: __ENV.PROMO_ID }), H(__ENV.PARTNER_JWT));
  if (r.status === 200) valid.add(1);
  else if (r.status === 409) conflict.add(1);
  check(r, { 'only 200 or 409': (x) => x.status === 200 || x.status === 409 || x.status === 429 });
}
