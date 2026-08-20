import { check } from "k6";
import exec from "k6/execution";
import http from "k6/http";

const rate = __ENV.RATE || 10000;
const vus = __ENV.VUS || 100;
const duration = __ENV.DURATION || "30s";

export const options = {
    scenarios: {
        load: {
            executor: "constant-arrival-rate",
            rate: rate,
            preAllocatedVUs: vus,
            duration: duration,
        },
    },
    discardResponseBodies: true,
};

export default function () {
    const k = exec.vu.iterationInInstance;
    var path;
    if (k % 4 === 0) {
        path = "/index.html";
    } else if (k % 4 === 1) {
        path = "/style.css";
    } else if (k % 4 === 2) {
        path = "/script.js";
    } else if (k % 4 === 3) {
        path = "/stripes.png";
    }

    const url = `http://localhost:8080${path}`;
    const res = http.get(url);
    let passed = check(res, {
        "status is 200": (r) => r.status === 200,
        "protocol is HTTP/1.1": (r) => r.proto === "HTTP/1.1",
    });

    return passed;
}
