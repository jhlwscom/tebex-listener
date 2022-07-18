const express = require('express')
const crypto = require('crypto'); // for validating webhook hashes
const promClient = require('prom-client'); // core prometheus client
const promBundle = require('express-prom-bundle'); // express specific metrics
const app = express()
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET;

if (SECRET === undefined) {
    console.log("secret not provided")
    process.exit(1)
}

/// prometheus
const bundle = promBundle({
    includeMethod: true,
    includeStatusCode: true,
    includeUp: true,
    promClient: {
        collectDefaultMetrics: {
        }
    }
});

app.use(bundle);

/// express (webHook processing)
app.use(express.json());

app.listen(PORT, () => {
    console.log("listening: " + PORT)
})

function hashTebex(body) {
    return crypto
        .createHash('sha256')
        .update(SECRET + body['payment']['txn_id'] + body['payment']['status'] + body['customer']['email'])
        .digest('hex')
}

app.get("/", (req, res) => {
    res.status(200).end();
})

app.post("/", (req, res) => {
    let suppliedHash = req.header("X-BC-Sig")
    if (!suppliedHash) {
        console.log("ignoring hook with no hash")
        res.status(400).end();
        return;
    }
    if (suppliedHash != hashTebex(req.body)) {
        console.log("ignoring hook with bad hash")
        res.status(400).end();
        return;
    }
    console.log(JSON.stringify(req.body));
    res.status(200).end();
});

app.post("/v1/events", (req, res) => {
    console.log(JSON.stringify({
        "body": req.body,
        "params": req.params,
        "headers": req.headers
    }));

    res.status(200).end();
});
