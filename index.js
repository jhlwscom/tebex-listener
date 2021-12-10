const express = require('express')
const crypto = require('crypto'); // for validating webhook hashes
const promClient = require('prom-client'); // core prometheus client
const promBundle = require('express-prom-bundle'); // express specific metrics
const app = express()
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET;

if(SECRET === undefined){
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
        .update(body['payment']['txn_id'])
        .update(body['payment']['status'])
        .update(body['customer']['email'])
        .digest()
}

app.get("/", (req, res) =>{
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
    console.log(req.body);
    res.status(200).end();
});