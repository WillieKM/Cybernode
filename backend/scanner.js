const express=require("express")
const cors=require("cors")
const axios=require("axios")

const app=express()

const ALLOWED_ORIGINS = ["https://www.cyber-node.com", "https://cyber-node.com"]
app.use(cors({ origin: ALLOWED_ORIGINS }))

const DOMAIN_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

app.get("/scan", async(req,res)=>{

let domain=req.query.domain

if (!domain || !DOMAIN_PATTERN.test(domain)) {
  return res.status(400).json({error:"Invalid domain"})
}

try{

let ssl="Detected"
let headers="Moderate"
let ports="80,443"

res.json({
domain:domain,
ssl:ssl,
headers:headers,
ports:ports
})

}

catch{

res.json({error:"Scan failed"})

}

})

app.get("/report",(req,res)=>{

let domain=req.query.domain

if (!domain || !DOMAIN_PATTERN.test(domain)) {
  return res.status(400).send("Invalid domain")
}

res.send(`

<h1>Cyber-Node Security Report</h1>

<p>Domain: ${escapeHtml(domain)}</p>

<p>SSL: Active</p>

<p>Headers: Needs Improvement</p>

<p>Open Ports: 80,443</p>

<p>Recommendation: Implement stronger security policies.</p>

`)

})

app.listen(3000,()=>{
console.log("Scanner API running on port 3000")
})
