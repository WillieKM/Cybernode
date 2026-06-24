function escapeHtml(str){
return String(str ?? '')
.replace(/&/g, "&amp;")
.replace(/</g, "&lt;")
.replace(/>/g, "&gt;")
.replace(/"/g, "&quot;")
.replace(/'/g, "&#39;")
}

let scans = JSON.parse(localStorage.getItem("scans") || "[]")

scans.forEach(scan=>{

let row = document.createElement("tr")

row.innerHTML=`
<td>${escapeHtml(scan.domain)}</td>
<td>${escapeHtml(scan.score)}</td>
<td>${scan.score>85?"Low":"Moderate"}</td>
<td>${escapeHtml(scan.date)}</td>
`

document.querySelector("table").appendChild(row)

})
