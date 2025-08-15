const API = "/api";

async function addUser() {
    const uid = document.getElementById("uid").value;
    const days = parseInt(document.getElementById("days").value);
    const res = await fetch(`${API}/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid, days })
    });
    document.getElementById("output").innerText = await res.text();
}

async function removeUser() {
    const uid = document.getElementById("uid").value;
    const res = await fetch(`${API}/remove`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid })
    });
    document.getElementById("output").innerText = await res.text();
}

async function listUsers() {
    const res = await fetch(`${API}/list`);
    document.getElementById("output").innerText = await res.text();
}
