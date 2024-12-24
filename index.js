const AuthService = require('./utils/auth.js');
const express = require('express');
require('dotenv').config();
const path = require("node:fs")
const server = express(); //Namespace for express call
const bcrypt = require('bcrypt');

let activeSessions = {};

const uri = 'mongodb://username:password@<your-host>:27017/AuthDatabase';
const options = {
    sslKey: fs.readFileSync('/crts/client.pem'),
    sslCert: fs.readFileSync('/crts/client.pem'),
    sslCA: fs.readFileSync('/ca/ca.crt')
};

const authService = new AuthService(uri, options);

function isAuth(req, res, next) {
    const sessionId = req.cookies?.sessionId;

    if (sessionId && activeSessions[sessionId]) {
        next(); // Func to serve next func on req
    } else {
        res.redirect("/login");
    }
}

server.use(express.json());
server.use("/protected", isAuth, express.static(path.join(__dirname, "public")));

server.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

server.post("/login", async (req, res) => {
    const { username, password } = req.body;

    await authService.connect();

    const valid = await authService.validateUser(username, password);
    
    if (valid.success) {
        console.log("User is validated");

        res.cookie("sessionId", sessionId, { httpOnly: true, secure: false});

        res.json({ success:true });
    } else {
        console.log("Invalid User");
        res.status(401).json({ message: "Invalid username or password" });
    }
});

server.listen(PORT, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);
});