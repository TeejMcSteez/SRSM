// When I get back to the server I need to setup $external users to be able to interact with the Auth user database
// I also need to make a way to manager user cookie authentication, whether that be server side or storing something on the program idk yet
// Also need to generate public and private keys for json web token validation
const AuthService = require('./utils/auth.js');
const express = require('express');
require('dotenv').config();
const fs = require("node:fs");
const path = require('path');
const server = express(); //Namespace for express call
const bcrypt = require('bcrypt');
const id = require('uuid');
const jwt = require('jsonwebtoken');

server.use(express.json());
server.use(express.urlencoded({ extended: true })); // for form-encoded data?

const HOSTNAME = process.env.HOSTNAME;
const PORT = process.env.PORT;

const MONGO_USERNAME = process.env.USERNAME;
const MONGO_PASSWORD = process.env.PASSWORD;
const MONGODB_HOST = process.env.MONGODB_HOST;
const USER_DATABASE = process.env.USER_DATABASE;

const CLIENT_KEY_PATH = process.env.CLIENT_KEY_PATH;
const CA_PATH = process.env.CA_PATH;

const JWT_SECRET = process.env.JWT_PRIVATE_KEY;
const JWT_TEST = process.env.JWT_PUBLIC_KEY;

const uri = `mongodb://${MONGODB_HOST}:27017/?authMechanism=MONGODB-X509`; //27017 is the default port for mongodb
const options = {
    tls: true,
    tlsCertificateKeyFile: CLIENT_KEY_PATH,
    tlsCAFile: CA_PATH
};

const authService = new AuthService(uri, options);

// Middleware to verify JWT tokens
const verifyToken = (req, res, next) => {
    // This is getting the token from session storage via the auth header 
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format

    const queryToken = req.query.token;

    const tokenToVerify = token || queryToken;

    if (!tokenToVerify) {
        res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(tokenToVerify, JWT_TEST, {algorithms: ['RS256'] });
        req.user = decoded; // Adding user info to request object
        next();
    } catch (error) {
        console.error(`Token Verification Failed: ${error.message}`);
        return res.status(403).json({ message: 'Invalid or expired token'});
    }
};

server.use("/protected", verifyToken, express.static(path.join(__dirname, "public")));

server.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

server.post("/login", async (req, res) => {
    console.log(req.body);
    const { username, password } = await req.body;
    try {
        await authService.connect();

        const valid = await authService.validateUser(username, password);
        
        if (valid.success) {
            console.log("User is validated");
        
            const token = jwt.sign({TempUID: Date.now() + id.v4()}, JWT_SECRET, {algorithm: 'RSA256', expiresIn: '1h'});
            sessionStorage.setItem('authToken', token);

            res.json({ success:true, token, redirect: '/?token=' + token });

        } else {
            console.log("Invalid User");
            res.status(401).json({ message: valid.message || "Invalid username or password" });
        }
        await authService.close();
    } catch (error) {
        console.error(`Error during login: ${error.message}`);
        res.status(500).json({ message: "Internal Server Error" });
        await authService.close();
    }
});

server.get('/', verifyToken, async (req, res) => {
    res.sendFile(path.join(__dirname, 'public/protected', 'index.html'));
});

server.listen(PORT, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);
});