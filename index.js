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
const system = require('./utils/system.js');
const fileManager = require('./utils/readFiles.js');

server.use(express.json());
server.use(express.urlencoded({ extended: true })); // for form-encoded data?

const HOSTNAME = process.env.HOSTNAME;
const PORT = process.env.PORT;

const CPU_TEMPERATURE_DIRECTORY = process.env.CPU_TEMPERATURE_DIRECTORY; // CPU Temp Directory
const MOTHERBOARD_DIRECTORY = process.env.MOTHERBOARD_DIRECTORY; // Motherboard IO Directory

const MONGO_USERNAME = process.env.USERNAME; // Might not be needed with $external
const MONGO_PASSWORD = process.env.PASSWORD; // Might not be needed with $external
const MONGODB_HOST = process.env.MONGODB_HOST;

const CLIENT_KEY_PATH = process.env.CLIENT_KEY_PATH;
const CA_PATH = process.env.CA_PATH;

const JWT_SECRET = fs.readFileSync(process.env.SECRET_PATH);
const JWT_PUB = fs.readFileSync(process.env.JWT_PATH);

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
    const token = authHeader && authHeader.split(' ')[1]; // ensures truthy header and splits into Bearer TOKEN format

    const queryToken = req.query.token; // If token is in the query header after login uses that.

    const tokenToVerify = token || queryToken; // Uses either valid token from login query or from protected routes custom headers

    if (!tokenToVerify) {
        res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(tokenToVerify, JWT_PUB, {algorithms: ['RS256'] });
        req.user = decoded; // Adding user info to request object
        next();
    } catch (error) {
        console.error(`Token Verification Failed: ${error.message}`);
        return res.status(403).json({ message: 'Invalid or expired token'});
    }
};

// Start of client
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
        
            const token = jwt.sign({UID: Date.now() + id.v4()}, JWT_SECRET, {algorithm: 'RSA256', expiresIn: '1h'});
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

// API's
server.get('/api/temperatures', verifyToken, async (req, res) => {
    try {
        const contents = await fileManager.readFolder(CPU_TEMPERATURE_DIRECTORY);

        const tempFiles = fileManager.findTemperatureFiles(contents);

       const readingsPromise =  await Promise.all(tempFiles.map(file => fileManager.findValues(CPU_TEMPERATURE_DIRECTORY, file.LABEL)));

       const readings = await Promise.all(readingsPromise);

       const convertedReadings = system.convert(readings);

        // sends each converted readings value as a json response
        // Only converts temperature and millivolts currently otherwise returns the data sent to it
        res.json(convertedReadings);

    } catch (error) {
        console.error(`Error fetching temperatures ${error.message}`);
        res.status(500).json({error: 'Could not fetch temperatures'});
    }
});

server.get('/api/motherboard', verifyToken, async (req, res) => {
    try {
        const contents = await fileManager.readFolder(MOTHERBOARD_DIRECTORY);

        const tempFiles = fileManager.findMotherboardFiles(contents);

        const readingsPromise = await Promise.all(tempFiles.map(file => fileManager.findValues(MOTHERBOARD_DIRECTORY, file.LABEL)));

        const readings = await Promise.all(readingsPromise);

        const convertedReadings = system.convert(readings);

        res.json(convertedReadings);
        
    } catch (error) {
        console.error(`Error fetching motherboard values: ${error.message}`);
        res.status(500).json({error: `Could not fetch temperature values`});
    }
});

server.get('/api/chartInformation', verifyToken, async (req, res) => {
    const memoryInformation = [system.getCurrentMemory(), system.getTotalMemory()];

    res.json(memoryInformation);
});

server.get('/api/uptime', verifyToken, async (req, res) => {
    const uptime = system.getUptime();

    const uptimeSplit = system.splitUptime(uptime);

    res.json(uptimeSplit);
});

server.get('/api/loadAvg', verifyToken, (req, res) => {
    const loadAvg = system.getLoadAvg();

    res.json(loadAvg);
}); 

// Starting server
server.listen(PORT, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);
});