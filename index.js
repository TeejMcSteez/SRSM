// Built in packages
const fs = require("node:fs");
const path = require('node:path');
// Installed Packages
require('dotenv').config();
const express = require('express');
const server = express(); //Namespace for express call
const id = require('uuid');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
// Utilitys
const system = require('./utils/system.js');
const fileManager = require('./utils/readFiles.js');
const AuthService = require('./utils/auth.js');
// Specifying what API's to use for express responses
server.use(express.json());
server.use(express.urlencoded({ extended: true })); // for form-encoded data?
server.use(cookieParser());
// Enviroment Variables
const HOSTNAME = process.env.HOSTNAME;
const PORT = process.env.PORT;

const CPU_TEMPERATURE_DIRECTORY = process.env.CPU_TEMPERATURE_DIRECTORY; // CPU Temp Directory
const MOTHERBOARD_DIRECTORY = process.env.MOTHERBOARD_DIRECTORY; // Motherboard IO Directory

const MONGODB_HOST = process.env.MONGODB_HOST;

const CLIENT_KEY_PATH = process.env.CLIENT_KEY_PATH;
const CA_PATH = process.env.CA_PATH;

const JWT_SECRET = fs.readFileSync(process.env.SECRET_PATH);
const JWT_PUB = fs.readFileSync(process.env.JWT_PATH);
// Instantiation of mongodb client service
const uri = `mongodb://${MONGODB_HOST}:27017/?authMechanism=MONGODB-X509`; //27017 is the default port for mongodb
const options = {
    tls: true,
    tlsCertificateKeyFile: CLIENT_KEY_PATH,
    tlsCAFile: CA_PATH
};

const authService = new AuthService(uri, options);

// Middleware to verify JWT tokens
const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken;
    
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
// Unprotected login route
server.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});
// On POST with user info verifies and signs
server.post("/login", async (req, res) => {
    console.log(req.body);
    const { username, password } = await req.body;
    try {
        await authService.connect();

        const valid = await authService.validateUser(username, password);
        if (valid) {
            console.log("User is validated");
        
            const token = jwt.sign({UID: Date.now() + id.v4()}, JWT_SECRET, {algorithm: 'RS256', expiresIn: '1h'});

            res.cookie('authToken', token, {
                httpOnly: true,
                secure: false,
                sameSite: 'strict',
                maxAge: 60 * 60 * 1000,
            });

            res.status(200).json({ success:true, redirect: '/?token=' + token });

        } else {
            console.log("Invalid Username or password");
            res.status(401).json({ message: valid.message || "Invalid username or password" });
        }
        await authService.close();
    } catch (error) {
        console.error(`Error during login: ${error.message}`);
        res.status(500).json({ message: "Internal Server Error" });
        await authService.close();
    }
});
// On root req checks for tokens and routes accordingly
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