/**
 * @fileoverview TODO
 * @description
 * This is the final TODO list for the secure remote web server (or atleast what I am capable of and slightly understand right now)
 * Mainly reminders I can check before deployment
 * 
 * 1. Ensure proper helmet configuration
 * - @notice ensure that cdn, IP's used, and security configs are correct for the setup
 * - @notice think about adding CSRF protection as well (prob through helmet)
 * 
 * 2. Perms for sensitive information 
 * - @notice Store certificates and keys with strict file permissions (e.g., chmod 600).
 * - @recommendation Provide a logout or session termination route to invalidate JWTs
 * on the client side.
 * 
 * 3. Add password hashing on the server
 * - @notice ensure that on the server and auth.js class there is password hashing and the passwords are not being stored in plain text
 * - @notice store passwords in hashed bcrypt or other library to check for upon validation
 * 
 * 4. Token refreshing (!Semi-Important!)
 * @notice when the user sits in the application and does not exit then refresh the JWT token after the timeout to ensure the user can 
 * keep there session and information and not have to re-log back in 
 * 
 * 5. Miscellaneous
 * @notice Add request login and logout functionality
 * @recommendation Add logout functionality to the index page I will prob not make a way to request a login as this is a personal
 * application and it is not needed  
 * 
 * @version 1.1.0
 * @author TeejMcSteez
 * @since 2024-12-28
 */
/**
 * Built in Node packages
 */
// Node Docs: https://nodejs.org/docs/latest/api/
const fs = require("node:fs");
const path = require('node:path');
/**
 * Installed Packages
 */
require('dotenv').config(); // DOC: https://www.npmjs.com/package/dotenv
const express = require('express'); // DOC: https://expressjs.com/en/5x/api.html
const server = express(); //Namespace for express call
const id = require('uuid');  // DOC: https://www.npmjs.com/package/uuid
const jwt = require('jsonwebtoken'); // DOC: https://www.npmjs.com/package/jsonwebtoken
const cookieParser = require('cookie-parser'); // DOC: https://www.npmjs.com/package/cookie-parser
const https = require('https'); // DOC: https://nodejs.org/api/https.html
const redirectToHTTPS = require('express-http-to-https').redirectToHTTPS; // DOC: https://www.npmjs.com/package/express-http-to-https
const rateLimit = require('express-rate-limit'); // DOC: https://www.npmjs.com/package/express-rate-limit
const logger = require('pino')(); // DOC: https://getpino.io/#/
const helmet = require('helmet'); // DOC: https://www.npmjs.com/package/helmet?activeTab=readme
const {body, check, validationResult } = require('express-validator'); // DOC: https://express-validator.github.io/docs/guides/getting-started 
/**
 * Packages made for index
 */
/**
 * Collects system information from node:os
 */
const system = require('./utils/system.js');
/**
 * Does important file operations with node
 */
const fileManager = require('./utils/readFiles.js');
const AuthService = require('./utils/auth.js');
/**
 * Enviroment Variables
 */
const HOSTNAME = process.env.HOSTNAME;
const PORT = process.env.PORT;

const CPU_TEMPERATURE_DIRECTORY = process.env.CPU_TEMPERATURE_DIRECTORY; // CPU Temp Directory
const MOTHERBOARD_DIRECTORY = process.env.MOTHERBOARD_DIRECTORY; // Motherboard IO Directory

const MONGO_URI = process.env.MONGODB_URI

const CLIENT_KEY_PATH = process.env.CLIENT_KEY_PATH;
const CA_PATH = process.env.CA_PATH;

const JWT_SECRET = fs.readFileSync(process.env.SECRET_PATH);
const JWT_PUB = fs.readFileSync(process.env.JWT_PATH);

const HTTPS_KEY = fs.readFileSync(process.env.HTTPS_KEY_PATH);
const HTTPS_CERT = fs.readFileSync(process.env.HTTPS_CERT_PATH);
/**
 * Limiter Middlware
 */
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 900, // I have requests at 3 seconds intervals over 900 seconds will equate to 300 requests every 900 seconds (15 min), At 1 second interval will be 900 requests every 15 min. 
    standardHeaders: 'draft-8', 
    legacyHeaders: false,
});
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
});
/**
 * Sanitizes username and password input from the user using express-validator
 */
const loginSanitation = [
    body('username').isString().isLength({min: 3}).trim().escape(),
    body('password').isString().isLength({ min: 8 }).trim().escape(),
];
/**
 * Instantiation of Mongodb uri and options
 */
const uri = MONGO_URI; //27017 is the default port for mongodb
const options = {
    tls: true,
    tlsCertificateKeyFile: CLIENT_KEY_PATH,
    tlsCAFile: CA_PATH,
    maxPoolSize: 10, 
    serverSelectionTimeoutMS: 15000,
    connectTimeoutMS: 10000,
    socketTimeoutMS: 45000,    // Longer timeout for operations
};

const authService = new AuthService(uri, options);
/**
 * HTTPS Config
 */
const httpsServer = https.createServer({
    key: HTTPS_KEY,
    cert: HTTPS_CERT
}, server);
/**
 * Helmet Config
 */
const helmetConfig = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "https://cdn.jsdelivr.net"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"], 
            fontSrc: ["'self'", "https://cdn.jsdelivr.net"],
            formAction: ["'self'"],
            upgradeInsecureRequests: [],
        },
    },
    strictTransportSecurity: {
        maxAge: 31536000, 
        includeSubDomains: true,
        preload: true,
    },
    referrerPolicy: {
        policy: "no-referrer",
    },
    crossOriginEmbedderPolicy: true,
    crossOriginResourcePolicy: {policy: "same-origin"},
};
/**
 * MIME checking config
 */
const mimeConfig = {
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) {
            res.set('Content-Type', 'application/javascript; charset=UTF-8');
        } else if (path.endsWith('.css')) {
            res.set('Content-Type', 'text/css; charset=UTF-8');
        } else if (path.endsWith('.html')) {
            res.set('Content-Type', 'text/html; charset=UTF-8')
        }
    }
};
/**
 * Specifying the middleware to use with server
 */
server.use(helmet(helmetConfig));
server.use(redirectToHTTPS([HOSTNAME], [], 301));
server.use(express.json());
server.use(cookieParser());
server.use(limiter);
/**
 * Middleware for verifying JWT Token
 * @param {Request} req 
 * @param {Response} res 
 * @param {NextFunction} next 
 * @returns {void}
 */
const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken;
    const refreshToken = req.cookies.refToken;

    if (!refreshToken) {
        logger.info("Missing refresh token, redirecting to login");
        return res.redirect('/login');
    }

    try {
        const decodedRefresh = jwt.verify(refreshToken, JWT_PUB, {algorithms: ['RS256']});

        if (!token) {
            logger.info("No access token generating new one")
            const newToken = jwt.sign({subj: decodedRefresh.subj, tid: id.v4(), iat: Date.now()}, JWT_SECRET, {algorithm: 'RS256', expiresIn: '1h'});
            res.cookie('authToken', newToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 60 * 60 * 1000,
            });
            req.user = decodedRefresh;
            return next();
        } else {
            const decodedAcess = jwt.verify(token, JWT_PUB, {algorithms: ['RS256'] });
            // Atttach the decoded access token user data to req object
            req.user = decodedAcess; // Adding user info to request object
            return next();
        }
    } catch (error) {
        logger.error(`Token Verification Failed: ${error.message}`);
        res.clearCookie('authToken');
        res.clearCookie('refToken');
        return res.redirect('/login');
    }
};
/**
 * Start of the client
 */
/**
 * Unprotected login route with rate limiter
 */
server.get("/login", loginLimiter,(req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});
/**
 * On POST with user info verifies and signs (With req limiting to prevent DDOS)
 */
server.post("/login", loginLimiter, loginSanitation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, password } = await req.body;
    try {
        await authService.connect();

        const valid = await authService.validateUser(username, password);

        if (valid.valid) {
            logger.info(`${username} is validated at ${Date.now()}`);
        
            const token = jwt.sign({subj: username, tid: id.v4(), iat: Date.now()}, JWT_SECRET, {algorithm: 'RS256', expiresIn: '1h'});

            res.cookie('authToken', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 60 * 60 * 1000, // 1hr 
            });

            const refreshToken = jwt.sign({subj: username, tid: id.v4(), iat: Date.now()}, JWT_SECRET, {algorithm: 'RS256', expiresIn: '12h'});

            res.cookie('refToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 4.32e7, // 12h in ms
            });

            res.status(200).json({ success:true, redirect: '/'});

        } else {
            logger.info(`Non-Validation Reason: ${valid.reason}`);
            res.status(401).json({ message: valid.message || "Invalid username or password" });
        }
    } catch (error) {
        logger.error(`Error during login: ${error.message}`);
        res.status(500).json({ message: "Internal Server Error" });
    } finally { // Must close the service after use to end the session
        await authService.close();
    }
});
/**
 * On root req checks for tokens and routes accordingly
 */
server.get('/', verifyToken, async (req, res) => {
    res.sendFile(path.join(__dirname, 'public/protected', 'index.html'));
});
/**
 * API's
 */
/**
 * Gets CPU Temperature Information
 */
server.get('/api/temperatures', verifyToken, async (req, res) => {
    try {
        const contents = await fileManager.readFolder(CPU_TEMPERATURE_DIRECTORY);

        const tempFiles = fileManager.findTemperatureFiles(contents);

        const readingsPromise =  await Promise.all(tempFiles.map(file => fileManager.findValues(CPU_TEMPERATURE_DIRECTORY, file.LABEL)));

        const readings = await Promise.all(readingsPromise);

        const convertedReadings = system.convert(readings);

        res.json(convertedReadings);

    } catch (error) {
        logger.error(`Error fetching temperatures ${error.message}`);
        res.status(500).json({error: 'Could not fetch temperatures'});
    }
});
/**
 * Gets Motherboard Readings
 */
server.get('/api/motherboard', verifyToken, async (req, res) => {
    try {
        const contents = await fileManager.readFolder(MOTHERBOARD_DIRECTORY);

        const tempFiles = fileManager.findMotherboardFiles(contents);

        const readingsPromise = await Promise.all(tempFiles.map(file => fileManager.findValues(MOTHERBOARD_DIRECTORY, file.LABEL)));

        const readings = await Promise.all(readingsPromise);

        const convertedReadings = system.convert(readings);

        res.json(convertedReadings);
        
    } catch (error) {
        logger.error(`Error fetching motherboard values: ${error.message}`);
        res.status(500).json({error: `Could not fetch temperature values`});
    }
});
/**
 * Gets Current and Total memory for graph
 */
server.get('/api/chartInformation', verifyToken, async (req, res) => {
    const memoryInformation = [system.getCurrentMemory(), system.getTotalMemory()];

    res.json(memoryInformation);
});
/**
 * Gets uptime of the server in milliseconds
 */
server.get('/api/uptime', verifyToken, async (req, res) => {
    const uptime = system.getUptime();

    const uptimeSplit = system.splitUptime(uptime);

    res.json(uptimeSplit);
});
/**
 * Gets 1, 5, 15 minute load average array from node
 */
server.get('/api/loadAvg', verifyToken, (req, res) => {
    const loadAvg = system.getLoadAvg();

    res.json(loadAvg);
});
/**
 * Servs public directory with all files
 */
server.use(express.static(
    path.join(__dirname, "public"),
    { mimeConfig, index: false }
  ));  
/**
 * Protected route near bottom of stack
 */
server.use(
    "/protected", 
    verifyToken, 
    express.static(path.join(__dirname, "public", "protected"), { mimeConfig, index: false })
  );  
/**
 * Global Error Handling
 */
server.use((req, res, next) => {
    res.status(404).json({ error: 'Not Found'});
});
/**
 * Global Error Handling
 */
server.use((err, req, res, next) => {
    logger.error(err);
    res.status(500).json({ error: 'Internal Service Error'});
});
/**
 * Starting Server
 */
httpsServer.listen(PORT, () => {
    logger.info(`Server running at https://${HOSTNAME}:${PORT}`);
});
