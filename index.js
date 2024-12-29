/**
 * @fileoverview Security Audit Summary for index.js (By GPT o1)
 * @description
 *  This file defines an Express-based Node.js server with HTTPS support, rate limiting,
 *  JWT-based authentication, and MongoDB connectivity. Below is a high-level security review
 *  summarizing potential risks and recommended enhancements:
 *
 *  1. Token Handling
 *     - @notice Using query parameters (req.query.token) for JWT tokens can inadvertently
 *       expose tokens in logs and browser history. Prefer cookies or Authorization headers.
 *     - @notice Clearing token variables (token = null, tokenToVerify = null) helps minimize
 *       the window of exposure in memory, but does not guarantee immediate garbage collection.
 *
 *  2. Input Validation & Sanitization ✔️ @notice Used express-validator to validate username and pwd input
 *     - @notice Validate and sanitize all user-provided data (e.g., username, password).
 *       This prevents injection attacks and ensures the data meets expected formats.
 *     - @recommendation Consider using express-validator or Joi for structured validation.
 *
 *  3. MongoDB Security ✔️ @notice Implemented global error handling for failures on the backend
 *     - @notice TLS, connection pooling, and timeouts are configured. Ensure least-privilege
 *       MongoDB user permissions. 
 *     - @recommendation Use try-catch blocks (or a global error handler) to avoid detailed
 *       error leakage.
 *
 *  4. Express & Middleware
 *     - @notice Helmet is configured with CSP and HSTS, which is good for preventing
 *       some common attacks. Adjust the directives carefully if you add external scripts.
 *     - @notice Rate limiting is in place. Fine-tune thresholds for login routes to
 *       mitigate brute-force attacks.
 *     - @recommendation Implement CSRF protection if you accept form data that modifies
 *       server-side state.
 *
 *  5. Logging & Error Handling ✔️ (Added global error handling to the script)
 *     - @notice Using Pino to handle structured logging. Avoid logging tokens, passwords,
 *       or other secrets. 
 *     - @recommendation Add a global error-handling middleware to catch unhandled exceptions
 *       and return a generic error to the client. ✔️
 *
 *  6. Miscellaneous
 *     - @notice Store certificates and keys with strict file permissions (e.g., chmod 600).
 *     - @recommendation Provide a logout or session termination route to invalidate JWTs
 *       on the client side.
 *
 * @version 1.0.0
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
    limit: 100,
    standardHeaders: 'draft-8', 
    legacyHeaders: false,
});
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
            defaultSrc: ["'self"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdeliver.net"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'"],
            formAction: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            upgradeInsecureRequests: [],
        },
    },
    strictTransportSecurity: {
        maxAge: 31536000, 
        includeSubDomains: true
    }
};
/**
 * Specifying the middleware to use with server
 */
server.use(helmet(helmetConfig));
server.use(redirectToHTTPS([HOSTNAME], [], 301));
server.use(express.json());
server.use(express.urlencoded({ extended: true })); // for form-encoded data?
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

    if (!token) {
        return res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(token, JWT_PUB, {algorithms: ['RS256'] });
        req.user = decoded; // Adding user info to request object
        next();
    } catch (error) {
        logger.error(`Token Verification Failed: ${error.message}`);
        res.clearCookie('authToken');
        return res.redirect('/login');
    }
};
/**
 * Start of the client
 */
/**
 * Unprotected login route with rate limiter
 */
server.get("/login", limiter,(req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});
/**
 * On POST with user info verifies and signs (With req limiting to prevent DDOS)
 */
server.post("/login", limiter, [body('username').isString().isLength({ min: 3}).trim().escape(), body('password').isString().isLength({ min: 8 }).trim()], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, password } = await req.body;
    try {
        await authService.connect();

        const valid = await authService.validateUser(username, password).catch(error);

        if (valid.valid) {
            logger.info("User is validated");
        
            const token = jwt.sign({subj: username, tid: id.v4(), iat: Date.now()}, JWT_SECRET, {algorithm: 'RS256', expiresIn: '1h'});

            res.cookie('authToken', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 60 * 60 * 1000,
            });

            res.status(200).json({ success:true, redirect: '/'});

        } else {
            logger.info(`Reason: ${valid.reason}`);
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
// Moved all protected and fallback routes to the end of the stack
server.use("/protected", verifyToken, express.static(path.join(__dirname, "public")));

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