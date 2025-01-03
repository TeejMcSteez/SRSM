# Secure Remote Web Sever #
Uses Mongodb, JWT, and Node to authenticate users defined by the Mongodb admin for there systems remote system monitor. Monitors Motherboard RPM and voltage inputs as well as CPU Inputs and Maxes (Package and per core)
---
**Only For UNIX/Linux node API and Hwmon do not exist/work on windows download [LibreHWMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases)**
---
**docs** directory contains API information for user made packages and classes made with jsdoc2md [JSDoc-to-Markdown Docs](https://www.npmjs.com/package/jsdoc-to-markdown) and therefore is not perfect and was automatically generated based of JSDoc comments in my code
---
## NPM Packages:
- Node/npm (Using path and fs built in packages)
- Express 
- UUID (for jsonwebtoken UID)
- Argon2 (To compare hashed DB values)
- jsonwebtoken (for session management)
- cookie-parser
- dotenv
- Express-http-to-https (for http redirects) 
- express-rate-limit (for rate limiting page requests)
- Pino (Logging)
- Helmet
---
Install with `npm i express uuid argon2 jsonwebtoken dotenv express-http-to-https cookie-parser express-rate-limit pino helmet express-validator mongodb`
---
## The dotenv file will need to contain information for:
- Hostname & Port (for express server listener)
- Directories for CPU and Motherboard readings values
- Mongodb Hostname and user database name
- Certificate and private key path (for mongodb connection)
- Private & public key path (for JWT verification)
---
**It is not fully secure** there is still plenty of work to be done . . . but this is a start and man is it cool and fun and has some industry standard-ish security in it. 