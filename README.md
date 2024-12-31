# Secure Remote Web Sever #
Using MongoDB and JWT to authenticate user sessions and manage them for logins to view remote web server information. Mainly to learn security measures but also for fun! I liked making the project now I want to secure it.
---
**docs** directory contains API information for user made packages and classes made with jsdoc2md [JSDoc-to-Markdown Docs](https://www.npmjs.com/package/jsdoc-to-markdown)
---
## Packages:
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
**It is not fully secure** there is still plenty of work to be done . . . but this is a start and man is it cool and fun
# For me # 
- When I get back to the server I need to remove database information and use hashed information for proper handling of non-plaintext information. 
- Also, Need to restrict login information to read only as there is no need to write to the database yet and will prob use another role for that
