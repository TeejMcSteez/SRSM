# Secure Remote Web Sever #
### Using MongoDB and JWT to authenticate user sessions and manage them for logins to view remote web server information. 
---
## Packages:
- Node/npm (Using path and fs built in packages)
- Express 
- UUID (for jsonwebtoken UID)
- Bcrypt (To compare hashed DB values)
- jsonwebtoken (for session management)
- dotenv
- Express-http-to-https (for http redirects) 
- express-rate-limit (for rate limiting page requests)
---
Install with `npm i express uuid bcrypt jsonwebtoken dotenv express-http-to-https express-rate-limit`
---
## The dotenv file will need to contain information for:
- Hostname & Port (for express server listener)
- Directories for CPU and Motherboard readings values
- Mongodb Hostname and user database name
- Certificate and private key path (for mongodb connection)
- Private & public key path (for JWT verification)
---
**It is not fully secure** there is still plenty of work to be done . . . but this is a start and man is it cool and fun