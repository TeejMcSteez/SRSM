# Secure Remote Web Sever #
Using MongoDB and JWT to authenticate user sessions and manage them for logins to view remote web server information. 
---
My hope is to be able to implement user authentication on my HTTP/HTTPS apps I use with this database setup as well as ensure that only the people I want to access my server will. 
---
Packages:
- Node/npm (Using path and fs built in packages)
- Express 
- UUID (for jsonwebtoken UID)
- Bcrypt (To compare hashed DB values)
- jsonwebtoken (for session management)
- dotenv
The dotenv file will need to contain information for:
- Hostname/Port for express
- Directories for CPU and Motherboard readings values
- Mongodb Hostname 
- Certificate and private key path for mongodb connection 
- Private and public key path for JWT verification
**It is not fully secure** there still needs to be better practices such as HTTP secure cookies and not using sessionStorage but this is a start.  