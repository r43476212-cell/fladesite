// Run locally with Node.js 20+: node create-admin.mjs USERNAME PASSWORD
import { randomBytes, pbkdf2Sync } from 'node:crypto';
const [username,password]=process.argv.slice(2);
if(!username||!password||username.length<3||password.length<12){console.error('Usage: node create-admin.mjs USERNAME PASSWORD (password at least 12 characters)');process.exit(1)}
const salt=randomBytes(16).toString('base64url');const hash=pbkdf2Sync(password,salt,210000,32,'sha256').toString('base64url');
const id=randomBytes(12).toString('hex');
console.log(`INSERT INTO users (id, username, password_hash, password_salt, role) VALUES ('${id}', '${username.replaceAll("'","''")}', '${hash}', '${salt}', 'owner');`);
