#!/usr/bin/env node

const crypto = require('crypto');
const readline = require('readline');
const bcrypt = require('bcrypt');

class PasswordHasher {
    constructor() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        this.hashTypes = {
            '1': { name: 'MD5', func: this.hashMD5 },
            '2': { name: 'SHA-1', func: this.hashSHA1 },
            '3': { name: 'SHA-256', func: this.hashSHA256 },
            '4': { name: 'SHA-512', func: this.hashSHA512 },
            '5': { name: 'BCRYPT', func: this.hashBcrypt },
            '6': { name: 'PBKDF2', func: this.hashPBKDF2 },
            '7': { name: 'Argon2 (Manual)', func: this.hashArgon2Manual },
            '8': { name: 'RIPEMD160', func: this.hashRIPEMD160 },
            '9': { name: 'Whirlpool', func: this.hashWhirlpool },
            '10': { name: 'Blake2b', func: this.hashBlake2b }
        };

        this.modes = {
            '1': { name: 'Hash Password', func: this.hashMode },
            '2': { name: 'Verify Password', func: this.verifyMode },
            '3': { name: 'Dictionary Attack', func: this.dictionaryMode },
            '4': { name: 'Brute Force Attack', func: this.bruteForceMode }
        };
    }

    // Hash functions
    hashMD5(password) {
        return crypto.createHash('md5').update(password).digest('hex');
    }

    hashSHA1(password) {
        return crypto.createHash('sha1').update(password).digest('hex');
    }

    hashSHA256(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }

    hashSHA512(password) {
        return crypto.createHash('sha512').update(password).digest('hex');
    }

    async hashBcrypt(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }

    hashPBKDF2(password) {
        const salt = crypto.randomBytes(32).toString('hex');
        const iterations = 100000;
        const keyLength = 64;
        const digest = 'sha512';
        
        const hash = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest).toString('hex');
        return `${salt}:${iterations}:${hash}`;
    }

    hashArgon2Manual(password) {
        // Manual Argon2-like implementation using PBKDF2
        const salt = crypto.randomBytes(32).toString('hex');
        const iterations = 200000;
        const keyLength = 64;
        
        const hash1 = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256').toString('hex');
        const hash2 = crypto.pbkdf2Sync(hash1, salt + 'argon2', iterations / 2, keyLength, 'sha512').toString('hex');
        
        return `argon2:${salt}:${iterations}:${hash2}`;
    }

    hashRIPEMD160(password) {
        return crypto.createHash('ripemd160').update(password).digest('hex');
    }

    hashWhirlpool(password) {
        return crypto.createHash('whirlpool').update(password).digest('hex');
    }

    // Verification functions
    async verifyPassword(password, hash, hashType) {
        try {
            if (hashType === 'BCRYPT') {
                return await bcrypt.compare(password, hash);
            } else if (hashType === 'PBKDF2') {
                const [salt, iterations, storedHash] = hash.split(':');
                const keyLength = 64;
                const computedHash = crypto.pbkdf2Sync(password, salt, parseInt(iterations), keyLength, 'sha512').toString('hex');
                return computedHash === storedHash;
            } else if (hashType === 'Argon2 (Manual)') {
                const [, salt, iterations, storedHash] = hash.split(':');
                const keyLength = 64;
                const hash1 = crypto.pbkdf2Sync(password, salt, parseInt(iterations), keyLength, 'sha256').toString('hex');
                const hash2 = crypto.pbkdf2Sync(hash1, salt + 'argon2', parseInt(iterations) / 2, keyLength, 'sha512').toString('hex');
                return hash2 === storedHash;
            } else {
                // Simple hash comparison
                const hashFunc = this.getHashFunction(hashType);
                const computedHash = hashFunc(password);
                return computedHash === hash.toLowerCase();
            }
        } catch (error) {
            return false;
        }
    }

    hashBlake2b(password) {
        // Using Blake2b512 if available, fallback to SHA-512
        try {
            return crypto.createHash('blake2b512').update(password).digest('hex');
        } catch (error) {
            console.log('Blake2b not available, using SHA-512 as fallback');
            return crypto.createHash('sha512').update(password).digest('hex');
        }
    }

    // Mode functions
    async hashMode() {
        this.displayHashMenu();
        
        return new Promise((resolve) => {
            this.rl.question('Choose hash algorithm (0-10): ', async (choice) => {
                if (choice === '0') {
                    resolve(this.run());
                    return;
                }

                if (!this.hashTypes[choice]) {
                    console.log('\n❌ Invalid choice!');
                    setTimeout(() => resolve(this.hashMode()), 2000);
                    return;
                }

                const selectedHash = this.hashTypes[choice];
                console.log(`\n📝 Selected: ${selectedHash.name}\n`);

                try {
                    const password = await this.getPassword();
                    if (password.length === 0) {
                        console.log('\n❌ Password cannot be empty!');
                        setTimeout(() => resolve(this.hashMode()), 2000);
                        return;
                    }

                    const confirmed = await this.confirmPassword(password);
                    if (!confirmed) {
                        setTimeout(() => resolve(this.hashMode()), 2000);
                        return;
                    }

                    console.log('\n🔄 Hashing password...\n');

                    const startTime = Date.now();
                    const hashedPassword = await selectedHash.func.call(this, password);
                    const endTime = Date.now();

                    console.log('═══════════════════════════════════════');
                    console.log(`🔐 Hash Type: ${selectedHash.name}`);
                    console.log(`⏱️  Time taken: ${endTime - startTime}ms`);
                    console.log(`📏 Hash length: ${hashedPassword.length} characters`);
                    console.log('═══════════════════════════════════════');
                    console.log(`\n🔑 Hashed Password:\n${hashedPassword}\n`);
                    console.log('═══════════════════════════════════════\n');

                    this.rl.question('Press Enter to continue: ', () => {
                        resolve(this.run());
                    });

                } catch (error) {
                    console.log(`\n❌ Error: ${error.message}`);
                    setTimeout(() => resolve(this.hashMode()), 2000);
                }
            });
        });
    }

    async verifyMode() {
        console.clear();
        console.log('\n╔══════════════════════════════════════╗');
        console.log('║         PASSWORD VERIFICATION       ║');
        console.log('╚══════════════════════════════════════╝\n');

        return new Promise((resolve) => {
            this.rl.question('Enter the hash to verify against: ', async (hash) => {
                if (!hash.trim()) {
                    console.log('\n❌ Hash cannot be empty!');
                    setTimeout(() => resolve(this.run()), 2000);
                    return;
                }

                this.displayHashMenu();
                
                this.rl.question('Choose hash type (0-10): ', async (choice) => {
                    if (choice === '0') {
                        resolve(this.run());
                        return;
                    }

                    if (!this.hashTypes[choice]) {
                        console.log('\n❌ Invalid choice!');
                        setTimeout(() => resolve(this.verifyMode()), 2000);
                        return;
                    }

                    const hashType = this.hashTypes[choice].name;
                    console.log(`\n📝 Hash Type: ${hashType}\n`);

                    const password = await this.getPassword();
                    if (password.length === 0) {
                        console.log('\n❌ Password cannot be empty!');
                        setTimeout(() => resolve(this.verifyMode()), 2000);
                        return;
                    }

                    console.log('\n🔄 Verifying password...\n');

                    const isMatch = await this.verifyPassword(password, hash, hashType);
                    
                    if (isMatch) {
                        console.log('✅ PASSWORD MATCHES! ✅');
                    } else {
                        console.log('❌ PASSWORD DOES NOT MATCH ❌');
                    }

                    this.rl.question('\nPress Enter to continue: ', () => {
                        resolve(this.run());
                    });
                });
            });
        });
    }

    async dictionaryMode() {
        console.clear();
        console.log('\n╔══════════════════════════════════════╗');
        console.log('║         DICTIONARY ATTACK           ║');
        console.log('╚══════════════════════════════════════╝\n');
        console.log('⚠️  WARNING: This is for educational/testing purposes only!');
        console.log('⚠️  Only use on hashes you own or have permission to test.\n');

        return new Promise((resolve) => {
            this.rl.question('Enter the hash to crack: ', async (hash) => {
                if (!hash.trim()) {
                    console.log('\n❌ Hash cannot be empty!');
                    setTimeout(() => resolve(this.run()), 2000);
                    return;
                }

                this.displayHashMenu();
                
                this.rl.question('Choose hash type (0-10): ', async (choice) => {
                    if (choice === '0') {
                        resolve(this.run());
                        return;
                    }

                    if (!this.hashTypes[choice]) {
                        console.log('\n❌ Invalid choice!');
                        setTimeout(() => resolve(this.dictionaryMode()), 2000);
                        return;
                    }

                    const hashType = this.hashTypes[choice].name;
                    
                    // Skip complex hashes for dictionary attack
                    if (['BCRYPT', 'PBKDF2', 'Argon2 (Manual)'].includes(hashType)) {
                        console.log('\n❌ Dictionary attack not efficient for this hash type!');
                        setTimeout(() => resolve(this.run()), 2000);
                        return;
                    }

                    const startTime = Date.now();
                    const result = await this.dictionaryAttack(hash, hashType);
                    const endTime = Date.now();

                    console.log(`\n⏱️ Time taken: ${endTime - startTime}ms`);
                    
                    this.rl.question('\nPress Enter to continue: ', () => {
                        resolve(this.run());
                    });
                });
            });
        });
    }

    async bruteForceMode() {
        console.clear();
        console.log('\n╔══════════════════════════════════════╗');
        console.log('║          BRUTE FORCE ATTACK         ║');
        console.log('╚══════════════════════════════════════╝\n');
        console.log('⚠️  WARNING: This is VERY slow and for educational purposes only!');
        console.log('⚠️  Only use on hashes you own or have permission to test.');
        console.log('⚠️  Limited to 4 characters max to prevent system overload.\n');

        return new Promise((resolve) => {
            this.rl.question('Enter the hash to crack: ', async (hash) => {
                if (!hash.trim()) {
                    console.log('\n❌ Hash cannot be empty!');
                    setTimeout(() => resolve(this.run()), 2000);
                    return;
                }

                this.displayHashMenu();
                
                this.rl.question('Choose hash type (0-10): ', async (choice) => {
                    if (choice === '0') {
                        resolve(this.run());
                        return;
                    }

                    if (!this.hashTypes[choice]) {
                        console.log('\n❌ Invalid choice!');
                        setTimeout(() => resolve(this.bruteForceMode()), 2000);
                        return;
                    }

                    const hashType = this.hashTypes[choice].name;
                    
                    // Skip complex hashes for brute force
                    if (['BCRYPT', 'PBKDF2', 'Argon2 (Manual)'].includes(hashType)) {
                        console.log('\n❌ Brute force attack not feasible for this hash type!');
                        setTimeout(() => resolve(this.run()), 2000);
                        return;
                    }

                    this.rl.question('Max password length (1-4, default 3): ', async (lengthInput) => {
                        const maxLength = Math.min(Math.max(parseInt(lengthInput) || 3, 1), 4);
                        
                        console.log(`\n🚀 Starting brute force with max length: ${maxLength}`);
                        console.log('⚠️  This may take a while...\n');

                        const startTime = Date.now();
                        const result = await this.bruteForceAttack(hash, hashType, maxLength);
                        const endTime = Date.now();

                        console.log(`\n⏱️ Total time: ${endTime - startTime}ms`);
                        
                        this.rl.question('\nPress Enter to continue: ', () => {
                            resolve(this.run());
                        });
                    });
                });
            });
        });
    }

    getHashFunction(hashType) {
        const hashMap = {
            'MD5': this.hashMD5,
            'SHA-1': this.hashSHA1,
            'SHA-256': this.hashSHA256,
            'SHA-512': this.hashSHA512,
            'RIPEMD160': this.hashRIPEMD160,
            'Whirlpool': this.hashWhirlpool,
            'Blake2b': this.hashBlake2b
        };
        return hashMap[hashType].bind(this);
    }

    // Dictionary attack
    async dictionaryAttack(targetHash, hashType, wordlist = null) {
        const commonPasswords = wordlist || [
            'password', '123456', 'password123', 'admin', 'qwerty', 'letmein',
            '12345678', '123456789', 'password1', 'abc123', '1234567890',
            'dragon', 'iloveyou', 'princess', 'rockyou', 'monkey', 'shadow',
            'master', 'jessica', 'michael', 'superman', 'batman', 'hello',
            'freedom', 'whatever', 'computer', 'internet', 'welcome', 'sunshine'
        ];

        console.log(`🔍 Starting dictionary attack with ${commonPasswords.length} common passwords...\n`);
        
        for (let i = 0; i < commonPasswords.length; i++) {
            const password = commonPasswords[i];
            process.stdout.write(`\r🔄 Testing: ${password.padEnd(20)} (${i + 1}/${commonPasswords.length})`);
            
            const isMatch = await this.verifyPassword(password, targetHash, hashType);
            if (isMatch) {
                console.log(`\n\n✅ PASSWORD FOUND: ${password}`);
                return password;
            }
        }
        
        console.log('\n\n❌ Password not found in dictionary');
        return null;
    }

    // Simple brute force (limited scope for demonstration)
    async bruteForceAttack(targetHash, hashType, maxLength = 4) {
        const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
        console.log(`🔍 Starting brute force attack (max length: ${maxLength})...\n`);
        
        let attempts = 0;
        const maxAttempts = Math.pow(charset.length, maxLength);
        
        for (let length = 1; length <= maxLength; length++) {
            const combinations = Math.pow(charset.length, length);
            console.log(`\n🔢 Testing ${length}-character combinations (${combinations} possibilities)...`);
            
            for (let i = 0; i < combinations; i++) {
                let password = '';
                let temp = i;
                
                for (let j = 0; j < length; j++) {
                    password = charset[temp % charset.length] + password;
                    temp = Math.floor(temp / charset.length);
                }
                
                attempts++;
                if (attempts % 1000 === 0) {
                    process.stdout.write(`\r🔄 Testing: ${password.padEnd(10)} (${attempts}/${maxAttempts})`);
                }
                
                const isMatch = await this.verifyPassword(password, targetHash, hashType);
                if (isMatch) {
                    console.log(`\n\n✅ PASSWORD FOUND: ${password}`);
                    console.log(`🔢 Attempts: ${attempts}`);
                    return password;
                }
            }
        }
        
        console.log(`\n\n❌ Password not found after ${attempts} attempts`);
        return null;
    }

    displayMainMenu() {
        console.clear();
        console.log('\n╔══════════════════════════════════════╗');
        console.log('║       PASSWORD HASH TOOLKIT         ║');
        console.log('╚══════════════════════════════════════╝\n');
        
        console.log('Select operation mode:\n');
        
        Object.entries(this.modes).forEach(([key, value]) => {
            console.log(`${key}. ${value.name}`);
        });
        
        console.log('\n0. Exit');
        console.log('\n═══════════════════════════════════════\n');
    }

    displayHashMenu() {
        console.clear();
        console.log('\n╔══════════════════════════════════════╗');
        console.log('║        SELECT HASH ALGORITHM         ║');
        console.log('╚══════════════════════════════════════╝\n');
        
        Object.entries(this.hashTypes).forEach(([key, value]) => {
            console.log(`${key.padStart(2)}. ${value.name}`);
        });
        
        console.log('\n 0. Back to Main Menu');
        console.log('\n═══════════════════════════════════════\n');
    }

    async getPassword() {
        return new Promise((resolve) => {
            // Hide password input
            const stdin = process.stdin;
            stdin.setRawMode(true);
            stdin.resume();
            stdin.setEncoding('utf8');
            
            let password = '';
            console.log('Enter password (hidden): ');
            
            stdin.on('data', (key) => {
                if (key === '\u0003') { // Ctrl+C
                    process.exit();
                } else if (key === '\r' || key === '\n') { // Enter
                    stdin.setRawMode(false);
                    stdin.pause();
                    stdin.removeAllListeners('data');
                    console.log(''); // New line
                    resolve(password);
                } else if (key === '\u007f') { // Backspace
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                        process.stdout.write('\b \b');
                    }
                } else if (key.charCodeAt(0) >= 32) { // Printable characters
                    password += key;
                    process.stdout.write('*');
                }
            });
        });
    }

    async confirmPassword(originalPassword) {
        console.log('Confirm password (hidden): ');
        const confirmPassword = await this.getPassword();
        
        if (originalPassword !== confirmPassword) {
            console.log('\n❌ Passwords do not match! Please try again.\n');
            return false;
        }
        return true;
    }

    async processMainMenu() {
        return new Promise((resolve) => {
            this.rl.question('Choose operation (0-4): ', async (choice) => {
                if (choice === '0') {
                    console.log('\n👋 Goodbye!\n');
                    this.rl.close();
                    process.exit(0);
                }

                if (!this.modes[choice]) {
                    console.log('\n❌ Invalid choice! Please try again.\n');
                    setTimeout(() => resolve(this.run()), 2000);
                    return;
                }

                const selectedMode = this.modes[choice];
                console.log(`\n📝 Selected: ${selectedMode.name}\n`);

                try {
                    await selectedMode.func.call(this);
                } catch (error) {
                    console.log(`\n❌ Error: ${error.message}\n`);
                    setTimeout(() => resolve(this.run()), 2000);
                }
            });
        });
    }

    async run() {
        this.displayMainMenu();
        await this.processMainMenu();
    }

    static checkDependencies() {
        try {
            require('bcrypt');
            return true;
        } catch (error) {
            console.log('\n❌ Missing dependencies!');
            console.log('\nTo install required packages, run:');
            console.log('npm install bcrypt\n');
            console.log('Or if you want to install all at once:');
            console.log('npm init -y && npm install bcrypt\n');
            return false;
        }
    }
}

// Main execution
if (require.main === module) {
    console.log('🚀 Starting Password Hasher Tool...\n');
    
    // Check dependencies
    if (!PasswordHasher.checkDependencies()) {
        process.exit(1);
    }
    
    const hasher = new PasswordHasher();
    
    // Handle Ctrl+C gracefully
    process.on('SIGINT', () => {
        console.log('\n\n👋 Goodbye!\n');
        process.exit(0);
    });
    
    // Start the application
    hasher.run().catch(console.error);
}

module.exports = PasswordHasher;