const { exec } = require('child_process'); // To execute Nmap command
const db = require('./db');

// Network range to scan (adjust based on your network range)
const networkRange = '192.168.18.0/24'; // Change this to your local network range

// Function to perform Nmap scan
function scanNetwork() {
    const nmapCommand = `nmap -O -sn ${networkRange}`; // Nmap command for host discovery (ping scan)

    // Execute Nmap command
    exec(nmapCommand, (err, stdout, stderr) => {
        if (err) {
            console.error('Error during Nmap scan:', err);
            return;
        }
        if (stderr) {
            console.error('Nmap stderr:', stderr);
            return;
        }

        console.log('Nmap scan result:', stdout);
        parseNmapOutput(stdout);
    });
}

// Function to parse the Nmap output and store results in the database
function parseNmapOutput(output) {
    // Regular expression to extract host IP and hostname from Nmap output
    const hostPattern = /Nmap scan report for (\d+\.\d+\.\d+\.\d+).*?OS details: (.*?)\s*Host is up/g;
    let match;

    // Parse each host found in the Nmap output
    while ((match = hostPattern.exec(output)) !== null) {
        const ipAddress = match[1].trim();
        const osType = match[2].trim();
        const hostname = ipAddress; // Default to IP as hostname if not available

        console.log(`Found host: ${ipAddress} (${hostname}) ${osType}`);

        // Store the discovered host in the PostgreSQL database
        storeHostInDatabase(ipAddress, hostname, osType);
    }
}

// Function to store discovered hosts in PostgreSQL database
function storeHostInDatabase(ipAddress, hostname, osType) {
    db.none('INSERT INTO hosts(ip_address, hostname, os_type ) VALUES($1, $2, $3)', [ipAddress, hostname, osType])
        .then(() => {
            console.log(`Stored host: ${ipAddress} (${hostname})`);
        })
        .catch((err) => {
            console.error('Error storing host:', err);
        });
}

// Run the network scan
scanNetwork();