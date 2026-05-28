//this part of code is ai wirtten !!
// Helper to convert raw binary ArrayBuffer to a standard Base64 string
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Helper to convert a Base64 string back into a raw binary Uint8Array
function base64ToUint8Array(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Stretches a simple user password into a secure 256-bit cryptographic key
 */
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    
    // 1. Import the plain text password as raw key material
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    // 2. Run it through the PBKDF2 blender 100,000 times
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: encoder.encode(salt), // We pass the user's email as the salt
            iterations: 100000,         // High iterations protect against brute-force guessing
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, // Target algorithm
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts a plain text note into a secure string containing the IV and Ciphertext
 */
export async function encryptNote(plainText, password, userEmail) {
    try {
        const encoder = new TextEncoder();
        
        // 1. Generate the shared Master Key
        const key = await deriveKey(password, userEmail);
        
        // 2. Generate a random 12-byte Initialization Vector (IV)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // 3. Encrypt the plaintext string using AES-GCM
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encoder.encode(plainText)
        );

        // 4. Convert the binary IV and Ciphertext outputs to Base64 text strings
        const base64Iv = arrayBufferToBase64(iv.buffer);
        const base64Ciphertext = arrayBufferToBase64(encryptedBuffer);

        // 5. Combine them using a colon separator
        return `${base64Iv}:${base64Ciphertext}`;
        
    } catch (error) {
        console.error("Encryption process failed:", error);
        throw new Error("Could not secure the note content.");
    }
}

/**
 * Reverses the encryption process to transform ciphertext back into readable text
 */
export async function decryptNote(combinedStr, password, userEmail) {
    try {
        const decoder = new TextDecoder();

        // 1. Split the incoming payload back into IV and Ciphertext strings
        const parts = combinedStr.split(":");
        const base64Iv = parts[0];
        const base64Ciphertext = parts[1];

        // 2. Reconstruct the raw binary components from the Base64 text strings
        const ivBytes = base64ToUint8Array(base64Iv);
        const ciphertextBuffer = base64ToUint8Array(base64Ciphertext).buffer;

        // 3. Re-derive the exact same Master Key using the password and email salt
        const key = await deriveKey(password, userEmail);

        // 4. Run the AES-GCM decryption tool
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBytes },
            key,
            ciphertextBuffer
        );

        // 5. Decode the raw output back into a human-readable string
        return decoder.decode(decryptedBuffer);

    } catch (error) {
        console.error("Decryption process failed:", error);
        throw new Error("Decryption failed. Invalid password or corrupted file structure.");
    }
}