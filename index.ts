import { createCipheriv, createDecipheriv, randomBytes, scryptSync, createHash } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';

export class MiniKV {
    #key: Buffer;
    #filePath: string;

    /**
     * Creates a new MiniKV instance.
     * @param {string} password - The password used to encrypt and decrypt data.
     * @param {string} [filePath='kvstore.db'] - The path and name of the database file.
     */
    constructor(password: string, filePath: string = 'kvstore.db') {
        this.#key = scryptSync(password, 'salt', 32);
        this.#filePath = filePath;
        if (!existsSync(filePath)) {
            writeFileSync(filePath, '');
        }
    }

    /**
     * Encrypts the given text.
     * @param {string} text - The text to encrypt.
     * @returns {string} The encrypted text.
     */
    #encrypt(text: string): string {
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-ctr', this.#key, iv);
        const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
        return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
    }

    /**
     * Decrypts the given text.
     * @param {string} text - The text to decrypt.
     * @returns {string} The decrypted text.
     */
    #decrypt(text: string): string {
        const [ivHex, encryptedHex] = text.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const encryptedText = Buffer.from(encryptedHex, 'hex');
        const decipher = createDecipheriv('aes-256-ctr', this.#key, iv);
        const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        return decrypted.toString();
    }

    /**
     * Hashes the given key.
     * @param {string} key - The key to hash.
     * @returns {string} The hashed key.
     */
    #hashKey = (key: string): string =>
        createHash('sha256').update(key).digest('hex');

    /**
     * Sets a key-value pair in the store.
     * @param {string} key - The key to set.
     * @param {string} value - The value to set.
     */
    set(key: string, value: string): void {
        const hashedKey = this.#hashKey(key);
        const encryptedValue = this.#encrypt(value);
        const data = this.#readData();
        data[hashedKey] = encryptedValue;
        this.#writeData(data);
    }

    /**
     * Gets the value associated with the given key.
     * @param {string} key - The key to retrieve.
     * @returns {string | undefined} The value associated with the key, or undefined if not found.
     */
    get(key: string): string | undefined {
        const hashedKey = this.#hashKey(key);
        const data = this.#readData();
        const encryptedValue = data[hashedKey];
        return encryptedValue ? this.#decrypt(encryptedValue) : undefined;
    }

    /**
     * Deletes the key-value pair associated with the given key.
     * @param {string} key - The key to delete.
     */
    delete(key: string): void {
        const hashedKey = this.#hashKey(key);
        const data = this.#readData();
        delete data[hashedKey];
        this.#writeData(data);
    }

    /**
     * Reads data from the file.
     * @returns {Record<string, string>} The data read from the file.
     */
    #readData = (): Record<string, string> => {
        try {
            const fileContent = readFileSync(this.#filePath, 'utf-8');
            return fileContent ? JSON.parse(fileContent) : {};
        } catch {
            return {};
        }
    }

    /**
     * Writes data to the file.
     * @param {Record<string, string>} data - The data to write to the file.
     */
    #writeData(data: Record<string, string>): void {
        writeFileSync(this.#filePath, JSON.stringify(data), 'utf-8');
    }
}