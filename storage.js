// ========== APP SECURITY: Encrypted Storage ==========
import AsyncStorage from '@react-native-async-storage/async-storage';
import CryptoJS from 'crypto-js';
import { Platform } from 'react-native';
import Keychain from 'react-native-keychain';

// Use Keychain for Android/iOS for extra security
const ENCRYPTION_KEY = process.env.STORAGE_ENCRYPTION_KEY || 'your-secure-key';

export const createSecureStorage = () => {
    const encrypt = (data) => {
        return CryptoJS.AES.encrypt(data, ENCRYPTION_KEY).toString();
    };

    const decrypt = (encrypted) => {
        const bytes = CryptoJS.AES.decrypt(encrypted, ENCRYPTION_KEY);
        return bytes.toString(CryptoJS.enc.Utf8);
    };

    return {
        // ========== APP SECURITY: Set with encryption ==========
        setItem: async (key, value) => {
            try {
                if (Platform.OS === 'ios' || Platform.OS === 'android') {
                    await Keychain.setInternetCredentials(
                        `securebank_${key}`,
                        key,
                        value
                    );
                } else {
                    const encrypted = encrypt(value);
                    await AsyncStorage.setItem(key, encrypted);
                }
            } catch (error) {
                console.error('Storage error:', error);
                throw error;
            }
        },

        // ========== APP SECURITY: Get with decryption ==========
        getItem: async (key) => {
            try {
                if (Platform.OS === 'ios' || Platform.OS === 'android') {
                    const credentials = await Keychain.getInternetCredentials(
                        `securebank_${key}`
                    );
                    return credentials ? credentials.password : null;
                } else {
                    const encrypted = await AsyncStorage.getItem(key);
                    if (!encrypted) return null;
                    return decrypt(encrypted);
                }
            } catch (error) {
                console.error('Storage error:', error);
                return null;
            }
        },

        // ========== APP SECURITY: Remove item ==========
        removeItem: async (key) => {
            try {
                if (Platform.OS === 'ios' || Platform.OS === 'android') {
                    await Keychain.resetInternetCredentials(`securebank_${key}`);
                } else {
                    await AsyncStorage.removeItem(key);
                }
            } catch (error) {
                console.error('Storage error:', error);
            }
        },

        // ========== APP SECURITY: Clear all ==========
        clear: async () => {
            try {
                if (Platform.OS === 'ios' || Platform.OS === 'android') {
                    // Clear all Keychain items
                    const keys = await AsyncStorage.getAllKeys();
                    for (const key of keys) {
                        await Keychain.resetInternetCredentials(`securebank_${key}`);
                    }
                }
                await AsyncStorage.clear();
            } catch (error) {
                console.error('Storage error:', error);
            }
        }
    };
};
