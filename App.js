import React, { useState, useEffect } from 'react';
import {
    SafeAreaView,
    ScrollView,
    View,
    Text,
    TextInput,
    TouchableOpacity,
    StyleSheet,
    Alert,
    ActivityIndicator,
    AsyncStorage,
    Linking,
    Platform,
    BiometricPrompt,
} from 'react-native';
import { createSecureStorage } from './storage';
import RNBiometrics from 'react-native-biometrics';
import DeviceInfo from 'react-native-device-info';
import { PERMISSIONS, request } from 'react-native-permissions';
import CryptoJS from 'crypto-js';

// ========== APP SECURITY: Secure Storage ==========
const secureStorage = createSecureStorage();

// ========== APP SECURITY: Biometric Auth ==========
const biometrics = new RNBiometrics();

// ========== APP SECURITY: API Client ==========
const API_BASE = 'https://api.securebank.com';

class SecureAPIClient {
    constructor() {
        this.token = null;
        this.deviceId = null;
    }

    async init() {
        this.deviceId = await DeviceInfo.getUniqueId();
        this.token = await secureStorage.getItem('access_token');
    }

    async request(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            'X-Device-ID': this.deviceId,
            'X-App-Version': DeviceInfo.getVersion(),
            ...options.headers,
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, {
                ...options,
                headers,
                timeout: 10000,
            });

            if (response.status === 401) {
                // Token expired, try refresh
                await this.refreshToken();
                return this.request(endpoint, options);
            }

            return response.json();
        } catch (error) {
            throw new Error(`API Error: ${error.message}`);
        }
    }

    async refreshToken() {
        const refreshToken = await secureStorage.getItem('refresh_token');
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }

        const response = await fetch(`${API_BASE}/api/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken }),
        });

        const data = await response.json();
        this.token = data.access_token;
        await secureStorage.setItem('access_token', this.token);
        await secureStorage.setItem('refresh_token', data.refresh_token);
    }
}

const api = new SecureAPIClient();

// ========== MAIN APP ==========
const App = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [loading, setLoading] = useState(true);
    const [biometricAvailable, setBiometricAvailable] = useState(false);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mfaToken, setMfaToken] = useState('');
    const [showMFA, setShowMFA] = useState(false);

    useEffect(() => {
        initApp();
    }, []);

    const initApp = async () => {
        try {
            await api.init();
            
            // Check biometric availability
            const available = await biometrics.isSensorAvailable();
            setBiometricAvailable(available.available);

            // Check if user is already authenticated
            const token = await secureStorage.getItem('access_token');
            if (token) {
                // Verify token
                const valid = await validateToken(token);
                if (valid) {
                    setIsAuthenticated(true);
                }
            }
        } catch (error) {
            console.error('Init error:', error);
        } finally {
            setLoading(false);
        }
    };

    const validateToken = async (token) => {
        try {
            const response = await api.request('/api/auth/validate', {
                headers: { Authorization: `Bearer ${token}` }
            });
            return response.valid;
        } catch {
            return false;
        }
    };

    // ========== APP SECURITY: Login with Biometrics ==========
    const loginWithBiometrics = async () => {
        try {
            const { success, error } = await biometrics.simplePrompt({
                promptMessage: 'Authenticate to access SecureBank',
                cancelButtonText: 'Cancel',
            });

            if (success) {
                const storedEmail = await secureStorage.getItem('email');
                if (storedEmail) {
                    // Auto-login
                    await login(storedEmail, await secureStorage.getItem('password'));
                }
            }
        } catch (error) {
            Alert.alert('Biometric Failed', error.message);
        }
    };

    // ========== APP SECURITY: Login ==========
    const login = async (email, password) => {
        setLoading(true);
        try {
            const response = await api.request('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password }),
            });

            if (response.mfa_required) {
                setShowMFA(true);
                setEmail(email);
                return;
            }

            await secureStorage.setItem('access_token', response.token);
            await secureStorage.setItem('refresh_token', response.refresh_token);
            await secureStorage.setItem('email', email);
            
            if (biometricAvailable) {
                await secureStorage.setItem('password', password);
            }

            setIsAuthenticated(true);
            Alert.alert('Success', 'Login successful!');
        } catch (error) {
            Alert.alert('Login Failed', error.message);
        } finally {
            setLoading(false);
        }
    };

    // ========== APP SECURITY: MFA Verification ==========
    const verifyMFA = async () => {
        try {
            const response = await api.request('/api/mfa/verify-login', {
                method: 'POST',
                body: JSON.stringify({ 
                    email, 
                    token: mfaToken,
                    backupCode: mfaToken // Same field for simplicity
                }),
            });

            await secureStorage.setItem('access_token', response.token);
            setIsAuthenticated(true);
            setShowMFA(false);
            Alert.alert('Success', 'MFA verified!');
        } catch (error) {
            Alert.alert('MFA Failed', error.message);
        }
    };

    // ========== APP SECURITY: Logout ==========
    const logout = async () => {
        await secureStorage.removeItem('access_token');
        await secureStorage.removeItem('refresh_token');
        await secureStorage.removeItem('password');
        setIsAuthenticated(false);
        setShowMFA(false);
    };

    // ========== APP SECURITY: Device Security Check ==========
    const checkDeviceSecurity = async () => {
        const isRooted = await DeviceInfo.isRooted();
        const isEmulator = await DeviceInfo.isEmulator();
        const hasSecureHardware = await DeviceInfo.hasSecureHardware();

        let warnings = [];
        if (isRooted) warnings.push('Device is rooted - security risk');
        if (isEmulator) warnings.push('Running on emulator');
        if (!hasSecureHardware) warnings.push('No secure hardware');

        if (warnings.length > 0) {
            Alert.alert('Security Warning', warnings.join('\n'));
        }
    };

    if (loading) {
        return (
            <View style={styles.centered}>
                <ActivityIndicator size="large" color="#0056b3" />
                <Text style={styles.loadingText}>Loading SecureBank...</Text>
            </View>
        );
    }

    if (showMFA) {
        return (
            <SafeAreaView style={styles.container}>
                <View style={styles.mfaContainer}>
                    <Text style={styles.title}>🔐 MFA Required</Text>
                    <Text style={styles.subtitle}>
                        Enter code from authenticator app
                    </Text>
                    <TextInput
                        style={styles.mfaInput}
                        placeholder="6-digit code"
                        keyboardType="number-pad"
                        maxLength={6}
                        value={mfaToken}
                        onChangeText={setMfaToken}
                    />
                    <TouchableOpacity 
                        style={styles.button}
                        onPress={verifyMFA}>
                        <Text style={styles.buttonText}>Verify</Text>
                    </TouchableOpacity>
                    
                    <TouchableOpacity 
                        style={[styles.button, styles.backupButton]}
                        onPress={() => {
                            Alert.alert('Backup Code', 'Enter backup code');
                        }}>
                        <Text style={styles.buttonText}>Use Backup Code</Text>
                    </TouchableOpacity>
                </View>
            </SafeAreaView>
        );
    }

    if (!isAuthenticated) {
        return (
            <SafeAreaView style={styles.container}>
                <ScrollView contentContainerStyle={styles.loginContainer}>
                    <Text style={styles.logo}>🏦</Text>
                    <Text style={styles.title}>SecureBank</Text>
                    
                    {biometricAvailable && (
                        <TouchableOpacity 
                            style={[styles.button, styles.biometricButton]}
                            onPress={loginWithBiometrics}>
                            <Text style={styles.buttonText}>👆 Login with Biometrics</Text>
                        </TouchableOpacity>
                    )}

                    <View style={styles.divider}>
                        <Text>or</Text>
                    </View>

                    <TextInput
                        style={styles.input}
                        placeholder="Email"
                        value={email}
                        onChangeText={setEmail}
                        autoCapitalize="none"
                        keyboardType="email-address"
                    />
                    
                    <TextInput
                        style={styles.input}
                        placeholder="Password"
                        value={password}
                        onChangeText={setPassword}
                        secureTextEntry
                    />

                    <TouchableOpacity 
                        style={styles.button}
                        onPress={() => login(email, password)}>
                        <Text style={styles.buttonText}>Login</Text>
                    </TouchableOpacity>

                    <TouchableOpacity 
                        onPress={() => Linking.openURL('https://securebank.com/register')}>
                        <Text style={styles.link}>Create Account</Text>
                    </TouchableOpacity>

                    <TouchableOpacity 
                        onPress={checkDeviceSecurity}>
                        <Text style={styles.link}>🔒 Check Device Security</Text>
                    </TouchableOpacity>
                </ScrollView>
            </SafeAreaView>
        );
    }

    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.header}>
                <Text style={styles.headerTitle}>🏦 SecureBank</Text>
                <TouchableOpacity onPress={logout}>
                    <Text style={styles.logoutText}>Logout</Text>
                </TouchableOpacity>
            </View>
            
            <ScrollView style={styles.dashboard}>
                <View style={styles.balanceCard}>
                    <Text style={styles.balanceLabel}>Total Balance</Text>
                    <Text style={styles.balanceAmount}>$5,432.10</Text>
                </View>

                <View style={styles.transferSection}>
                    <Text style={styles.sectionTitle}>Transfer Money</Text>
                    <TextInput
                        style={styles.input}
                        placeholder="Recipient"
                    />
                    <TextInput
                        style={styles.input}
                        placeholder="Amount"
                        keyboardType="numeric"
                    />
                    <TouchableOpacity style={styles.button}>
                        <Text style={styles.buttonText}>Send</Text>
                    </TouchableOpacity>
                </View>

                <View style={styles.recentSection}>
                    <Text style={styles.sectionTitle}>Recent Transactions</Text>
                    <View style={styles.transaction}>
                        <Text>Received from John</Text>
                        <Text style={styles.positive}>+$500.00</Text>
                    </View>
                    <View style={styles.transaction}>
                        <Text>Transfer to Alice</Text>
                        <Text style={styles.negative}>-$100.00</Text>
                    </View>
                </View>
            </ScrollView>
        </SafeAreaView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#f5f5f5',
    },
    centered: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    loginContainer: {
        padding: 20,
        justifyContent: 'center',
        flex: 1,
    },
    logo: {
        fontSize: 80,
        textAlign: 'center',
        marginBottom: 10,
    },
    title: {
        fontSize: 32,
        fontWeight: 'bold',
        textAlign: 'center',
        color: '#0056b3',
        marginBottom: 30,
    },
    input: {
        backgroundColor: 'white',
        borderRadius: 8,
        padding: 15,
        marginBottom: 15,
        borderWidth: 1,
        borderColor: '#ddd',
    },
    button: {
        backgroundColor: '#0056b3',
        padding: 15,
        borderRadius: 8,
        marginVertical: 10,
    },
    buttonText: {
        color: 'white',
        textAlign: 'center',
        fontWeight: 'bold',
        fontSize: 16,
    },
    biometricButton: {
        backgroundColor: '#28a745',
    },
    backupButton: {
        backgroundColor: '#6c757d',
    },
    mfaContainer: {
        flex: 1,
        justifyContent: 'center',
        padding: 20,
        backgroundColor: 'white',
    },
    mfaInput: {
        backgroundColor: '#f8f9fa',
        borderRadius: 8,
        padding: 20,
        fontSize: 24,
        textAlign: 'center',
        marginVertical: 20,
        borderWidth: 1,
        borderColor: '#ddd',
    },
    divider: {
        alignItems: 'center',
        marginVertical: 20,
    },
    link: {
        color: '#0056b3',
        textAlign: 'center',
        marginVertical: 10,
    },
    header: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        padding: 20,
        backgroundColor: 'white',
        borderBottomWidth: 1,
        borderBottomColor: '#ddd',
    },
    headerTitle: {
        fontSize: 20,
        fontWeight: 'bold',
        color: '#0056b3',
    },
    logoutText: {
        color: '#dc3545',
        fontWeight: 'bold',
    },
    dashboard: {
        padding: 20,
    },
    balanceCard: {
        backgroundColor: '#0056b3',
        padding: 20,
        borderRadius: 10,
        marginBottom: 20,
    },
    balanceLabel: {
        color: 'white',
        fontSize: 14,
    },
    balanceAmount: {
        color: 'white',
        fontSize: 36,
        fontWeight: 'bold',
        marginTop: 5,
    },
    transferSection: {
        backgroundColor: 'white',
        padding: 20,
        borderRadius: 10,
        marginBottom: 20,
    },
    sectionTitle: {
        fontSize: 18,
        fontWeight: 'bold',
        marginBottom: 15,
        color: '#333',
    },
    recentSection: {
        backgroundColor: 'white',
        padding: 20,
        borderRadius: 10,
    },
    transaction: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 10,
        borderBottomWidth: 1,
        borderBottomColor: '#eee',
    },
    positive: {
        color: '#28a745',
        fontWeight: 'bold',
    },
    negative: {
        color: '#dc3545',
        fontWeight: 'bold',
    },
    loadingText: {
        marginTop: 10,
        color: '#666',
    },
});

export default App;
