package com.rnbiometrics;

import android.app.Activity;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.content.Context;
import android.content.Intent;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.AuthenticationCallback;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import android.app.KeyguardManager;
import android.util.Log;

import static android.app.Activity.RESULT_OK;

/**
 * Created by brandon on 4/5/18.
 */

public class ReactNativeBiometrics extends ReactContextBaseJavaModule  {

    private static final int INTENT_AUTHENTICATE = 1234;
    public static final int REQUEST_PWD_PROMPT = 1;

    protected String biometricKeyAlias = "biometric_key";

    public ReactNativeBiometrics(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "ReactNativeBiometrics";
    }

    @ReactMethod
    public void isSensorAvailable(Promise promise) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                Context context = getReactApplicationContext();
                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                int canAuthenticate = biometricManager.canAuthenticate();
                KeyguardManager keyguardManager = (KeyguardManager) reactApplicationContext.getSystemService(Context.KEYGUARD_SERVICE);
                boolean secure=keyguardManager.isKeyguardSecure();
                Log.v("Secure","is device secure " + secure);
                if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                    WritableMap resultMap = new WritableNativeMap();
                    resultMap.putBoolean("available", true);
                    resultMap.putBoolean("secure", secure);
                    resultMap.putString("biometryType", "Biometrics");
                    promise.resolve(resultMap);
                } else {
                    WritableMap resultMap = new WritableNativeMap();
                    resultMap.putBoolean("available", false);

                    switch (canAuthenticate) {
                        case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                            resultMap.putString("error", "BIOMETRIC_ERROR_NO_HARDWARE");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                            resultMap.putString("error", "BIOMETRIC_ERROR_HW_UNAVAILABLE");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                            resultMap.putString("error", "BIOMETRIC_ERROR_NONE_ENROLLED");
                            break;
                    }
                    resultMap.putBoolean("secure", secure);
                    promise.resolve(resultMap);
                }
            } 
            else {
                WritableMap resultMap = new WritableNativeMap();
                resultMap.putBoolean("available", false);
                resultMap.putString("error", "Unsupported android version");
                promise.resolve(resultMap);
            }
        } catch (Exception e) {
            promise.reject("Error detecting biometrics availability: " + e.getMessage(), "Error detecting biometrics availability: " + e.getMessage());
        }
    }

    @ReactMethod
    public void createKeys(Promise promise) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                deleteBiometricKey();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,"AndroidKeyStore");
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(biometricKeyAlias, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                        // .setUserAuthenticationRequired(true)
                        // .setUserAuthenticationValidityDurationSeconds(10)
                        .build();
                keyPairGenerator.initialize(keyGenParameterSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                PublicKey publicKey = keyPair.getPublic();
                byte[] encodedPublicKey = publicKey.getEncoded();
                String publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT);
                publicKeyString = publicKeyString.replaceAll("\r", "").replaceAll("\n", "");

                WritableMap resultMap = new WritableNativeMap();
                resultMap.putString("publicKey", publicKeyString);
                promise.resolve(resultMap);
            } else {
                promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
            }
        } catch (Exception e) {
            promise.reject("Error generating public private keys: " + e.getMessage(), "Error generating public private keys");
        }
    }

    @ReactMethod
    public void deleteKeys(Promise promise) {
        if (doesBiometricKeyExist()) {
            boolean deletionSuccessful = deleteBiometricKey();

            if (deletionSuccessful) {
                WritableMap resultMap = new WritableNativeMap();
                resultMap.putBoolean("keysDeleted", true);
                promise.resolve(resultMap);
            } else {
                promise.reject("Error deleting biometric key from keystore", "Error deleting biometric key from keystore");
            }
        } else {
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("keysDeleted", false);
            promise.resolve(resultMap);
        }
    }

    @ReactMethod
    public void createSignature(final ReadableMap params, final Promise promise) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                String cancelButtomText = params.getString("cancelButtonText"); 
                                String promptMessage = params.getString("promptMessage");
                                final String payload = params.getString("payload");
                                final String requestFrom = params.getString("requestFrom");
                                Log.v("request form ",requestFrom);
                                final Signature signature = Signature.getInstance("SHA256withRSA");
                                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                                keyStore.load(null);

                                PrivateKey privateKey = (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
                                signature.initSign(privateKey);

                                BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
                                final AuthenticationCallback authCallback = new CreateSignatureCallback(promise, payload);
                                FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                Executor executor = Executors.newSingleThreadExecutor();
                                BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);
                                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                                Context context = getReactApplicationContext();
                                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                                int canAuthenticate = biometricManager.canAuthenticate();
                                if(canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS && (requestFrom.equals("otp") || requestFrom.equals("login"))){
                                        Log.v("inside biometrics","requestFrom :"+requestFrom);
                                        PromptInfo promptInfo = new PromptInfo.Builder()
                                        .setDeviceCredentialAllowed(false)
                                        .setNegativeButtonText(cancelButtomText)
                                        .setTitle(promptMessage)
                                        .build();
                                        biometricPrompt.authenticate(promptInfo,cryptoObject);
                                }
                                else if(canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS && (requestFrom.equals("otp") || requestFrom.equals("login"))){
                                        Log.v("inside biometrics","requestFrom :"+requestFrom);
                                        WritableMap resultMap = new WritableNativeMap();
                                        resultMap.putBoolean("success", false);
                                        promise.resolve(resultMap);
                                }
                                else{ 
                                        Log.v("inside else","requestFrom :"+requestFrom);
                                        KeyguardManager keyguardManager = (KeyguardManager) reactApplicationContext.getSystemService(Context.KEYGUARD_SERVICE);
                                        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("Syfe", "Please confirm your screen lock PIN, pattern or password");

                                        ActivityEventListener activityEventListener= new ActivityEventListener() {
                                            @Override
                                            public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
                                                if (requestCode == REQUEST_PWD_PROMPT) {
                                                    // ..it is. Did the user get the password right?
                                                    if (resultCode == RESULT_OK) {
                                                        try {                                            
                                                            signature.update(payload.getBytes());
                                                            byte[] signed = signature.sign();
                                                            String signedString = Base64.encodeToString(signed, Base64.DEFAULT);
                                                            signedString = signedString.replaceAll("\r", "").replaceAll("\n", "");
                                                            Log.v("In CreateSIGNATURE", "cryptosignature " + signature);
                                                            WritableMap resultMap = new WritableNativeMap();
                                                            resultMap.putBoolean("success", true);
                                                            resultMap.putString("signature", signedString);
                                                            promise.resolve(resultMap);
                                                        }catch (Exception e){
                                                            Log.v("ExceptionSignature","##########################exception "+e);
                                                        }
                                                    } else{
                                                        Log.v("ActResult", "requestCode" + requestCode);
                                                        WritableMap resultMap = new WritableNativeMap();
                                                        resultMap.putBoolean("success", false);
                                                        promise.resolve(resultMap);
                                                    }
                                                }else{
                                                    WritableMap resultMap = new WritableNativeMap();
                                                    resultMap.putBoolean("success", false);
                                                    promise.resolve(resultMap);
                                                }
                                            }
                                            @Override
                                            public void onNewIntent(Intent intent) {

                                            }
                                        };
                                        reactApplicationContext.addActivityEventListener(activityEventListener);
                                        fragmentActivity.startActivityForResult(intent, REQUEST_PWD_PROMPT);
                                       
                                }
                                
                            } catch (Exception e) {
                                promise.reject("Error signing payload: " + e.getMessage(), "Error generating signature:4234234234234234234 " + e.getMessage());
                            }
                        }
                    });
        } else {
            promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
        }
    }
    @ReactMethod
    public void simplePrompt(final ReadableMap params, final Promise promise) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                String cancelButtomText = params.getString("cancelButtonText");
                                String promptMessage = params.getString("promptMessage");
                                AuthenticationCallback authCallback = new SimplePromptCallback(promise);
                                FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                Executor executor = Executors.newSingleThreadExecutor();
                                BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

                                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                                Context context = getReactApplicationContext();
                                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                                int canAuthenticate = biometricManager.from(context).canAuthenticate();
                                Log.v("simplePrompt","canauthenticate" + canAuthenticate);
                                if(canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS){
                                    KeyguardManager keyguardManager = (KeyguardManager) reactApplicationContext.getSystemService(Context.KEYGUARD_SERVICE);
                                    Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("Syfe", "Please confirm your screen lock PIN, pattern or password");

                                    ActivityEventListener activityEventListener= new ActivityEventListener() {
                                        @Override
                                        public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
                                            if (requestCode == REQUEST_PWD_PROMPT) {
                                                // ..it is. Did the user get the password right?
                                                if (resultCode == RESULT_OK) {
                                                        Log.v("ActResult", "activityResult" + resultCode);
                                                        WritableMap resultMap = new WritableNativeMap();
                                                        resultMap.putBoolean("success", true);
                                                        promise.resolve(resultMap);
                                                } else {
                                                    Log.v("ActResult", "activityResult" + resultCode);
                                                    WritableMap resultMap = new WritableNativeMap();
                                                    resultMap.putBoolean("success", false);
                                                    promise.resolve(resultMap);
                                                    // they got it wrong/cancelled
                                                }
                                            }else{
                                                Log.v("ActResult", "requestCode" + requestCode);
                                                WritableMap resultMap = new WritableNativeMap();
                                                resultMap.putBoolean("success", false);
                                                promise.resolve(resultMap);
                                            }
                                        }
                                        @Override
                                        public void onNewIntent(Intent intent) {

                                        }
                                    };
                                    reactApplicationContext.addActivityEventListener(activityEventListener);
                                    fragmentActivity.startActivityForResult(intent, REQUEST_PWD_PROMPT);
                                }else{
                                    Log.v("simplePrompt","===in else canauthenticate");
                                    KeyguardManager keyguardManager = (KeyguardManager) reactApplicationContext.getSystemService(Context.KEYGUARD_SERVICE);
                                    Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("Syfe", "Please confirm your screen lock PIN, pattern or password");

                                    ActivityEventListener activityEventListener= new ActivityEventListener() {
                                        @Override
                                        public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
                                            if (requestCode == REQUEST_PWD_PROMPT) {
                                                // ..it is. Did the user get the password right?
                                                if (resultCode == RESULT_OK) {
                                                        Log.v("ActResult", "activityResult" + resultCode);
                                                        WritableMap resultMap = new WritableNativeMap();
                                                        resultMap.putBoolean("success", true);
                                                        promise.resolve(resultMap);
                                                } else {
                                                    Log.v("ActResult", "activityResult" + resultCode);
                                                    WritableMap resultMap = new WritableNativeMap();
                                                    resultMap.putBoolean("success", false);
                                                    promise.resolve(resultMap);
                                                    // they got it wrong/cancelled
                                                }
                                            }else{
                                                Log.v("ActResult", "requestCode" + requestCode);
                                                WritableMap resultMap = new WritableNativeMap();
                                                resultMap.putBoolean("success", false);
                                                promise.resolve(resultMap);
                                            }
                                        }
                                        @Override
                                        public void onNewIntent(Intent intent) {

                                        }
                                    };
                                    reactApplicationContext.addActivityEventListener(activityEventListener);
                                    fragmentActivity.startActivityForResult(intent, REQUEST_PWD_PROMPT);
                                }
                            } catch (Exception e) {
                                promise.reject("Error displaying local biometric prompt: " + e.getMessage(), "Error displaying local biometric prompt: " + e.getMessage());
                            }
                        }
                    });
        } else {
            promise.reject("Cannot display biometric prompt on android versions below 6.0", "Cannot display biometric prompt on android versions below 6.0");
        }
    }

    @ReactMethod
    public void biometricKeysExist(Promise promise) {
        try {
            boolean doesBiometricKeyExist = doesBiometricKeyExist();
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("keysExist", doesBiometricKeyExist);
            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject("Error checking if biometric key exists: " + e.getMessage(), "Error checking if biometric key exists: " + e.getMessage());
        }
    }

    protected boolean doesBiometricKeyExist() {
      try {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        return keyStore.containsAlias(biometricKeyAlias);
      } catch (Exception e) {
        return false;
      }
    }

    protected boolean deleteBiometricKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyStore.deleteEntry(biometricKeyAlias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    private PrivateKey generateSecretKey(){
        PrivateKey privateKey=null;
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            privateKey= (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
        }catch (Exception e){
            Log.v("THIS IS THE KEY","CHECK EXCEPTION "+e);
        }
        return privateKey;
    }
}
