package com.rnbiometrics;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;

import javax.crypto.SecretKey;

public class CreateSignatureCallback extends BiometricPrompt.AuthenticationCallback {
    private Promise promise;
    private String payload;
    private String privateKeyString;
    protected String biometricKeyAlias = "biometric_key";

    public CreateSignatureCallback(Promise promise, String payload, String privateKeyString) {
        super();
        this.promise = promise;
        this.payload = payload;
        this.privateKeyString = privateKeyString;
    }

    @Override
    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_USER_CANCELED ) {
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("success", false);
            resultMap.putString("error", "User cancellation");
            this.promise.resolve(resultMap);
        } else {
            this.promise.reject(errString.toString(), errString.toString());
        }
    }

    @Override
    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        Signature cryptoSignature = null;

        try {
            BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
            if(cryptoObject != null){
                cryptoSignature = cryptoObject.getSignature();
            } else {
                PrivateKey newKey = generateSecretKey();
                privateKeyString = Utils.getPrivateString(newKey);
                cryptoSignature = Signature.getInstance("SHA256withRSA");
                cryptoSignature.initSign(newKey);
            }
            cryptoSignature.update(this.payload.getBytes());
            byte[] signed = cryptoSignature.sign();
            String signedString = Base64.encodeToString(signed, Base64.DEFAULT);
            signedString = signedString.replaceAll("\r", "").replaceAll("\n", "");

            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("success", true);
            resultMap.putString("signature", signedString);
            resultMap.putString("privateKey", privateKeyString);
            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject("Error creating signature: " + e.getMessage(), "Error creating signature");
        }
    }

     private PrivateKey generateSecretKey(){
        PrivateKey privateKey = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            privateKey= (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
        } catch (Exception e) {}
        return privateKey;
    }
}
