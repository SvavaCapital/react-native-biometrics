package com.rnbiometrics;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import android.util.Log;
public class SimplePromptCallback extends BiometricPrompt.AuthenticationCallback {
    private Promise promise;

    public SimplePromptCallback(Promise promise) {
        super();
        this.promise = promise;
    }

    @Override
    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        Log.v("error1", "User cancellation"+errorCode);
        if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("success", false);
            Log.v("error2", "User cancellation");
            resultMap.putString("error", "User cancellation");
            this.promise.resolve(resultMap);
        } else {
            this.promise.reject(errString.toString(), errString.toString());
        }
    }

    @Override
    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        Log.v("success","success"+result);
        WritableMap resultMap = new WritableNativeMap();
        resultMap.putBoolean("success", true);
        this.promise.resolve(resultMap);

    }
}
