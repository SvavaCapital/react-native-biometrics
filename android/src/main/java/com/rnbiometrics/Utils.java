package com.rnbiometrics;

import android.util.Base64;
import android.util.Log;

import java.security.PrivateKey;
import java.security.interfaces.RSAKey;

public class Utils {
    public static String getPrivateString(PrivateKey privateKey) {
        try {
            String privateKeyString = Base64.encodeToString(((RSAKey) privateKey).getModulus().toByteArray(), Base64.DEFAULT);
            privateKeyString = privateKeyString.replaceAll("\r", "").replaceAll("\n", "");
            return privateKeyString.substring(0, 10) + "..." + privateKeyString.substring(privateKeyString.length() - 10);
        } catch (Exception e) {
            Log.e("KeyError", "Error processing private key", e);
            return null; // Return null if an exception occurs
        }
    }
}
