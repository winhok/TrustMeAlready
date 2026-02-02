package com.virb3.trustmealready;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import android.net.http.SslError;
import android.net.http.X509TrustManagerExtensions;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import static de.robv.android.xposed.XC_MethodReplacement.DO_NOTHING;
import static de.robv.android.xposed.XposedHelpers.*;

public class Main implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    private static final String TAG = "TrustMeAlready";
    private static final String SSL_CLASS_NAME = "com.android.org.conscrypt.TrustManagerImpl";
    private static final String SSL_METHOD_NAME = "checkTrustedRecursive";
    private static final Class<?> SSL_RETURN_TYPE = List.class;
    private static final Class<?> SSL_RETURN_PARAM_TYPE = X509Certificate.class;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
        Log.d(TAG, message);
    }

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        log("TrustMeAlready loading...");
        int hookedMethods = 0;

        for (Method method : findClass(SSL_CLASS_NAME, null).getDeclaredMethods()) {
            if (!checkSSLMethod(method)) {
                continue;
            }

            List<Object> params = new ArrayList<>();
            params.addAll(Arrays.asList(method.getParameterTypes()));
            params.add(new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return new ArrayList<X509Certificate>();
                }
            });

            log("Hooking method: " + method.toString());
            findAndHookMethod(SSL_CLASS_NAME, null, SSL_METHOD_NAME, params.toArray());
            hookedMethods++;
        }

        log(String.format(Locale.ENGLISH, "TrustMeAlready loaded! Hooked %d methods", hookedMethods));
    }

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        log("TrustMeAlready hooking WebView for: " + lpparam.packageName);

        /* WebView Hooks */
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        findAndHookMethod("android.webkit.WebViewClient", lpparam.classLoader, "onReceivedSslError",
                WebView.class, SslErrorHandler.class, SslError.class, new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        ((SslErrorHandler) param.args[1]).proceed();
                        return null;
                    }
                });

        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedError(WebView, int, String, String) */
        findAndHookMethod("android.webkit.WebViewClient", lpparam.classLoader, "onReceivedError",
                WebView.class, int.class, String.class, String.class, DO_NOTHING);

        /* Additional hooks from JustTrustMe that affect WebView SSL validation */
        /* X509TrustManagerExtensions */
        try {
            findAndHookMethod(X509TrustManagerExtensions.class, "checkServerTrusted", X509Certificate[].class, String.class, String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return param.args[0];
                }
            });
        } catch (Throwable ignored) {
        }

        /* NetworkSecurityTrustManager */
        try {
            findAndHookMethod("android.security.net.config.NetworkSecurityTrustManager", lpparam.classLoader, "checkPins", List.class, DO_NOTHING);
        } catch (Throwable ignored) {
        }
    }

    private boolean checkSSLMethod(Method method) {
        if (!method.getName().equals(SSL_METHOD_NAME)) {
            return false;
        }

        // check return type
        if (!SSL_RETURN_TYPE.isAssignableFrom(method.getReturnType())) {
            return false;
        }

        // check if parameterized return type
        Type returnType = method.getGenericReturnType();
        if (!(returnType instanceof ParameterizedType)) {
            return false;
        }

        // check parameter type
        Type[] args = ((ParameterizedType) returnType).getActualTypeArguments();
        if (args.length != 1 || !(args[0].equals(SSL_RETURN_PARAM_TYPE))) {
            return false;
        }

        return true;
    }
}