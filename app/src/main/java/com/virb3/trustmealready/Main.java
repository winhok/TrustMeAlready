package com.virb3.trustmealready;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.http.SslError;
import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import static de.robv.android.xposed.XC_MethodReplacement.DO_NOTHING;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.findClass;

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
        int hookedMethods = hookTrustManagerImpl(SSL_CLASS_NAME, null);
        log(String.format(Locale.ENGLISH, "TrustMeAlready loaded! Hooked %d methods", hookedMethods));
    }

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        log("TrustMeAlready hooking for: " + lpparam.packageName);

        /* Hook bundled Conscrypt */
        hookTrustManagerImpl(SSL_CLASS_NAME, lpparam.classLoader);
        hookTrustManagerImpl("org.conscrypt.TrustManagerImpl", lpparam.classLoader);

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

        /* public void onReceivedError(WebView, WebResourceRequest, WebResourceError) */
        try {
            findAndHookMethod("android.webkit.WebViewClient", lpparam.classLoader, "onReceivedError",
                    WebView.class, "android.webkit.WebResourceRequest", "android.webkit.WebResourceError", DO_NOTHING);
        } catch (Throwable ignored) {}

        /* JSSE Hooks */
        /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
        /* public final TrustManager[] getTrustManager() */
        try {
            findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (hasTrustManagerImpl()) {
                        Class<?> cls = findClass("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader);
                        TrustManager[] managers = (TrustManager[]) param.getResult();
                        if (managers.length > 0 && cls.isInstance(managers[0]))
                            return;
                    }
                    param.setResult(new TrustManager[]{getTrustManager()});
                }
            });
        } catch (Throwable ignored) {}

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        try {
            findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier", HostnameVerifier.class, DO_NOTHING);
            findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", javax.net.ssl.SSLSocketFactory.class, DO_NOTHING);
            findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier", HostnameVerifier.class, DO_NOTHING);
        } catch (Throwable ignored) {}

        /* SSLContext.init >> (null,ImSureItsLegitTrustManager,null) */
        try {
            findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init", KeyManager[].class, TrustManager[].class, SecureRandom.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = null;
                    param.args[1] = new TrustManager[]{getTrustManager()};
                    param.args[2] = null;
                }
            });
        } catch (Throwable ignored) {}

        /* X509TrustManagerExtensions */
        try {
            findAndHookMethod(X509TrustManagerExtensions.class, "checkServerTrusted", X509Certificate[].class, String.class, String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return Arrays.asList((X509Certificate[]) param.args[0]);
                }
            });
        } catch (Throwable ignored) {}

        /* NetworkSecurityTrustManager */
        try {
            findAndHookMethod("android.security.net.config.NetworkSecurityTrustManager", lpparam.classLoader, "checkPins", List.class, DO_NOTHING);
        } catch (Throwable ignored) {}

        /* NetworkSecurityPolicy */
        try {
            findAndHookMethod("android.security.NetworkSecurityPolicy", lpparam.classLoader, "isCleartextTrafficPermitted", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return true;
                }
            });
            findAndHookMethod("android.security.NetworkSecurityPolicy", lpparam.classLoader, "isCleartextTrafficPermitted", String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return true;
                }
            });
        } catch (Throwable ignored) {}

        /* Hook for Apache HttpClient (if used) */
        try {
            findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "verify", String.class, SSL_RETURN_TYPE, DO_NOTHING);
        } catch (Throwable ignored) {}

        /* Multi-dex support for OkHttp and others */
        try {
            findAndHookMethod("android.app.Application", lpparam.classLoader, "attach", Context.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Context context = (Context) param.args[0];
                    processOkHttp(context.getClassLoader());
                    processHttpClientAndroidLib(context.getClassLoader());
                    processXutils(context.getClassLoader());
                }
            });
        } catch (Throwable ignored) {}
    }

    private void processOkHttp(ClassLoader classLoader) {
        try {
            Class<?> pinner = findClass("com.squareup.okhttp.CertificatePinner", classLoader);
            findAndHookMethod(pinner, "check", String.class, List.class, DO_NOTHING);
        } catch (Throwable ignored) {}

        try {
            Class<?> pinner = findClass("okhttp3.CertificatePinner", classLoader);
            findAndHookMethod(pinner, "check", String.class, List.class, DO_NOTHING);
            try {
                findAndHookMethod(pinner, "check$okhttp", String.class, "kotlin.jvm.functions.Function0", DO_NOTHING);
            } catch (Throwable ignored) {}
        } catch (Throwable ignored) {}

        try {
            Class<?> verifier = findClass("okhttp3.internal.tls.OkHostnameVerifier", classLoader);
            findAndHookMethod(verifier, "verify", String.class, SSLSession.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return true;
                }
            });
            findAndHookMethod(verifier, "verify", String.class, X509Certificate.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return true;
                }
            });
        } catch (Throwable ignored) {}
    }

    private void processHttpClientAndroidLib(ClassLoader classLoader) {
        try {
            Class<?> verifier = findClass("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", classLoader);
            findAndHookMethod(verifier, "verify", String.class, String[].class, String[].class, boolean.class, DO_NOTHING);
        } catch (Throwable ignored) {}
    }

    private void processXutils(ClassLoader classLoader) {
        try {
            Class<?> params = findClass("org.xutils.http.RequestParams", classLoader);
            findAndHookMethod(params, "setSslSocketFactory", javax.net.ssl.SSLSocketFactory.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = SSLContext.getInstance("TLS").getSocketFactory();
                }
            });
            findAndHookMethod(params, "setHostnameVerifier", HostnameVerifier.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = new HostnameVerifier() {
                        @Override
                        public boolean verify(String hostname, SSLSession session) {
                            return true;
                        }
                    };
                }
            });
        } catch (Throwable ignored) {}
    }

    private boolean hasTrustManagerImpl() {
        try {
            Class.forName("com.android.org.conscrypt.TrustManagerImpl");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private TrustManager getTrustManager() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return new ImSureItsLegitExtendedTrustManager();
        } else {
            return new ImSureItsLegitTrustManager();
        }
    }

    @TargetApi(Build.VERSION_CODES.N)
    private static class ImSureItsLegitExtendedTrustManager extends X509ExtendedTrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

        public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host) throws CertificateException {
            return Arrays.asList(chain);
        }
    }

    private static class ImSureItsLegitTrustManager implements X509TrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

        public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host) throws CertificateException {
            return Arrays.asList(chain);
        }
    }

    private int hookTrustManagerImpl(String className, ClassLoader classLoader) {
        int hookedMethods = 0;
        try {
            Class<?> clazz = findClass(className, classLoader);
            for (Method method : clazz.getDeclaredMethods()) {
                if (!checkSSLMethod(method)) {
                    continue;
                }

                List<Object> params = new ArrayList<>();
                params.addAll(Arrays.asList(method.getParameterTypes()));
                params.add(new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return Arrays.asList((X509Certificate[]) param.args[0]);
                    }
                });

                log("Hooking method: " + method.toString());
                findAndHookMethod(clazz, method.getName(), params.toArray());
                hookedMethods++;
            }
        } catch (Throwable ignored) {}
        return hookedMethods;
    }

    private boolean checkSSLMethod(Method method) {
        if (!method.getName().equals(SSL_METHOD_NAME) && !method.getName().equals("checkServerTrusted")) {
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