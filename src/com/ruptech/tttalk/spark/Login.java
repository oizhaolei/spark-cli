package com.ruptech.tttalk.spark;

import org.jivesoftware.smack.*;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smackx.ChatStateManager;
import org.jivesoftware.spark.SessionManager;
import org.jivesoftware.spark.SparkManager;
import org.jivesoftware.spark.util.DummySSLSocketFactory;
import org.jivesoftware.spark.util.ModelUtil;
import org.jivesoftware.spark.util.log.Log;
import org.jivesoftware.sparkimpl.settings.local.LocalPreferences;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

public class Login implements CallbackHandler {

    private LocalPreferences localPref;
    private ArrayList<String> _usernames = new ArrayList<String>();
    private String loginUsername;
    private String loginPassword;
    private String loginServer;
    private XMPPConnection connection = null;

    /**
     * Empty Constructor
     */
    public Login(String loginUsername,String loginPassword,String loginServer) {
        localPref = new LocalPreferences(new Properties());
        this.loginUsername = loginUsername;
        this.loginPassword = loginPassword;
        this.loginServer = loginServer;
    }

    public void handle(Callback[] callbacks) throws IOException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback ncb = (NameCallback) callback;
                ncb.setName(loginUsername);
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback pcb = (PasswordCallback) callback;
                pcb.setPassword(loginPassword.toCharArray());
            } else {
                Log.error("Unknown callback requested: " + callback.getClass().getSimpleName());
            }
        }
    }


    boolean login() {
        final SessionManager sessionManager = SparkManager.getSessionManager();

        boolean hasErrors = false;
        String errorMessage = null;

        localPref.setLoginAsInvisible(false);

        // Handle specifyed Workgroup
        String serverName = loginServer;


        if (!hasErrors) {
            if (localPref.isDebuggerEnabled()) {
                XMPPConnection.DEBUG_ENABLED = true;
            }

            SmackConfiguration.setPacketReplyTimeout(localPref.getTimeOut() * 1000);

            // Get connection
            try {
                ConnectionConfiguration config = retrieveConnectionConfiguration();
                connection = new XMPPConnection(config, this);
                //If we want to use the debug version of smack, we have to check if
                //we are on the dispatch thread because smack will create an UI
                connection.connect();

                String resource = localPref.getResource();
                connection.login(loginUsername, loginPassword,
                        org.jivesoftware.spark.util.StringUtils.modifyWildcards(resource).trim());

                sessionManager.setServerAddress(connection.getServiceName());
                sessionManager.initializeSession(connection, loginUsername, loginPassword);
                sessionManager.setJID(connection.getUser());
            } catch (Exception xee) {
                if (xee instanceof XMPPException) {

                    XMPPException xe = (XMPPException) xee;
                    final XMPPError error = xe.getXMPPError();
                    int errorCode = 0;
                    if (error != null) {
                        errorCode = error.getCode();
                    }
                    if (errorCode == 401) {
                        errorMessage = ("message.invalid.username.password");
                    } else if (errorCode == 502 || errorCode == 504) {
                        errorMessage = ("message.server.unavailable");
                    } else if (errorCode == 409) {
                        errorMessage = ("label.conflict.error");
                    } else {
                        errorMessage = ("message.unrecoverable.error");
                    }
                } else {
                    errorMessage = xee.getMessage();
                }

                // Log Error
                Log.warning("Exception in Login:", xee);
                hasErrors = true;
            }
        }

        if (hasErrors) {

            printf("title.login.error");

            return false;
        }

        // Since the connection and workgroup are valid. Add a ConnectionListener
        connection.addConnectionListener(SparkManager.getSessionManager());
        //Initialize chat state notification mechanism in smack
        ChatStateManager.getInstance(SparkManager.getConnection());

        // Persist information
        localPref.setLastUsername(loginUsername);

        // Check to see if the password should be saved.
        try {
            localPref.setPasswordForUser(getBareJid(), loginPassword);
        } catch (Exception e) {
            Log.error("Error encrypting password.", e);
        }

        localPref.setSavePassword(true);
        localPref.setAutoLogin(true);

//            if (localPref.isSSOEnabled()) {
//                localPref.setAutoLogin(true);
//            }

        localPref.setServer(serverName);


        return !hasErrors;
    }

    private void printf(String s) {
        System.out.println(s);
    }

    private String getBareJid() {
        return loginUsername + "@" + loginServer;
    }

    protected ConnectionConfiguration retrieveConnectionConfiguration() {
        int port = localPref.getXmppPort();

        int checkForPort = loginServer.indexOf(":");
        if (checkForPort != -1) {
            String portString = loginServer.substring(checkForPort + 1);
            if (ModelUtil.hasLength(portString)) {
                // Set new port.
                port = Integer.valueOf(portString);
            }
        }

        boolean useSSL = localPref.isSSL();
        boolean hostPortConfigured = localPref.isHostAndPortConfigured();

        ConnectionConfiguration config = null;

        if (useSSL) {
            if (!hostPortConfigured) {
                config = new ConnectionConfiguration(loginServer, 5223);
                config.setSocketFactory(new DummySSLSocketFactory());
            } else {
                config = new ConnectionConfiguration(localPref.getXmppHost(), port, loginServer);
                config.setSocketFactory(new DummySSLSocketFactory());
            }
        } else {
            if (!hostPortConfigured) {
                config = new ConnectionConfiguration(loginServer);
            } else {
                config = new ConnectionConfiguration(localPref.getXmppHost(), port, loginServer);
            }


        }
        config.setReconnectionAllowed(true);
        config.setRosterLoadedAtLogin(true);
        config.setSendPresence(false);

        if (localPref.isPKIEnabled()) {
            SASLAuthentication.supportSASLMechanism("EXTERNAL");
            config.setKeystoreType(localPref.getPKIStore());
            if (localPref.getPKIStore().equals("PKCS11")) {
                config.setPKCS11Library(localPref.getPKCS11Library());
            } else if (localPref.getPKIStore().equals("JKS")) {
                config.setKeystoreType("JKS");
                config.setKeystorePath(localPref.getJKSPath());

            } else if (localPref.getPKIStore().equals("X509")) {
                //do something
            } else if (localPref.getPKIStore().equals("Apple")) {
                config.setKeystoreType("Apple");
            }
        }

        boolean compressionEnabled = localPref.isCompressionEnabled();
        config.setCompressionEnabled(compressionEnabled);
        if (ModelUtil.hasLength(localPref.getTrustStorePath())) {
            config.setTruststorePath(localPref.getTrustStorePath());
            config.setTruststorePassword(localPref.getTrustStorePassword());
        }
        return config;
    }

}
