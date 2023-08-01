package nl.knaw.meertens.pid;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class PIDService {
    
    private static final Logger logger = LoggerFactory.getLogger(PIDService.class.getName());
    
    protected String hostName;
    protected String host;
    protected String handlePrefix;
    protected String userName;
    protected String password;
    protected String email;
    protected String privateKey;
    protected String serverCert;
    protected String clientCert;
    protected String versionNumber;
    protected String namingAuthority;
    protected boolean isTest;
    protected SSLContext ssl;
    
    public PIDService() {
        this.hostName = null;
        this.host = null;
        this.handlePrefix = null;
        this.userName = null;
        this.password = null;
        this.email = null;
        this.privateKey = null;
        this.serverCert = null;
        this.clientCert = null;
        this.versionNumber = null;
        this.namingAuthority = null;
        this.isTest = true;
        this.ssl = null;
    }

    public static PIDService create(XMLConfiguration config, SSLContext ssl) throws ConfigurationException, IllegalAccessException {
        PIDService pids = null;
        
        if( config == null)
            throw new IllegalArgumentException("No EPICify configuration specified!");
        
        if (config.containsKey("private_key")) {
            if (config.containsKey("Version") && config.getString("Version").equals("hi")) {
                pids = new PIDService_hi(config,ssl);
            }
            else {
                pids = new PIDService_8(config,ssl);
            }

        } else {
            pids = new PIDService_2(config,ssl);
        }

        return pids;

    }

    public String getVersionNumber() {
        return this.versionNumber;
    }

    public String getPrefix() {
        return this.handlePrefix;
    }

    protected static byte[] parseDERFromPEM(byte[] pem, String beginDelimiter, String endDelimiter) {
        String data = new String(pem);
        String[] tokens = data.split(beginDelimiter);
        tokens = tokens[1].split(endDelimiter);
        return DatatypeConverter.parseBase64Binary(tokens[0]);        
    }

    protected static RSAPrivateKey generatePrivateKeyFromDER(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey)factory.generatePrivate(spec);        
    }

    protected static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        return (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(certBytes));      
    }

    SSLSocketFactory getFactory() throws NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        // get client certificate from file
        File clientCertFile = new File(this.clientCert);
        byte[] clientCertByte = Files.readAllBytes(clientCertFile.toPath());
        byte[] clientCertificate = parseDERFromPEM(clientCertByte, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
        X509Certificate cert = generateCertificateFromDER(clientCertificate);              
    
        // get client private key from file
        File clientPrivateKeyFile = new File(this.privateKey);
        byte[] clientPrivateKeyByte = Files.readAllBytes(clientPrivateKeyFile.toPath());
        byte[] clientPrivateKey = parseDERFromPEM(clientPrivateKeyByte, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        RSAPrivateKey key = generatePrivateKeyFromDER(clientPrivateKey);
        
        // get predownloaded server certificate from file
        boolean fisFileExist = false;
        if (this.serverCert != null) {
            File fisFile = new File(this.serverCert);
            fisFileExist = fisFile.exists();
        }
        X509Certificate ca;
        if (fisFileExist) {
            FileInputStream fis = new FileInputStream(this.serverCert);
            ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(fis));
        } else {
            ca = cert;
        }
        // init an empty keystore 
        /*NOTE: this keystore is not a Java Key Store
        // it is a container for keys and certs
        // Java Key Store and Java Trust Store can both be init using this keystore
        */
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, "".toCharArray());
        
        /* adding server cert, client cert and private key to keystore */
        // adding client cert
        ks.setCertificateEntry("cert-alias", cert);
        // adding client private key
        ks.setKeyEntry("key-alias", key, "".toCharArray(), new Certificate[] {cert});
        //addin server cert
        if (fisFileExist) {
            ks.setCertificateEntry("server-cert", ca);
        }
        /* end here*/
        
        // adding keystore to Jave Key Store
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "".toCharArray());

        // adding keystore to Java Trust Store
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        // init sslcontext
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext.getSocketFactory();
    }


    public String getJsonString(InputStream stream) throws IOException {
        BufferedReader rd = new BufferedReader(new InputStreamReader(stream));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = rd.readLine()) != null) {
            sb.append(line);
        }
        rd.close();

        return sb.toString();
    } 
    
    public URL makeActionable( String a_PID){
        URL url = null;
        try {
            url = new URL( "https://hdl.handle.net/" + a_PID);
        } catch (MalformedURLException e) {
            //logger.error("couldn't make PID actionable",e);
            //do nothing
            //null will be returned
        }
        return url;
    }

    public String requestHandle(String a_location) throws Exception {
        return requestHandle(UUID.randomUUID().toString(), a_location);
    }
    
    public abstract String requestHandle(String uuid,String a_location) throws Exception;

    public abstract void updateLocation( String a_handle, String a_location)throws Exception;

    public abstract String getPIDLocation(String a_handle) throws Exception;
    
    public abstract void deleteHandle(String a_handle) throws Exception;
    
}
