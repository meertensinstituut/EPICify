package nl.knaw.meertens.pid;

import nl.knaw.huygens.persistence.PersistenceException;
import nl.knaw.huygens.persistence.HandleManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.io.OutputStreamWriter;

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
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

import net.sf.json.JSONException;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import nl.knaw.huygens.persistence.PersistenceManagerCreationException;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.protocol.Protocol;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PIDService {
    
    private static final Logger logger = LoggerFactory.getLogger(PIDService.class.getName());
    
    private final String hostName;
    private final String host;
    private final String handlePrefix;
    private final String userName;
    private final String password;
    private final String email;
    private final String privateKey;
    private final String serverCert;
    private final String clientCert;
    private final String versionNumber;
    final String namingAuthority;
    private boolean isTest = true;
    private final SSLContext ssl;

    // Huygens handle server specific
    final String cypher;
    final String prefix;

    public PIDService(XMLConfiguration config) {
        this.cypher = config.getString("cypher");
        this.namingAuthority = config.getString("namingAuthority");
        this.prefix = config.getString("prefix");
        this.privateKey = config.getString("private_key");
        // requuired but not used
        this.versionNumber = "8";
        this.serverCert = null;
        this.clientCert = null;
        this.hostName = null;
        this.userName = null;
        this.password = null;
        this.host = null;
        this.handlePrefix = null;
        this.email = null;
        this.ssl = null;
    }

//    public PIDService(SSLContext ssl) throws ConfigurationException, IllegalAccessException {
//        this(new XMLConfiguration("config.xml"), ssl);
//    }

    public PIDService(XMLConfiguration config, SSLContext ssl) throws ConfigurationException, IllegalAccessException {
        this.ssl = ssl;

        if( config == null)
            throw new IllegalArgumentException("No EPIC configuration specified!");
        
        // do something with config
        this.host = config.getString("URI");
        this.handlePrefix = config.getString("HandlePrefix");
        this.email = config.getString("email");
        if (config.containsKey("private_key")) {
            if (config.containsKey("Version") && config.getString("Version").equals("hi")) {
                this.versionNumber = "hi";
                this.privateKey = config.getString("private_key");
                this.cypher = config.getString("private_key_cypher");
                this.namingAuthority = config.getString("namingAuthority");
                this.prefix = config.getString("HandlePrefix");
                // initialize EPIC Huygens API props
                this.hostName = null;
                this.userName = null;
                this.password = null;
                this.serverCert = null;
                this.clientCert = null;
            }
            else {
                this.versionNumber = "8";
                this.privateKey = config.getString("private_key");
                this.serverCert = config.getString("server_certificate_only");
                this.clientCert = config.getString("private_certificate");
                // initialize EPIC 2 API props
                this.hostName = null;
                this.userName = null;
                this.password = null;
                this.namingAuthority = null;
                this.cypher = null;
                this.prefix = null;
            }

        } else {
            System.out.println("version 2 found");
            this.versionNumber = "2";
            this.hostName = config.getString("hostName");
            this.userName = config.getString("userName");
            this.password = config.getString("password");
            // initialize Handle version 8 API props
            this.privateKey = null;
            this.serverCert = null;
            this.clientCert = null;
            this.namingAuthority = null;
            this.cypher = null;
            this.prefix = null;
        }

        this.isTest = !Objects.equals(config.getString("status"), "");

    }

    public String getVersionNumber() {
        return this.versionNumber;
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

    /*
    call to Huygens version of API (ver. hi)
     */
    public String requestHandle(String urlToBeStored, boolean isHuygens) throws PersistenceManagerCreationException, PersistenceException {
        logger.info("creating handle for " + urlToBeStored);
        if (isHuygens) {
            HandleManager handleManager = HandleManager.newHandleManager(
                    this.cypher, this.namingAuthority, this.prefix, this.privateKey);

            return handleManager.persistURL(urlToBeStored);
        }
        logger.error("not huygens, returning null");
        return null;
    }

    /*
    call to new version of API (ver. 8)
    */
    public String requestHandle(String uuid, String a_location, String version) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException{
        if (isTest) {
            logger.info("[TESTMODE 8] Created Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
            return "PIDManager_"+ a_location;
        }

        String handle = this.handlePrefix + "/" + uuid;
        logger.debug("Requesting handle: " + handle);

        URL url = new URL(this.host + handle);
        
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(this.getFactory());
        httpsUrlConnection.setRequestMethod("PUT");
        httpsUrlConnection.setDoInput(true);
        httpsUrlConnection.setDoOutput(true);  
        httpsUrlConnection.setRequestProperty("Authorization", "Handle clientCert=\"true\"");
        httpsUrlConnection.setRequestProperty("Content-Type", "application/json");
        httpsUrlConnection.connect();

        String payload = "{\"values\": ["
                       + "{\"index\":1,\"type\":\"URL\",\"data\": {\"format\": \"string\",\"value\":\"" + a_location + "\"}},"
                       + (this.email!=null?"{\"index\":2,\"type\":\"EMAIL\",\"data\": {\"format\": \"string\",\"value\":\"" + this.email + "\"}},":"")
                       + "{ \"index\":100,\"type\": \"HS_ADMIN\",\"data\": {\"format\": \"admin\",\"value\": {\"handle\": \"0.NA/" + this.handlePrefix + "\",\"index\": 200,\"permissions\": 011111110011}}}"
                       + "]}";

        OutputStreamWriter osw = new OutputStreamWriter(httpsUrlConnection.getOutputStream());
        osw.write(String.format(payload));
        
        osw.flush();
        osw.close();

        logger.debug("Server response: " + httpsUrlConnection.getResponseCode() + " " + httpsUrlConnection.getResponseMessage());

        httpsUrlConnection.disconnect();
        
        logger.info( "Created handle["+handle+"] for location ["+a_location+"]");

        return handle;
    }

  public String requestHandle(String a_location) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException{
        return requestHandle(UUID.randomUUID().toString(), a_location);
    }
    
    public String requestHandle(String uuid,String a_location) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException{
        String handle = this.handlePrefix + "/" + uuid;
        if (this.versionNumber.equals("8")) {
            requestHandle(uuid, a_location, this.versionNumber);
        } else {
            if (isTest) {
                logger.info("[TESTMODE] Created Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
                return "PIDManager_"+ a_location;
            }

            Protocol easyhttps = null;
            try {
                easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(ssl), 443);
            } catch (Exception e){
                logger.error("Problem configurating connection",e);
                throw new IOException("Problem configurating connection");
            }
            //String handle = this.handlePrefix + "/" + uuid;
            logger.debug("Requesting handle: " + handle);
            URI uri = new URI(this.host + handle, true);

            HttpClient client = new HttpClient();
            client.getState().setCredentials(
                new AuthScope(this.hostName, 443, "realm"),
                new UsernamePasswordCredentials(this.userName, this.password));
            client.getParams().setAuthenticationPreemptive(true);
            PutMethod httpput = new PutMethod( uri.getPathQuery());
            httpput.setRequestHeader("Content-Type", "application/json");
            HostConfiguration hc = new HostConfiguration();
            hc.setHost(uri.getHost(), uri.getPort(), easyhttps);
            httpput.setDoAuthentication(true);

            Map<String, Object> map = new HashMap<String, Object>();
            map.put("idx", "1");
            map.put("type", "URL");
            map.put("parsed_data",a_location);
            map.put( "timestamp", "" + System.currentTimeMillis());
            map.put("refs","");
            Map<String, Object> map2 = new HashMap<String, Object>();
            if (this.email!=null) {
                map2.put("idx", "2");
                map2.put("type", "EMAIL");
                map2.put("parsed_data",this.email);
                map2.put( "timestamp", String.valueOf(System.currentTimeMillis()));
                map2.put("refs","");
            }
            String jsonStr = null;
            try {
                List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
                list.add(map);
                if (this.email!=null)
                    list.add(map2);
                JSONArray a = JSONArray.fromObject(list);
                jsonStr = a.toString();
                logger.info(jsonStr);
            } catch (JSONException e) {
                logger.error("Unable to create JSON Request object",e);
                throw new IOException( "Unable to create JSON Request object");
            }

            httpput.setRequestEntity(new StringRequestEntity( jsonStr, "application/json","UTF-8"));

            try {
                client.executeMethod(hc, httpput);
                if (httpput.getStatusCode() != HttpStatus.SC_CREATED ) {
                    logger.error("EPIC unexpected result[" + httpput.getStatusLine().toString()+"]");
                    throw new HandleCreationException("Handle creation failed. Unexpected failure: " + httpput.getStatusLine().toString() + ". " + httpput.getResponseBodyAsString());
                }
            } finally {
                logger.debug("EPIC result["+httpput.getResponseBodyAsString()+"]");
                httpput.releaseConnection();
            }

            //A resolvable handle is returned using the global resolver
            logger.info( "Created handle["+handle+"] for location ["+a_location+"]");
        }

        return handle;
    }

    public void updateLocation(String handleValue, String uri, boolean isHuygens) throws PersistenceManagerCreationException {
        logger.debug("isHuygens: " + isHuygens);
        logger.info("Updating location for handle: " + handleValue + " to " + uri);
        if (isHuygens) {
            HandleManager handleManager = HandleManager.newHandleManager(
                    this.cypher, this.namingAuthority, this.prefix, this.privateKey);
            // get rid of the prefix from handleValue, it is added automatically
            if (handleValue.contains("/")) {
                logger.info("handleValue contains /, removing prefix");
                handleValue = handleValue.substring(handleValue.indexOf("/") + 1);
            }
            // updating the content of the handle
            try {
                handleManager.modifyURLForPersistentId(handleValue, uri);
            } catch (PersistenceException e) {
                throw new PersistenceManagerCreationException("Unable to update handle " + handleValue + " with new value " + uri, e);
            }
        }
    }

    public void updateLocation(String a_handle, String a_location, String version)throws IOException, HandleCreationException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, KeyManagementException, InvalidKeySpecException, InvalidKeySpecException, InvalidKeySpecException, InvalidKeySpecException{
        if (isTest) {
            logger.info("[TESTMODE 8] Updated Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
            return;
        }

        String handle = a_handle;
        if (!handle.contains("/"))
            handle = this.handlePrefix + "/" + handle;
        
        logger.debug("Updating handle: " + handle);

        URL url = new URL(this.host + handle);
        
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(this.getFactory());
        httpsUrlConnection.setRequestMethod("PUT");
        httpsUrlConnection.setDoInput(true);
        httpsUrlConnection.setDoOutput(true);  
        httpsUrlConnection.setRequestProperty("Authorization", "Handle clientCert=\"true\"");
        httpsUrlConnection.setRequestProperty("Content-Type", "application/json");
        httpsUrlConnection.connect();

        String payload = "{\"values\": ["
                       + "{\"index\":1,\"type\":\"URL\",\"data\": {\"format\": \"string\",\"value\":\"" + a_location + "\"}},"
                       + (this.email!=null?"{\"index\":2,\"type\":\"EMAIL\",\"data\": {\"format\": \"string\",\"value\":\"" + this.email + "\"}},":"")
                       + "{ \"index\":100,\"type\": \"HS_ADMIN\",\"data\": {\"format\": \"admin\",\"value\": {\"handle\": \"0.NA/" + this.handlePrefix + "\",\"index\": 200,\"permissions\": 011111110011}}}"
                       + "]}";

        OutputStreamWriter osw = new OutputStreamWriter(httpsUrlConnection.getOutputStream());
        osw.write(String.format(payload));
        
        osw.flush();
        osw.close();

        logger.debug("Server response: " + httpsUrlConnection.getResponseCode() + " " + httpsUrlConnection.getResponseMessage());

        httpsUrlConnection.disconnect();
        
        logger.info( "Updated handle["+handle+"] for location ["+a_location+"]");


    }
    
    public void updateLocation( String a_handle, String a_location)throws IOException, HandleCreationException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException{
        if (this.versionNumber.equals("8")) {
            updateLocation(a_handle, a_location, this.versionNumber);
        } else {
            if (isTest) {
                logger.info("[TESTMODE] Handled request location change for Handle=["+a_handle+"] to new location["+a_location+"] ... did nothing");
                return;
            }
            UUID uuid = UUID.randomUUID();
            Protocol easyhttps = null;
            try {
                easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
            } catch(Exception e){
                logger.error("Problem configurating connection",e);
                throw new IOException("Problem configurating connection");
            }

            URI uri = new URI(this.host + a_handle, true);

            HttpClient client = new HttpClient();

            client.getState().setCredentials(
                new AuthScope(this.hostName, 443, "realm"),
                new UsernamePasswordCredentials(this.userName, this.password));
            client.getParams().setAuthenticationPreemptive(true);
            PutMethod httpput = new PutMethod( uri.getPathQuery());
            httpput.setRequestHeader("Content-Type", "application/json");
            HostConfiguration hc = new HostConfiguration();
            hc.setHost(uri.getHost(), uri.getPort(), easyhttps);
            httpput.setDoAuthentication(true);

            Map<String, Object> map = new HashMap<String, Object>();
            map.put("idx", "1");
            map.put("type", "URL");
            map.put("parsed_data",a_location);
            map.put("timestamp", String.valueOf(System.currentTimeMillis()));
            map.put("refs","");
            Map<String, Object> map2 = new HashMap<String, Object>();
            if (this.email!=null) {
                map2.put("idx", "2");
                map2.put("type", "EMAIL");
                map2.put("parsed_data",this.email);
                map2.put( "timestamp", String.valueOf(System.currentTimeMillis()));
                map2.put("refs","");
            }
            String jsonStr = null;
            try{
                List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
                list.add(map);
                if (this.email!=null)
                    list.add(map2);
                JSONArray a = JSONArray.fromObject(list);
                jsonStr = a.toString();
                logger.info(jsonStr);
            }
            catch( JSONException e){
                logger.error("Unable to create JSON Request object",e);
                throw new IOException("Unable to create JSON Request object");
            }

            //System.out.println( jsonStr);
            httpput.setRequestEntity(new StringRequestEntity( jsonStr, "application/json","UTF-8"));

            try {
                client.executeMethod(hc, httpput);
                if (httpput.getStatusCode() == HttpStatus.SC_NO_CONTENT) {
                    logger.info( "EPIC updated handle["+a_handle+"] for location ["+a_location+"]");
                } else {
                    logger.error("EPIC unexpected result[" + httpput.getStatusLine().toString()+"]");
                    throw new HandleCreationException("Handle creation failed. Unexpected failure: " + httpput.getStatusLine().toString() + ". " + httpput.getResponseBodyAsString());
                }
            } finally {
                logger.debug("EPIC result["+httpput.getResponseBodyAsString()+"]");
                httpput.releaseConnection();
            }
        }
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

    public String getPIDLocation(String handleValue, boolean isHuygens) throws PersistenceManagerCreationException, PersistenceException {
        logger.debug("isHuygens: " + isHuygens);
        logger.info("Getting location for handle: " + handleValue);
        if (isHuygens) {
            HandleManager handleManager = HandleManager.newHandleManager(
                this.cypher, this.namingAuthority, this.prefix, this.privateKey);
            // get rid of the prefix from handleValue, it is added automatically
            if (handleValue.contains("/")) {
                logger.info("handleValue contains /, removing prefix");
                handleValue = handleValue.substring(handleValue.indexOf("/") + 1);
            }
            // getting the content of the handle
            try {
                String result = handleManager.getPersistedURL(handleValue);
                return result;
            } catch (PersistenceException e) {
                return null;
            }
        }
        logger.error("not huygens, returning null");
        return null;
    }
//    public String getPIDLocation(String handleValue, boolean isHuygens) throws PersistenceManagerCreationException, PersistenceException {
//        logger.debug("isHuygens: " + isHuygens);
//        logger.info("Getting location for handle: " + handleValue);
//        if (isHuygens) {
//            String urlToBeStored = "https://www.huygens.knaw.nl/projecten/ecodicesnl/";
//            HandleManager handleManager = HandleManager.newHandleManager(
//                this.cypher, this.namingAuthority, this.prefix, this.privateKey);
//
//            // create
//            String id = handleManager.persistURL(urlToBeStored);
//            logger.info("create ok " + id);
//            // get
//            String persistedUrl = handleManager.getPersistedURL(handleValue);
//            logger.info("get ok: " + persistedUrl);
//            // TODO: use http to the the result url
//            // update
//            handleManager.modifyURLForPersistentId(id, urlToBeStored);
//            logger.info("update ok: " + id);
//            // delete
//            handleManager.deletePersistentId(id);
//
//            logger.info("clean up ok");
//            return "finished";
//        }
//        logger.error("not huygens, returning null");
//        return null;
//    }

    public String getPIDLocation(String a_handle, String version) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException, KeyManagementException {
        String handle = a_handle;
        if (!handle.contains("/"))
            handle = this.handlePrefix + "/" + handle;
        logger.debug("Getting location of handle: " + handle);
        String location = null;
        JSONObject json = null;
        
        URL url = new URL(this.host + handle);
        
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(this.getFactory());
        httpsUrlConnection.setRequestMethod("GET");
        httpsUrlConnection.setDoInput(true);
        httpsUrlConnection.setDoOutput(false);  
//        httpsUrlConnection.setRequestProperty("Authorization", "Handle clientCert=\"true\"");
        httpsUrlConnection.setRequestProperty("Content-Type", "application/json");
        httpsUrlConnection.connect();
        
        switch (httpsUrlConnection.getResponseCode()) {
            case HttpStatus.SC_OK:

                String jsonString = getJsonString(httpsUrlConnection.getInputStream());
                JSONArray jsonArr = JSONArray.fromObject("[" + jsonString + "]");
                json = jsonArr.getJSONObject(0);
                location = json.getString("values");
                
                jsonArr = JSONArray.fromObject(location);
                json = jsonArr.getJSONObject(0);
                location = json.getString("data");
                //String ts = json.getString("timestamp");
                
                jsonArr = JSONArray.fromObject("[" + location + "]");
                json = jsonArr.getJSONObject(0);
                location = json.getString("value");
                break;
            case HttpStatus.SC_NOT_FOUND:
                logger.warn("EPIC handle["+a_handle+"] doesn't exist[" + httpsUrlConnection.getResponseMessage()+"]");
                break;
            default:
                logger.error("EPIC unexpected result[" + httpsUrlConnection.getResponseMessage()+"]");
                throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpsUrlConnection.getResponseMessage() + ". " + getJsonString(httpsUrlConnection.getInputStream()));
        }
        
        httpsUrlConnection.disconnect();
        return location;
    }
    
    public String getPIDLocation(String a_handle) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException{
        String location = null;
        if (this.versionNumber.equals("8")) {
            location = getPIDLocation(a_handle, this.versionNumber);
        } else {
            Protocol easyhttps = null;
            try {
                easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
            } catch (Exception e){
                logger.error("Problem configurating connection",e);
                throw new IOException("Problem configurating connection");
            }
            URI uri = new URI(host + a_handle, true);

            HttpClient client = new HttpClient();
            client.getState().setCredentials(
                new AuthScope(this.hostName, 443, "realm"),
                new UsernamePasswordCredentials(this.userName, this.password));
            client.getParams().setAuthenticationPreemptive(true);
            GetMethod httpGet = new GetMethod(uri.getPathQuery());
            httpGet.setFollowRedirects(false);
            httpGet.setQueryString(new NameValuePair[] { 
                new NameValuePair("redirect", "no") 
            }); 
            httpGet.setRequestHeader("Accept", "application/json");
            HostConfiguration hc = new HostConfiguration();
            hc.setHost(uri.getHost(), uri.getPort(), easyhttps);
            httpGet.setDoAuthentication(true);
            //String location = null;
            JSONObject json = null;
            try {
                client.executeMethod(hc, httpGet);
                switch (httpGet.getStatusCode()) {
                    case HttpStatus.SC_OK:
                        logger.debug(httpGet.getResponseBodyAsString());
                        JSONArray jsonArr = JSONArray.fromObject(httpGet.getResponseBodyAsString());
                        json = jsonArr.getJSONObject(0);
                        location = json.getString("parsed_data");
                        break;
                    case HttpStatus.SC_NOT_FOUND:
                        logger.warn("EPIC handle["+a_handle+"] doesn't exist[" + httpGet.getStatusLine().toString()+"]");
                        break;
                    default:
                        logger.error("EPIC unexpected result[" + httpGet.getStatusLine().toString()+"]");
                        throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpGet.getStatusLine().toString() + ". " + httpGet.getResponseBodyAsString());
                }
            } finally {
                logger.debug("EPIC result["+httpGet.getResponseBodyAsString()+"]");
                httpGet.releaseConnection();
            }
        }
        return location;
    }

    public URL makeActionable( String a_PID){
        URL url = null;
        try {
            url = new URL( "https://hdl.handle.net/" + a_PID);
        } catch (MalformedURLException e) {
            logger.error("couldn't make PID actionable",e);
            //do nothing
            //null will be returned
        }
        return url;
    }
    
    public void deleteHandle(String a_handle) throws IOException, MalformedURLException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        if (this.versionNumber.equals("8")) {
            deleteHandle(a_handle, this.versionNumber);
        } else {
            
            if (isTest) {
                logger.info("[TESTMODE] Handled request delete for Handle=["+a_handle+"] ... did nothing");
                return;
            }
            
            Protocol easyhttps = null;
            try {
                easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
            } catch (Exception e){
                logger.error("Problem configurating connection",e);
                throw new IOException("Problem configurating connection");
            }
            URI uri = new URI(host + a_handle, true);

            HttpClient client = new HttpClient();
            client.getState().setCredentials(
                new AuthScope(this.hostName, 443, "realm"),
                new UsernamePasswordCredentials(this.userName, this.password));
            client.getParams().setAuthenticationPreemptive(true);
            DeleteMethod httpDel = new DeleteMethod(uri.getPathQuery());
            httpDel.setFollowRedirects(false);
            httpDel.setQueryString(new NameValuePair[] { 
                new NameValuePair("redirect", "no") 
            }); 
            httpDel.setRequestHeader("Accept", "application/json");
            HostConfiguration hc = new HostConfiguration();
            hc.setHost(uri.getHost(), uri.getPort(), easyhttps);
            httpDel.setDoAuthentication(true);
            try {
                client.executeMethod(hc, httpDel);
                if (httpDel.getStatusCode() != HttpStatus.SC_NO_CONTENT) {
                    logger.error("EPIC unexpected result[" + httpDel.getStatusLine().toString()+"]");
                    throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpDel.getStatusLine().toString() + ". " + httpDel.getResponseBodyAsString());
                }
            } finally {
                logger.debug("EPIC result["+httpDel.getResponseBodyAsString()+"]");
                httpDel.releaseConnection();
            }
        }
    }

    public void deleteHandle(String handleValue, boolean isHuygens) throws Exception {
        logger.debug("isHuygens: " + isHuygens);
        logger.info("Deleting handle: " + handleValue);
        if (isHuygens) {
            HandleManager handleManager = HandleManager.newHandleManager(
                    this.cypher, this.namingAuthority, this.prefix, this.privateKey);
            // get rid of the prefix from handleValue, it is added automatically
            if (handleValue.contains("/")) {
                logger.info("handleValue contains /, removing prefix");
                handleValue = handleValue.substring(handleValue.indexOf("/") + 1);
            }
            // delete
            try {
                handleManager.deletePersistentId(handleValue);
            } catch (Exception e) {
                throw new Exception("Error deleting handle: " + handleValue, e);
            }
        }

    }

    public void deleteHandle(String a_handle, String version) throws MalformedURLException, IOException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        if (isTest) {
            logger.info("[TESTMODE] Handled request delete for Handle=["+a_handle+"] ... did nothing");
            return;
        }
        String handle = a_handle;
        logger.debug("Deleting handle: " + this.handlePrefix + "/" + handle);
        
        URL url = new URL(this.host + this.handlePrefix + "/" + handle);
        
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(this.getFactory());
        httpsUrlConnection.setRequestMethod("DELETE");
        httpsUrlConnection.setDoInput(true);
        httpsUrlConnection.setDoOutput(false);  
        httpsUrlConnection.setRequestProperty("Authorization", "Handle clientCert=\"true\"");
        httpsUrlConnection.setRequestProperty("Content-Type", "application/json");
        httpsUrlConnection.setRequestProperty("Accept", "application/json");
        
        try {
            httpsUrlConnection.connect();
            int responseCode = httpsUrlConnection.getResponseCode();
            if (responseCode!=HttpStatus.SC_OK) {
                    logger.error("EPIC unexpected result[" +httpsUrlConnection.getResponseMessage()+ "]");
                    throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpsUrlConnection.getResponseMessage() + ". " + httpsUrlConnection.getContent().toString());
            }
        } finally {
            logger.debug("EPIC result["+ httpsUrlConnection.getContent().toString()+"]");
            httpsUrlConnection.disconnect();
        }
        
    }
}
