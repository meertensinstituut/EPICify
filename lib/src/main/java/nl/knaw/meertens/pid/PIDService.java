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
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;

import net.sf.json.JSONException;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

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
//import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.http.conn.ssl.SSLContexts;
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
//    private final String pk12;
    private final String serverCert;
    private final String clientCert;
    private final String baseUri;
    private boolean isTest = true;
    
    private final SSLContext ssl;
	
    public PIDService(SSLContext ssl) throws ConfigurationException{
        this(new XMLConfiguration("config.xml"), ssl);
    }
	
    public PIDService(XMLConfiguration config, SSLContext ssl) throws ConfigurationException{	
        this.ssl = ssl;
        
        if( config == null)
            throw new IllegalArgumentException("No EPIC configuration specified!");
        
        // do something with config
        this.hostName = config.getString("hostName");
        this.host = config.getString("URI");
        this.handlePrefix = config.getString("HandlePrefix");
        this.userName = config.getString("userName");
        this.password = config.getString("password");
        this.email = config.getString("email");
        this.privateKey = config.getString("private_key");
//        this.pk12 = config.getString("private_key_pk12");
        this.serverCert = config.getString("server_certificate_only");
        this.clientCert = config.getString("private_certificate");
        this.baseUri = config.getString("baseuri");
        this.isTest = config.getString("status") != null && config.getString("status").equals("test");
        
        logger.debug((this.isTest?"test":"production")+" PIDService ["+this.host+"]["+this.handlePrefix+"]["+this.userName+":"+this.password+"]["+this.email+"]");
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
        FileInputStream fis = new FileInputStream(this.serverCert);
        X509Certificate ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(fis));

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, "".toCharArray());
        /* adding client cert and private key to keystore */
        ks.setCertificateEntry("cert-alias", cert);
        ks.setKeyEntry("key-alias", key, "".toCharArray(), new Certificate[] {cert});
        /* end here*/
        
//        ks.setCertificateEntry(Integer.toString(1), ca);
        ks.setCertificateEntry("server-cert", ca);
        
        /* test code */
//        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
//        kmf.init(ks, "".toCharArray());
//
//        KeyManager[] km = kmf.getKeyManagers(); 
//        SSLContext sslContext = SSLContext.getInstance("TLSv1");
//        sslContext.init(km, null, null);
        /* end here */
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, tmf.getTrustManagers(), null);

        return sslContext.getSocketFactory();
    }
    
    /*
    call to new version of API (ver. 8)
    */
    public String requestHandle(String uuid, String a_location, String version) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException{
        if (isTest) {
            logger.info("[TESTMODE 8] Created Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
            return "PIDManager_"+ a_location;
        }
	/* new */
        String handle = this.handlePrefix + "/" + uuid;
        logger.info("Requesting handle: " + handle);

        URL url = new URL(baseUri + handle);
        
        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) url.openConnection();
        httpsUrlConnection.setSSLSocketFactory(this.getFactory());
        httpsUrlConnection.setRequestMethod("PUT");
        httpsUrlConnection.setDoInput(true);
        httpsUrlConnection.setDoOutput(true);  
        httpsUrlConnection.setRequestProperty("Content-Type", "application/json");
        httpsUrlConnection.setRequestProperty("Accept", "application/json");
        httpsUrlConnection.connect();

        String payload = "{\"values\": [{\"index\":1,\"type\":\"URL\",\"data\": {\"format\": \"string\",\"value\":\"testtext\"}},{ \"index\": 100,\"type\": \"HS_ADMIN\",\"data\": {\"format\": \"admin\",\"value\": {\"handle\": \"0.NA/'21.T12995'\",\"index\": 200,\"permissions\": \"011111110011\"}}}]}";

        OutputStreamWriter osw = new OutputStreamWriter(httpsUrlConnection.getOutputStream());
        osw.write(String.format(payload));
        
        osw.flush();
        osw.close();


        System.out.println("Response Code : " + httpsUrlConnection.getResponseCode());
        System.out.println("Cipher Suite : " + httpsUrlConnection.getCipherSuite());
        System.out.println("Message : " + httpsUrlConnection.getResponseMessage());
//        String line;
//
//        BufferedReader reader = new BufferedReader(new InputStreamReader(httpsUrlConnection.getInputStream()));
//
//        while((line = reader.readLine()) != null) {
//            System.out.println(line);
//        }       
//
//        reader.close();
        httpsUrlConnection.disconnect();
        
        logger.info("ok");
        /* end */

        logger.info( "Created handle["+handle+"] for location ["+a_location+"]");
		
        return handle;
    }
    
    public String requestHandle(String a_location) throws IOException, HandleCreationException{
        return requestHandle(UUID.randomUUID().toString(), a_location);
    }
    
    public String requestHandle(String uuid,String a_location) throws IOException, HandleCreationException{
		
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
        String handle = this.handlePrefix + "/" + uuid;
        logger.info("Requesting handle: " + handle);
        URI uri = new URI(host + handle, true);
		
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
        map2.put("idx", "2");
        map2.put("type", "EMAIL");
        map2.put("parsed_data",this.email);
        map2.put( "timestamp", System.currentTimeMillis());
        map2.put("refs","");
        String jsonStr = null;
        try {
            List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
            list.add(map);
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
		
        return handle;
    }
	
    public void updateLocation( String a_handle, String a_location)throws IOException, HandleCreationException{
        if (isTest) {
            logger.debug("[TESTMODE] Handled request location change for Handle=["+a_handle+"] to new location["+a_location+"] ... did nothing");
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
		
        URI uri = new URI(host + a_handle, true);		
		
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
        map2.put("idx", "2");
        map2.put("type", "EMAIL");
        map2.put("parsed_data",this.email);
        map2.put( "timestamp", System.currentTimeMillis());
        map2.put("refs","");
        String jsonStr = null;
        try{
            List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
            list.add(map);
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
	
    public String getPIDLocation( String a_handle) throws IOException{
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
        String location = null;
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
        return location;		
    }
	
    public URL makeActionable( String a_PID){
        URL url = null;
        try {
            url = new URL( "http://hdl.handle.net/" + a_PID);
        } catch (MalformedURLException e) {
            logger.error("couldn't make PID actionable",e);
            //do nothing
            //null will be returned
        }
        return url;
    }
    
    public void deleteHandle(String a_handle) throws IOException {
	Protocol easyhttps = null;
	try {
            easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
	} catch (Exception e){
            logger.error("Problem configurating connection",e);
            throw new IOException("Problem configurating connection");
        }
        URI uri = new URI(host + a_handle, true);
        System.err.println("DBG: URI["+uri+"]");
		
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
