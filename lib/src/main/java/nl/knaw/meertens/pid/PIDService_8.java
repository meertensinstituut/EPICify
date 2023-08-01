package nl.knaw.meertens.pid;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.httpclient.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author menzowi
 */
public class PIDService_8 extends PIDService {
    
    private static final Logger logger = LoggerFactory.getLogger(PIDService_8.class.getName());

    public PIDService_8(XMLConfiguration config, SSLContext ssl) {
        if( config == null)
            throw new IllegalArgumentException("No EPICify configuration specified!");
        
        this.ssl = ssl;
        this.host = config.getString("URI");
        this.handlePrefix = config.getString("HandlePrefix");
        this.email = config.getString("email");
        if (config.containsKey("private_key")) {
            if (!config.containsKey("Version")) {
                this.versionNumber = "8";
                this.privateKey = config.getString("private_key");
                this.serverCert = config.getString("server_certificate_only");
                this.clientCert = config.getString("private_certificate");
            }
        }
        this.isTest = !Objects.equals(config.getString("status"), "");
        
        if ("8".equals(this.versionNumber)) {
        } else {
            throw new IllegalArgumentException("The EPICify configuration isn't for version 8!");
        }
    }
    
    @Override
    public String requestHandle(String uuid,String a_location) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException {
        if (isTest) {
            //logger.info("[TESTMODE 8] Created Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
            return "PIDManager_"+ a_location;
        }

        String handle = this.handlePrefix + "/" + uuid;
        //logger.debug("Requesting handle: " + handle);

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

        //logger.debug("Server response: " + httpsUrlConnection.getResponseCode() + " " + httpsUrlConnection.getResponseMessage());

        httpsUrlConnection.disconnect();
        
        //logger.info( "Created handle["+handle+"] for location ["+a_location+"]");

        return handle;

    }
    
    @Override
    public void updateLocation( String a_handle, String a_location)throws IOException, HandleCreationException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        if (isTest) {
            //logger.info("[TESTMODE 8] Updated Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
            return;
        }

        String handle = a_handle;
        if (!handle.contains("/"))
            handle = this.handlePrefix + "/" + handle;
        
        //logger.debug("Updating handle: " + handle);

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

        //logger.debug("Server response: " + httpsUrlConnection.getResponseCode() + " " + httpsUrlConnection.getResponseMessage());

        httpsUrlConnection.disconnect();
        
        //logger.info( "Updated handle["+handle+"] for location ["+a_location+"]");
    }

    @Override
    public String getPIDLocation(String a_handle) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException, KeyManagementException {
        String handle = a_handle;
        if (!handle.contains("/"))
            handle = this.handlePrefix + "/" + handle;
        //logger.debug("Getting location of handle: " + handle);
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
                //logger.warn("EPIC handle["+a_handle+"] doesn't exist[" + httpsUrlConnection.getResponseMessage()+"]");
                break;
            default:
                //logger.error("EPIC unexpected result[" + httpsUrlConnection.getResponseMessage()+"]");
                throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpsUrlConnection.getResponseMessage() + ". " + getJsonString(httpsUrlConnection.getInputStream()));
        }
        
        httpsUrlConnection.disconnect();
        return location;
    }

    @Override
    public void deleteHandle(String a_handle) throws MalformedURLException, IOException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        if (isTest) {
            //logger.info("[TESTMODE] Handled request delete for Handle=["+a_handle+"] ... did nothing");
            return;
        }
        String handle = a_handle;
        //logger.debug("Deleting handle: " + this.handlePrefix + "/" + handle);
        
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
                    //logger.error("EPIC unexpected result[" +httpsUrlConnection.getResponseMessage()+ "]");
                    throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpsUrlConnection.getResponseMessage() + ". " + httpsUrlConnection.getContent().toString());
            }
        } finally {
            //logger.debug("EPIC result["+ httpsUrlConnection.getContent().toString()+"]");
            httpsUrlConnection.disconnect();
        }
        
    }
    
}
