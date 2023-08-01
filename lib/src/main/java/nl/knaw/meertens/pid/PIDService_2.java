/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
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

/**
 *
 * @author menzowi
 */
public class PIDService_2 extends PIDService {
    
    private static final Logger logger = LoggerFactory.getLogger(PIDService_2.class.getName());
    
    public PIDService_2(XMLConfiguration config, SSLContext ssl) {
        if( config == null)
            throw new IllegalArgumentException("No EPICify configuration specified!");
        
                
        this.ssl = ssl;
        this.host = config.getString("URI");
        this.handlePrefix = config.getString("HandlePrefix");
        this.email = config.getString("email");
        if (!config.containsKey("private_key")) {
            this.versionNumber = "2";
            this.hostName = config.getString("hostName");
            this.userName = config.getString("userName");
            this.password = config.getString("password");
        }

        this.isTest = !Objects.equals(config.getString("status"), "");        

        if (!"2".equals(this.versionNumber))
            throw new IllegalArgumentException("The EPICify configuration isn't for version 2!");
    }
    
    @Override
    public String requestHandle(String uuid,String a_location) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException {
        if (isTest) {
            //logger.info("[TESTMODE] Created Handle=["+"PIDManager_"+ a_location+"] for location["+a_location+"]");
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
    public void updateLocation( String a_handle, String a_location)throws IOException, HandleCreationException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException{
        if (isTest) {
            //logger.info("[TESTMODE] Handled request location change for Handle=["+a_handle+"] to new location["+a_location+"] ... did nothing");
            return;
        }
        UUID uuid = UUID.randomUUID();
        Protocol easyhttps = null;
        try {
            easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
        } catch(Exception e){
            //logger.error("Problem configurating connection",e);
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
            //logger.info(jsonStr);
        }
        catch( JSONException e){
            //logger.error("Unable to create JSON Request object",e);
            throw new IOException("Unable to create JSON Request object");
        }

        //System.out.println( jsonStr);
        httpput.setRequestEntity(new StringRequestEntity( jsonStr, "application/json","UTF-8"));

        try {
            client.executeMethod(hc, httpput);
            if (httpput.getStatusCode() == HttpStatus.SC_NO_CONTENT) {
                //logger.info( "EPIC updated handle["+a_handle+"] for location ["+a_location+"]");
            } else {
                //logger.error("EPIC unexpected result[" + httpput.getStatusLine().toString()+"]");
                throw new HandleCreationException("Handle creation failed. Unexpected failure: " + httpput.getStatusLine().toString() + ". " + httpput.getResponseBodyAsString());
            }
        } finally {
            //logger.debug("EPIC result["+httpput.getResponseBodyAsString()+"]");
            httpput.releaseConnection();
        }
    }
    
    @Override
    public String getPIDLocation(String a_handle) throws IOException, HandleCreationException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, CertificateException, FileNotFoundException, InvalidKeySpecException{
        String location = null;
        Protocol easyhttps = null;
        try {
            easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
        } catch (Exception e){
            //logger.error("Problem configurating connection",e);
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
                    //logger.debug(httpGet.getResponseBodyAsString());
                    JSONArray jsonArr = JSONArray.fromObject(httpGet.getResponseBodyAsString());
                    json = jsonArr.getJSONObject(0);
                    location = json.getString("parsed_data");
                    break;
                case HttpStatus.SC_NOT_FOUND:
                    //logger.warn("EPIC handle["+a_handle+"] doesn't exist[" + httpGet.getStatusLine().toString()+"]");
                    break;
                default:
                    //logger.error("EPIC unexpected result[" + httpGet.getStatusLine().toString()+"]");
                    throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpGet.getStatusLine().toString() + ". " + httpGet.getResponseBodyAsString());
            }
        } finally {
            //logger.debug("EPIC result["+httpGet.getResponseBodyAsString()+"]");
            httpGet.releaseConnection();
        }
        return location;
    }

    @Override
    public void deleteHandle(String a_handle) throws IOException, MalformedURLException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        if (isTest) {
            //logger.info("[TESTMODE] Handled request delete for Handle=["+a_handle+"] ... did nothing");
            return;
        }

        Protocol easyhttps = null;
        try {
            easyhttps = new Protocol("https", new EasySSLProtocolSocketFactory(), 443);
        } catch (Exception e){
            //logger.error("Problem configurating connection",e);
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
                //logger.error("EPIC unexpected result[" + httpDel.getStatusLine().toString()+"]");
                throw new IOException("Handle retrieval failed["+a_handle+"]. Unexpected failure: " + httpDel.getStatusLine().toString() + ". " + httpDel.getResponseBodyAsString());
            }
        } finally {
            //logger.debug("EPIC result["+httpDel.getResponseBodyAsString()+"]");
            httpDel.releaseConnection();
        }
    }

}
