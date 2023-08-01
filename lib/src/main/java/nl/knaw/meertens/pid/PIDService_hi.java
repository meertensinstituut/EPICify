/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package nl.knaw.meertens.pid;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import nl.knaw.huygens.persistence.HandleManager;
import nl.knaw.huygens.persistence.PersistenceException;
import nl.knaw.huygens.persistence.PersistenceManagerCreationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.LoggerFactory;

/**
 *
 * @author menzowi
 */
public class PIDService_hi extends PIDService {
    
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(PIDService_hi.class.getName());

    protected String cypher;
    protected String prefix;
    
    public PIDService_hi(XMLConfiguration config, SSLContext ssl) {
        
        if( config == null)
            throw new IllegalArgumentException("No EPICify configuration specified!");

        this.ssl = ssl;
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
            }
        }

        this.isTest = !Objects.equals(config.getString("status"), "");
        
        if (!"hi".equals(this.versionNumber))
            throw new IllegalArgumentException("The EPICify configuration isn't for version hi!");
    }
    
    @Override
    public String requestHandle(String uuid,String a_location) throws Exception {
        HandleManager handleManager = HandleManager.newHandleManager(this.cypher, this.namingAuthority, this.prefix, this.privateKey);
        return handleManager.persistURL(a_location);
    }

    @Override
    public void updateLocation( String a_handle, String a_location)throws Exception {
        HandleManager handleManager = HandleManager.newHandleManager(
                this.cypher, this.namingAuthority, this.prefix, this.privateKey);
        // get rid of the prefix from handleValue, it is added automatically
        if (a_handle.contains("/")) {
            //logger.info("handleValue contains /, removing prefix");
            a_handle = a_handle.substring(a_handle.indexOf("/") + 1);
        }
        // updating the content of the handle
        try {
            handleManager.modifyURLForPersistentId(a_handle, a_location);
        } catch (PersistenceException e) {
            throw new PersistenceManagerCreationException("Unable to update handle " + a_handle + " with new value " + a_location, e);
        }
    }

    @Override
    public String getPIDLocation(String handleValue) throws Exception {
        HandleManager handleManager = HandleManager.newHandleManager(
            this.cypher, this.namingAuthority, this.prefix, this.privateKey);
        // get rid of the prefix from handleValue, it is added automatically
        if (handleValue.contains("/")) {
            //logger.info("handleValue contains /, removing prefix");
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

    @Override
    public void deleteHandle(String handleValue) throws Exception {
        HandleManager handleManager = HandleManager.newHandleManager(
                this.cypher, this.namingAuthority, this.prefix, this.privateKey);
        // get rid of the prefix from handleValue, it is added automatically
        if (handleValue.contains("/")) {
            //logger.info("handleValue contains /, removing prefix");
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
