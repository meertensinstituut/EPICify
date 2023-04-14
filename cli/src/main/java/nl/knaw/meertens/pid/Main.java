package nl.knaw.meertens.pid;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.SSLContext;

import net.sf.json.JSONException;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import nl.knaw.huygens.persistence.HandleManager;
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

import java.util.UUID;

public class Main {

    public static void main(String[] args) {

        try {

            if (args.length < 3) {
                System.err.println("java -jar epicify.jar <options>");
                System.err.println();
                System.err.println("new handle   : <path to config> new <suffix>? <uri>");
                System.err.println("get handle   : <path to config> get <prefix/suffix>");
                System.err.println("update handle: <path to config> upd <prefix/suffix> <uri>");
                System.err.println("delete handle: <path to config> del <prefix/suffix>");
                System.err.println("               NOTE: there might be a nodelete policy active!");
                System.err.println();
                System.err.println("batch        : <path to config> csv <FILE.csv>");
                System.err.println("               NOTE: CSV columns: <suffix>,<uri>");
                System.err.println("               NOTE: will do an upsert, i.e., insert for a new suffix");
                System.err.println("                     and an update for an existing suffix");
                System.exit(1);
            }

            String epic = args[0];
            String action = args[1];

            File config = new File(epic);
            if (!config.exists()) {
                System.err.println("The EPIC configuration[" + epic + "] doesn't exist!");
                System.exit(2);
            } else if (!config.isFile()) {
                System.err.println("The EPIC configuration[" + epic + "] isn't a file!");
                System.exit(2);
            } else if (!config.canRead()) {
                System.err.println("The EPIC configuration[" + epic + "] can't be read!");
                System.exit(2);
            }

            XMLConfiguration xml = new XMLConfiguration(config);
            PIDService ps = new PIDService(xml, null);

            /*
             * 1. get version
             * 2. if version is not hi, then get version again from args
             * 3. if version is 8, use the new handle service
             * 3. if version is empty, then use the old handle service
             */
            // TODO: it seems version can always be drawn from config
            //      value in ["2", "8", "hi"]
            //      getting value from command line is not needed
            String version = ps.getVersionNumber();
            if (version == null || !version.equals("hi")) {
                version = args[args.length - 1].equals("8") ? "8" : "";
            }

            // TODO: clean up the code below
            //      use the version to determine which service to use
            //      parse the needed values, then get action from command line
            if (action.equals("new")) {
                if (version.equals("8")) {
                    String suf = (args.length > 4 ? args[2] : null);
                    String uri = (args.length > 4 ? args[3] : args[2]);
                    if (uri == null) {
                        System.err.println("new handle: needs a URI!");
                        System.exit(3);
                    }
                    String hdl = suf == null ? ps.requestHandle(UUID.randomUUID().toString(), uri, version) : ps.requestHandle(suf, uri, version);
                    System.err.println("new handle: " + hdl + " -> " + uri);
                    System.out.println(hdl);
                } else if (version.equals("hi")) {
                    // Huygens specific code for adding new handle
                    if (args.length != 3) {
                        System.err.println("new handle: needs both action and url");
                        System.exit(3);
                    } else {
                        String hdl = ps.requestHandle(args[2], true);
                        System.out.println("new hdl created: " + ps.prefix + "/" + hdl + " -> " + args[2]);
                    }
                } else {
                    String suf = (args.length > 3 ? args[2] : null);
                    String uri = (args.length > 3 ? args[3] : args[2]);
                    if (uri == null) {
                        System.err.println("new handle: needs a URI!");
                        System.exit(3);
                    }
                    String hdl = suf == null ? ps.requestHandle(uri) : ps.requestHandle(suf, uri);
                    System.err.println("new handle: " + hdl + " -> " + uri);
                    System.out.println(hdl);
                }

            } else if (action.equals("get")) {
                if (version.equals("8")) {
                    if (args.length < 4) {
                        System.err.println("get handle: needs a handle!");
                        System.exit(3);
                    }
                    String hdl = args[2];
                    String uri = ps.getPIDLocation(hdl, version);
                    if (uri != null) {
                        System.err.println("got handle: " + hdl + " -> " + uri);
                        System.out.println(uri);
                    } else {
                        System.err.println("get handle: " + hdl + " -> doesn't exist!");
                        System.exit(9);
                    }
                } else if (version.equals("hi")) {
                    if (args.length != 3) {
                        System.err.println("get handle: needs both action and handle!");
                        System.exit(3);
                    } else {
                        String hdl = args[2];
                        String uri = ps.getPIDLocation(hdl, true);
                        if (uri != null) {
                            System.out.println("got handle: " + hdl + " -> " + uri);
                        } else {
                            System.err.println("get handle: " + hdl + " -> doesn't exist!");
                            System.exit(9);
                        }
                    }
                } else {
                    if (args.length < 3) {
                        System.err.println("get handle: needs a handle!");
                        System.exit(3);
                    }
                    String hdl = args[2];
                    String uri = ps.getPIDLocation(hdl);
                    if (uri != null) {
                        System.err.println("got handle: " + hdl + " -> " + uri);
                        System.out.println(uri);
                    } else {
                        System.err.println("get handle: " + hdl + " -> doesn't exist!");
                        System.exit(9);
                    }
                }
            } else if (action.equals("upd")) {
                if (version.equals("8")) {
                    if (args.length < 5) {
                        System.err.println("update handle: needs a handle and an uri!");
                        System.exit(3);
                    }
                    String hdl = args[2];
                    String uri = args[3];
                    ps.updateLocation(hdl, uri, version);
                    String nw = ps.getPIDLocation(hdl, version);
                    if (!nw.equals(uri)) {
                        System.err.println("FATAL: failed to update handle[" + hdl + "] to [" + uri + "]! It (still) refers to [" + nw + "].");
                        System.exit(3);
                    }
                    System.err.println("updated handle: " + hdl + " -> " + uri);
                } else if (version.equals("hi")) {
                    if (args.length != 4) {
                        System.err.println("update handle: needs both action, handle and url");
                        System.exit(3);
                    } else {
                        String hdl = args[2];
                        String uri = args[3];
                        ps.updateLocation(hdl, uri, true);
                        System.out.println("updated handle: " + hdl + " -> " + uri + "; verifying...");
                        String nw = ps.getPIDLocation(hdl, true);
                        if (!nw.equals(uri)) {
                            System.err.println("FATAL: failed to update handle[" + hdl + "] to [" + uri + "]! It (still) refers to [" + nw + "].");
                            System.exit(3);
                        }
                        System.err.println("updated handle: " + hdl + " -> " + uri);
                    }
                } else {
                    if (args.length < 4) {
                        System.err.println("update handle: needs a handle and an uri!");
                        System.exit(3);
                    }
                    String hdl = args[2];
                    String uri = args[3];
                    ps.updateLocation(hdl, uri);
                    String nw = ps.getPIDLocation(hdl);
                    if (!nw.equals(uri)) {
                        System.err.println("FATAL: failed to update handle[" + hdl + "] to [" + uri + "]! It (still) refers to [" + nw + "].");
                        System.exit(3);
                    }
                    System.err.println("updated handle: " + hdl + " -> " + uri);
                }
            } else if (action.equals("del")) {
                if (version.equals("8")) {
                    if (args.length < 4) {
                        System.err.println("delete handle: needs a handle!");
                        System.exit(3);
                    }
                    String hdl = args[2];
                    try {
                        ps.deleteHandle(hdl, version);
                        System.err.println("deleted handle: " + hdl);
                    } catch (IOException x) {
                        System.err.println("Error occured: " + x);
                    }
                } else if (version.equals("hi")) {
                    if (args.length != 3) {
                        System.err.println("delete handle: needs both action and handle!");
                        System.exit(3);
                    } else {
                        String hdl = args[2];
                        ps.deleteHandle(hdl, true);
                        System.err.println("deleted handle: " + hdl);
                    }
                } else {
                    if (args.length < 3) {
                        System.err.println("delete handle: needs a handle!");
                        System.exit(3);
                    }
                    String hdl = args[2];
                    ps.deleteHandle(hdl);
                    System.err.println("deleted handle: " + hdl);
                }
            } else if (action.equals("csv")) {
                if (args.length < 3) {
                    System.err.println("csv action: needs a CSV file!");
                    System.exit(3);
                }
                File csv = new File(args[2]);
                if (!csv.exists()) {
                    System.err.println("csv action: The CSV file[" + csv.getAbsolutePath() + "] doesn't exist!");
                    System.exit(3);
                } else if (!csv.isFile()) {
                    System.err.println("csv action: The CSV file[" + csv.getAbsolutePath() + "] isn't a file!");
                    System.exit(3);
                } else if (!csv.canRead()) {
                    System.err.println("csv action: The CSV file[" + csv.getAbsolutePath() + "] can't be read!");
                    System.exit(3);
                }
                String prefix = xml.getString("HandlePrefix");
                List<String> lines = Files.readAllLines(csv.toPath(), StandardCharsets.UTF_8);
                int l = 0;
                for (String line : lines) {
                    l++;
                    if (line.startsWith("#"))
                        continue;
                    String[] cols = line.split(",");
                    if (cols.length != 2)
                        System.err.println("ERROR: CSV[" + csv.getAbsolutePath() + "][" + l + "] doesn't contain 2 columns!");
                    String suffix = cols[0];
                    String uri = cols[1];
                    String hdl = prefix + "/" + suffix;
                    String loc = ps.getPIDLocation(hdl);
                    boolean nw = (loc == null);
                    if (nw) {
                        ps.requestHandle(suffix, uri);
                    } else {
                        ps.updateLocation(hdl, uri);
                    }
                    loc = ps.getPIDLocation(hdl);
                    if (!loc.equals(uri)) {
                        System.err.println("ERROR: CSV[" + csv.getAbsolutePath() + "][" + l + "] failed to upsert handle[" + hdl + "] to [" + uri + "]! It (still) refers to [" + loc + "].");
                    } else
                        System.err.println("CSV[" + csv.getAbsolutePath() + "][" + l + "] " + (nw ? "new" : "updated") + " handle: " + hdl + " -> " + loc);
                }
            }  else {
                System.err.println("Unknown action!");
                System.exit(4);
            }

        } catch (Exception e) {
            System.err.println("FATAL: " + e);
            e.printStackTrace(System.err);
        }

    }
}
