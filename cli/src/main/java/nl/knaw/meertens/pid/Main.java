package nl.knaw.meertens.pid;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class.getName());

    public static void main(String[] args) {

        logger.info("Starting EPICicy CLI");
        try {

            if (args.length < 2) {
                System.err.println("java -jar epicify.jar <options>");
                System.err.println();
                System.err.println("new handle   : <path to config>? new <suffix>? <uri>");
                System.err.println("get handle   : <path to config>? get <prefix/suffix>");
                System.err.println("update handle: <path to config>? upd <prefix/suffix> <uri>");
                System.err.println("delete handle: <path to config>? del <prefix/suffix>");
                System.err.println("               NOTE: there might be a nodelete policy active!");
                System.err.println();
                System.err.println("batch        : <path to config>? csv <FILE.csv>");
                System.err.println("               NOTE: CSV columns: <suffix>,<uri>");
                System.err.println("               NOTE: will do an upsert, i.e., insert for a new suffix");
                System.err.println("                     and an update for an existing suffix");
                System.err.println();
                System.err.println("If no explicit path to config is given th following locations are tried:");
                System.err.println("- config.xml in the current working directory");
                System.err.println("- .epicfy/config.xml in the user's home directory");
                System.exit(1);
            }

            String epic = args[0];
            
            List<String> actions = Arrays.asList("new","get","upd","del","csv");
            
            int startAction = 1;
            if (actions.contains(epic)) {
                startAction = 0;
                epic = null;
            }
            
            List<String> configs = new ArrayList();
            if (epic!=null)
                configs.add(epic);
            
            configs.add(System.getProperty("user.dir")+System.getProperty("file.separator")+"config.xml"); //config in the CWD
            configs.add(System.getProperty("user.home")+System.getProperty("file.separator")+".epicify"+System.getProperty("file.separator")+"config.xml"); //hidden file in the HOME
            
            File config = null;
            for (String c: configs) {
                //System.err.println("DBG: trying config["+c+"]");
                config = new File(c);
                if (config.exists() && config.isFile()&& config.canRead()) {
                    //System.err.println("DBG: using config["+c+"]");
                    break;
                }
                config = null;
            }
            
            if (config == null) {
                System.err.println("!ERROR: No EPIC configuration could be loaded!");
                System.err.println("Tried:");
                for (String c: configs) {
                    System.err.println("- "+c);
                }
                System.exit(2);
            }

            XMLConfiguration xml = new XMLConfiguration(config);
            PIDService ps = PIDService.create(xml, null);

            String action = args[startAction];

            if (action.equals("new")) {
                String suf = ((args.length - startAction) > 2 ? args[startAction + 1] : null);
                String uri = ((args.length - startAction) > 2 ? args[startAction + 2] : args[startAction + 1]);
                if (uri == null) {
                    System.err.println("!ERROR: new handle: needs a URI!");
                    System.exit(3);
                }
                String hdl = suf == null ? ps.requestHandle(uri) : ps.requestHandle(suf, uri);
                System.err.println("new handle: " + hdl + " -> " + uri);
                System.out.println(hdl);
            } else if (action.equals("get")) {
                String hdl = args[startAction+ 1];
                String uri = ps.getPIDLocation(hdl);
                if (uri != null) {
                    System.err.println("got handle: " + hdl + " -> " + uri);
                    System.out.println(uri);
                } else {
                    System.err.println("!ERROR: get handle: " + hdl + " -> doesn't exist!");
                    System.exit(9);
                }
            } else if (action.equals("upd")) {
                if ((args.length - startAction) < 4) {
                    System.err.println("!ERROR: update handle: needs a handle and an uri!");
                    System.exit(3);
                }
                String hdl = args[startAction + 1];
                String uri = args[startAction + 2];
                ps.updateLocation(hdl, uri);
                String nw = ps.getPIDLocation(hdl);
                if (!nw.equals(uri)) {
                    System.err.println("!ERROR: failed to update handle[" + hdl + "] to [" + uri + "]! It (still) refers to [" + nw + "].");
                    System.exit(3);
                }
                System.err.println("updated handle: " + hdl + " -> " + uri);
            } else if (action.equals("del")) {
                if ((args.length - startAction) < 2) {
                    System.err.println("!ERROR: delete handle: needs a handle!");
                    System.exit(3);
                }
                String hdl = args[startAction + 1];
                ps.deleteHandle(hdl);
                System.err.println("deleted handle: " + hdl);
            } else if (action.equals("csv")) {
                if ((args.length - startAction) < 2) {
                    System.err.println("!ERROR: csv action: needs a CSV file!");
                    System.exit(3);
                }
                File csv = new File(args[startAction + 1]);
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
                    String suffix = cols[0].trim();
                    String uri = cols[1].trim();
                    String loc = null;
                    String hdl = suffix;
                    if (hdl!=null && !hdl.equals("")) {
                        if (!suffix.startsWith(prefix))
                            hdl = prefix + "/" + suffix;
                        loc = ps.getPIDLocation(hdl);                        
                        if (ps.getVersionNumber().equals("hi"))
                            System.err.println("!WRN: version[hi] suffix["+suffix+"] will be ignored! an unique suffix will be generated.");
                    }
                    boolean nw = (loc == null);
                    if (nw) {
                        hdl = ps.requestHandle(suffix, uri);
                        //System.err.println("new hdl created: " + ps.prefix + "/" + hdl + " -> " + uri);
                        System.out.println(ps.getPrefix() + "/" + hdl);
                    } else {
                        ps.updateLocation(hdl, uri);
                    }
                    loc = ps.getPIDLocation(hdl);                        
                    if (loc ==null || !loc.equals(uri)) {
                        System.err.println("!ERROR:  CSV[" + csv.getAbsolutePath() + "][" + l + "] failed to upsert handle[" + hdl + "] to [" + uri + "]! It (still) refers to [" + loc + "].");
                    } else
                        System.err.println("CSV[" + csv.getAbsolutePath() + "][" + l + "] " + (nw ? "new" : "updated") + " handle: " + hdl + " -> " + loc);
                }
            }  else {
                System.err.println("!ERROR: Unknown action!");
                System.exit(4);
            }

        } catch (Exception e) {
            System.err.println("!ERROR: : " + e);
            e.printStackTrace(System.err);
            System.exit(9);
        }

    }
}
