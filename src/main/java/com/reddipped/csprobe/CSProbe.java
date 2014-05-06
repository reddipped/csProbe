package com.reddipped.csprobe;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Properties;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.*;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.security.Encryptor;
import org.identityconnectors.common.security.EncryptorFactory;
import org.identityconnectors.common.IOUtil;

public class CSProbe {

    static Logger logger = Logger.getLogger("CSProbe");

    public static void main(String[] args) throws Exception {
        String cfPropertiesFile = null;
        String logFile = null;
        String csProbeHttpPort = null;
        String csProbeHttpUri = null;
        String csProbeCSListenAddress = null ;
        String csprobeTruststore = null ;
        String csprobeTruststorePwd = null ;
        String csprobeKeystoreType = null ;
        String csPropertiesFile = null;
        String cskeystore = null;
        String cskey = null;
        String secretKey = null;
        String csProbeSecretKeyFile = null ;
        
        Boolean connectorserverUseSSL = Boolean.FALSE;
        Integer connectorserverPort = 8759;

        Properties csProbeProperties = new Properties();
        Options options = new Options();
        CommandLine cmdLine;
        CommandLineParser parser = new GnuParser();

        // disable jetty default logger
        // org.eclipse.jetty.util.log.Log.setLog(null);
        // init log4j logger
        logger.info("Initializing and processing arguments");

        // Parse arguments
        Option option_propfile = OptionBuilder.withArgName("propFilename").hasArg().withDescription("Properties file").create("propFile");
        options.addOption(option_propfile);
        Option option_encryptKey = OptionBuilder.withArgName("encryptValue").hasArg().withDescription("unencrypted value").create("encryptValue");
        options.addOption(option_encryptKey);

        try {
            cmdLine = parser.parse(options, args);

            if (cmdLine.hasOption("encryptValue")) {
                EncryptorFactory ef = EncryptorFactory.getInstance();
                Encryptor e = ef.getDefaultEncryptor();
                String csKey = cmdLine.getOptionValue("encryptValue") ;
                String csEncKey = Base64.encode(e.encrypt(cmdLine.getOptionValue("encryptValue").getBytes())) ;
                csEncKey = csEncKey.replaceAll("=", "\\\\=") ;
                System.out.println("Encrypted value '" + csKey + "'");
                System.out.println("Add one of the following lines to you csProbe.properties file,") ;
                System.out.println("depending on the value you encrypted\n") ;
                System.out.println("csProbe.connectorserverKey=" + csEncKey);
                System.out.println("csProbe.truststorePassword=" + csEncKey);
                
                System.exit(0);
            }
            
            if (cmdLine.hasOption("propFile")) {
                cfPropertiesFile = cmdLine.getOptionValue("propFile");
            } else {
                logger.fatal("argument -propFile <propertiesfilename> is missing.");
                System.exit(1);
            }

        } catch (ParseException exception) {
            logger.fatal("Failed to parse arguments" + exception);
            System.exit(2);
        }

        // load CSProbe properties 
        try {
            if (cfPropertiesFile != null) {
                EncryptorFactory ef = EncryptorFactory.getInstance();
                Encryptor e = ef.getDefaultEncryptor();

                FileInputStream csProbeInputStream = new FileInputStream(cfPropertiesFile) ;
                csProbeProperties.load(csProbeInputStream);
                csProbeInputStream.close();
                csProbeHttpPort = csProbeProperties.getProperty("csProbe.httpStatusPagePort","52781");
                csProbeHttpUri = csProbeProperties.getProperty("csProbe.httpStatusPagePath","/csProbe");
                csprobeTruststore = csProbeProperties.getProperty("csProbe.truststore","");
                csprobeTruststorePwd = new String(e.decrypt(Base64.decode(csProbeProperties.getProperty("csProbe.truststorePassword",""))));
                csprobeKeystoreType =   csProbeProperties.getProperty("csProbe.keyStoreType","JKS") ;
                csPropertiesFile = csProbeProperties.getProperty("csProbe.connectorserverPropertiesfile","");
                csProbeCSListenAddress = csProbeProperties.getProperty("csProbe.connectorserverListenAddress","");
                cskey = new String(e.decrypt(Base64.decode(csProbeProperties.getProperty("csProbe.connectorserverKey",""))));
                csProbeSecretKeyFile = csProbeProperties.getProperty("csProbe.publishSecretKey","") ;

                csProbeInputStream.close(); 
            }
        } catch (IOException ioEx) {
            logger.fatal("Properties file '" + cfPropertiesFile + "' could not be found.");
            logger.fatal(ioEx) ;
            System.exit(3);
        } catch (RuntimeException rtEx) {
            if (rtEx.getMessage().startsWith("javax.crypto.IllegalBlockSizeException")) {
                logger.fatal("property csProbe.connectorserverKey or csProbe.truststorePassword in csProbe.properties is incorrectly encrypted");
                System.exit(4);
            } if (rtEx.getMessage().startsWith("javax.crypto.BadPaddingException")) {
                logger.fatal("property csProbe.connectorserverKey or csProbe.truststorePassword in csProbe.properties is incorrectly encrypted");
                System.exit(4);
            }
            else {
                logger.fatal("Something definitely went wrong, but have no clue what... sorry");
                logger.fatal("Stacktrace " + rtEx) ;
                System.exit(5);
            }
        } catch (Exception ex) {
            logger.fatal("Something definitely went wrong, but have no clue what... sorry");
            logger.fatal("Stacktrace " + ex) ;
            System.exit(6);
        }
        
        
        // load csProperties on initialization of the servlet
        try {
            Properties csProperties = IOUtil.loadPropertiesFile(csPropertiesFile);
            
            String pName = "connectorserver.usessl";
            connectorserverUseSSL = csProperties.getProperty("connectorserver.usessl").equalsIgnoreCase("true");

            pName = "connectorserver.port";
            connectorserverPort = Integer.valueOf(csProperties.getProperty("connectorserver.port"));
            
        } catch (Exception e) {
            logger.fatal("Failed to load properties from file '"
                    + csPropertiesFile + "' (" + e.getMessage() + ")", e);
            System.exit(7);

        }
        
        // Create HTTP server instance
        Server server = new Server();

        secretKey = new BigInteger(130, new SecureRandom()).toString(32);

        try {
            SelectChannelConnector channelConn = new SelectChannelConnector();
            channelConn.setPort(Integer.valueOf(csProbeHttpPort));
            server.setConnectors(new Connector[]{channelConn});

            HandlerCollection handlerCollection = new HandlerCollection();

            // Add servlet on path {cfHttpUri}/probe/
            ServletContextHandler probeServletContext = new ServletContextHandler(ServletContextHandler.SESSIONS);
            probeServletContext.setContextPath(csProbeHttpUri);

            ServletHolder csProbeServletHolder = probeServletContext.addServlet("com.reddipped.csprobe.CSProbeServlet", "/probe/*");
            probeServletContext.addServlet("com.reddipped.csprobe.CSProbeServlet", "/probe/*");
            probeServletContext.setInitParameter("csprobe.truststore", csprobeTruststore) ;
            probeServletContext.setInitParameter("csprobe.truststorepwd", csprobeTruststorePwd) ;
            probeServletContext.setInitParameter("csprobe.keystoretype", csprobeKeystoreType) ;
            probeServletContext.setInitParameter("csprobe.connectorserverkey", cskey);
            probeServletContext.setInitParameter("csprobe.connectorserverlistenaddress",csProbeCSListenAddress);
            probeServletContext.setInitParameter("servlet.serverPort", csProbeHttpPort);
            
            // connectorserver properties
            probeServletContext.setInitParameter("csprobe.useSSL", connectorserverUseSSL.toString());
            probeServletContext.setInitParameter("csprobe.csport", connectorserverPort.toString());
            // Generated servlet secret key
            probeServletContext.setInitParameter("servlet.secretKey", secretKey);
            csProbeServletHolder.setInitOrder(1);

            // Add handler on path /shutdown
            ContextHandler shutdownHandlerContext = new ContextHandler();
            shutdownHandlerContext.setContextPath("/shutdown");
            CSProbeStopHandler contextStopCSProbeHandler = new CSProbeStopHandler(secretKey, server, csProbeSecretKeyFile);
            shutdownHandlerContext.setHandler(contextStopCSProbeHandler);

            // Add handlers to handlercollection and set handlerCollection as handler for server
            Handler[] handlers = {probeServletContext, shutdownHandlerContext};
            handlerCollection.setHandlers(handlers);
            server.setHandler(handlerCollection);

            server.start();
            server.join();

            logger.debug("exit main class with exitcode '" + contextStopCSProbeHandler.exitCode + "'");
            System.exit(contextStopCSProbeHandler.exitCode);


        } catch (Exception ex) {
            String exceptionName = ex.getClass().getSimpleName();

            if (exceptionName.equals("NumberFormatException")) {
                logger.error("Error: Incorrect port (" + csProbeHttpPort + ") specified in property httpStatusPagePort");
            }

            if (exceptionName.equals("IllegalArgumentException")) {
                logger.error("Error: Incorrect port (" + csProbeHttpUri + ") specified in property httpStatusPagePath");
            }

            server.stop();
            server.destroy();
        }


    }

}
