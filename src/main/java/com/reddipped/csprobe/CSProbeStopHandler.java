package com.reddipped.csprobe;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;

public class CSProbeStopHandler extends AbstractHandler {

    private final String secretKey;
    private final String csProbeSecretKeyFile ;
    private final Server server;
    protected Integer exitCode;
    static Logger logger = Logger.getLogger("CSProbeStopHandler");

    /**
     * Constructor
     *
     * @param secretKey shared secret key
     * @param server jetty server instance
     */
    CSProbeStopHandler(String secretKey, Server server, String csProbeSecretKeyFile) {
        this.secretKey = secretKey;
        this.server = server;
        this.csProbeSecretKeyFile = csProbeSecretKeyFile ; 
        logger.debug("SecretKey set to '" + secretKey + "'");
        
        try {
            PrintWriter skWriter = new PrintWriter(this.csProbeSecretKeyFile, "UTF-8");
            skWriter.print(secretKey);
            skWriter.close();
        } catch (FileNotFoundException ex) {
            logger.error("Could not open file '" +  csProbeSecretKeyFile + "' defined in propery csProbe.publishSecretKey");
        } catch (UnsupportedEncodingException ex) {
            logger.error("UTF-8 encoding not supported");
        }
            
        
    }

    @Override
    public void handle(String string, Request rqst, HttpServletRequest hsr,
            HttpServletResponse hsr1) throws IOException, ServletException {

        // get url parameters
        String sharedSecretKey = rqst.getParameter("secretKey");

        try {
            exitCode = Integer.valueOf(rqst.getParameter("exitCode"));
        } catch (NumberFormatException nfe) {
            exitCode = 0;
        }

        // Basis http response
        hsr1.setContentType("text/html");
        hsr1.setStatus(HttpServletResponse.SC_OK); //200
        rqst.setHandled(true);

        if (sharedSecretKey != null) {
            if (sharedSecretKey.equals(this.secretKey)) {
                // Stop the server in separate thread.
                new Thread() {
                    @Override
                    public void run() {
                        try {
                            server.stop();
                        } catch (Exception ex) {
                            //
                        }
                    }
                }.start();
            } else {
                logger.warn("Tried to stop csStatus using wrong key value from address " + rqst.getRemoteAddr());
                logger.debug("Received key '" + sharedSecretKey + "'");
                hsr1.getWriter().println("Sorry, will not stop csStatus, you guessed the wrong key<br/>");
            }
        } else {
            logger.warn("Tried to stop csStatus without key value from address " + rqst.getRemoteAddr());
            hsr1.getWriter().println("Sorry, will not stop Jetty, you have to supply a proper key<br/>");
        }
    }
}
