package com.reddipped.csprobe;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.log4j.Logger;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.IOUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.api.ConnectorInfo;
import org.identityconnectors.framework.api.ConnectorInfoManager;
import org.identityconnectors.framework.api.ConnectorInfoManagerFactory;
import org.identityconnectors.framework.api.RemoteFrameworkConnectionInfo;
import org.identityconnectors.framework.api.operations.APIOperation;
import org.identityconnectors.framework.api.operations.SchemaApiOp;
import org.identityconnectors.framework.api.operations.TestApiOp;
import org.identityconnectors.framework.api.operations.ValidateApiOp;
import org.identityconnectors.framework.common.exceptions.ConnectorException;

public class CSProbeProbe {
    
    static Logger logger = Logger.getLogger("CSProbeProbe");

    private TrustManager trustManager = new cfTrustManager(CSProbeServlet.csprobeTruststore);

    private KeyStore loadKeyStoreResource(String name) {
        try {
            logger.debug("Loading keystore " + name) ;
            File file = new File(name);
            byte[] bytes = IOUtil.readFileBytes(file);
            KeyStore store = KeyStore.getInstance(CSProbeServlet.csprobeKeystoreType);
            
            store.load(new ByteArrayInputStream(bytes), CSProbeServlet.csprobeTruststorePwd.toCharArray());
            return store;
        } catch (Exception loadKSExc) {
            
            String exceptionClassName = loadKSExc.getClass().getSimpleName();

            if (exceptionClassName.equalsIgnoreCase("FileNotFoundException")) {
                    //logger.error("Truststore '" + name + "'defined in Property csProbe.truststore not found") ;
                    throw new CSProbeFatalException("Truststore '" + name + "' defined in Property csProbe.truststore not found") ;
            }
            
            if (exceptionClassName.equalsIgnoreCase("KeyStoreException")) {
                if (loadKSExc.getMessage().endsWith("not found")) {
                    //logger.error("Property csProbe.keyStoreType set to invalid keystore type") ;
                    throw new CSProbeFatalException("Property csProbe.keyStoreType set to invalid keystore type") ;
                }
            }
                
            if (loadKSExc.getMessage().startsWith("Keystore was tampered with, or password was incorrect")) {
                //logger.error("Check property 'csProbe.truststorePassword'") ;
                throw new CSProbeFatalException("Check property 'csProbe.truststorePassword'") ;
            }
            
           return null ;  
        }
        
        
    }

    private class cfTrustManager implements X509TrustManager {

        private String _keyStoreName;

        public cfTrustManager(String name) {
            _keyStoreName = name;
            logger.debug("Creating trustmanager for truststore " + name) ;
        }

        @Override
        public int hashCode() {
            return 0;
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof cfTrustManager) {
                cfTrustManager other = (cfTrustManager) o;
                return _keyStoreName.equals(other._keyStoreName);
            }
            return false;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            checkTrusted(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            checkTrusted(chain);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        private void checkTrusted(X509Certificate[] chain)
                throws CertificateException {
            logger.debug("Checking X509 certificate chain") ;
            for (X509Certificate cert: chain) {
                logger.debug("  " + cert.toString()) ;
            }
            
            KeyStore store = loadKeyStoreResource(_keyStoreName);
            try {
                if (store.getCertificateAlias(chain[0]) == null) {
                    throw new CertificateException();
                }
            } catch (CertificateException e) {
                throw e;
            } catch (Exception e) {
                throw new CertificateException(e);
            }
        }
    }

    public static void main(String[] args) throws IOException {
    }

    public CSProbeProbe() {
        logger.debug("Instantiating " + this.getClass().getSimpleName());
    }

    public boolean probe() {
        // Start positive
        Boolean status = Boolean.TRUE;
        logger.debug("Probing...") ;
        ConnectorInfoManagerFactory factory = ConnectorInfoManagerFactory.getInstance();
        // Clearing the remote cache is essential 
        // If not cleared, the factory will return the (old) incorrect status.
        factory.clearRemoteCache();

        try {
                       
            RemoteFrameworkConnectionInfo remoteConnectionInfo;
            if (CSProbeServlet.connectorserverUseSSL) {
               remoteConnectionInfo = new RemoteFrameworkConnectionInfo(CSProbeServlet.csProbeCSListenAddress, CSProbeServlet.connectorserverPort, new GuardedString(CSProbeServlet.connectorserverKey.toCharArray()), true, CollectionUtil.newList(trustManager), 5000);
            } else {
                remoteConnectionInfo = new RemoteFrameworkConnectionInfo(CSProbeServlet.csProbeCSListenAddress, CSProbeServlet.connectorserverPort, new GuardedString(CSProbeServlet.connectorserverKey.toCharArray()), false, null, 5000);
            }

            ConnectorInfoManager manager = factory.getRemoteManager(remoteConnectionInfo);

            // Get the bundles
            List<ConnectorInfo> connectorInfos = manager.getConnectorInfos();

            int numConnInfos = connectorInfos.size();
            if (numConnInfos <= 0) {
                logger.error("No connector bundles");
                throw new CSProbeException("Connector: no bundles");
            }
            logger.debug("Number of bundles loaded " + connectorInfos.size());

//            Iterator cIi = connectorInfos.iterator();
//            while (cIi.hasNext()) {
//                
//                ConnectorInfo ci = (ConnectorInfo) cIi.next();
//                logger.debug("Bundle Name:" + ci.getConnectorKey().getBundleName()
//                        + " Version" + ci.getConnectorKey().getBundleVersion());
//                
//                // Optional bundle validation
//                ConnectorFacadeFactory cFF = ConnectorFacadeFactory.getInstance()  ;
//                
//                APIConfiguration apiCfg = ci.createDefaultAPIConfiguration() ;
//                ConnectorFacade cF = cFF.newInstance(apiCfg) ;
//     
//                Set<java.lang.Class<? extends APIOperation>> apiSupOpp = apiCfg.getSupportedOperations() ;
//                Iterator apiSupOppItr = apiSupOpp.iterator() ;
//                while (apiSupOppItr.hasNext()) {
//                    
//                    java.lang.Class<? extends APIOperation> apiTestOp =  (java.lang.Class<? extends APIOperation>) apiSupOppItr.next() ;
//       
//                    if (apiTestOp.getName().endsWith("ValidateApiOp")) {
//                        ValidateApiOp ValidateOp = (ValidateApiOp) cF.getOperation(apiTestOp) ;
//
//                            logger.debug("Validating bundle " + ci.getConnectorKey().getBundleName()) ;
//                            ValidateOp.validate() ;
//                            //APITestOp.test();
//                            logger.debug("Bundle valid") ;
//                               
//                    }
//                }
//                
//            }

        } catch (RuntimeException csException) {
            String exceptionClassName = csException.getClass().getSimpleName();

            if (exceptionClassName.equalsIgnoreCase("ConnectorException")) {
                if (csException.getMessage().startsWith("Bad magic number")) {
                    throw new CSProbeException("Connector: Bad magic number (SSL related)");
                }

                if (csException.getMessage().startsWith("java.net.ConnectException: Connection refused")) {
                    throw new CSProbeException("Connector: Connection refused (port:" + CSProbeServlet.connectorserverPort + ")");
                }

                if (csException.getMessage().startsWith("java.net.SocketTimeoutException: Read timed out")) {
                    throw new CSProbeException("Connector: Socket read timed out (port:" + CSProbeServlet.connectorserverPort + ")");
                }

                if (csException.getMessage().startsWith("javax.net.ssl.SSLException")) {
                    if (csException.getMessage().lastIndexOf("java.io.FileNotFoundException:") != -1) {
                        throw new CSProbeFatalException("Failed to connect due to SSL error (keystore " + CSProbeServlet.csprobeTruststore + " not found)");
                    }

                    throw new CSProbeFatalException("Failed to connect due to SSL Error, '" + csException.getMessage());
                }

                if (csException.getMessage().startsWith("javax.net.ssl.SSLHandshakeException")) {
                    throw new CSProbeException("Failed to connect due to SSL Handshake error, possibly connecting to nonSSL port " + CSProbeServlet.connectorserverPort);
                }

                if (csException.getMessage().startsWith("java.net.SocketTimeoutException")) {
                    throw new CSProbeException("Failed to connect to connectorserver due to socket timeout");
                }
                
                        
                throw new CSProbeException("Failed to connect (" + csException.getMessage() + ")");
            }

            if (exceptionClassName.equalsIgnoreCase("InvalidCredentialException")) {
                logger.error("Check property 'csProbe.connectorserverKey'") ;
                throw new CSProbeException("Invalid server key (" + CSProbeServlet.connectorserverKey + ")");
            }
            
            if (exceptionClassName.equalsIgnoreCase("NullPointerException")) {
                if (csException.getMessage().startsWith("Parameter 'host' must not be null")) {
                    throw new CSProbeFatalException("Property csProbe.connectorserverListenAddress not set");
                }
                
            }
            
//            if (exceptionClassName.equalsIgnoreCase("ConfigurationException")) {
//                    throw new CSProbeFatalException("Bundle invalid, " + csException.getMessage());
//            }

            throw new CSProbeFatalException("Uncontemplated error, (" + csException.getMessage() + ")");
        }

        return true;
    }
}
