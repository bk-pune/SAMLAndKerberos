package kerberos;

import com.sun.security.auth.module.Krb5LoginModule;
import com.sun.security.jgss.GSSUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.security.auth.Subject;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

/**
 * This is simple Java program that tests ability to authenticate with Kerberos using the JDK implementation.<br/>
 * Moreover, it also tests the delegation of kerberos credentials. Delegation is crucial step as we are going to use it at several places.
 * The program uses Krb5LoginModule which is part of JDK.
 * @author bhushank
 */
@Configuration
public class KerberosTest {
    private String ketabPath = "C:\\kerberos_files\\sapuser.keytab";
    private String spn ="HTTP/VINW10KB25221.EQSECTEST.LOCAL@EQSECTEST.LOCAL";
    private String krb5Conf= "C:\\kerberos_files\\krb5.conf";

    // Completes the security context initialisation and returns the client name.


    public KerberosTest(String ketabPath, String spn, String krb5Conf) {
        this.ketabPath = ketabPath;
        this.spn = spn;
        this.krb5Conf = krb5Conf;
    }

    public Subject loginImpl(byte[] kerberosTicket, String propertiesFileName) throws Exception {
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.krb5.conf", krb5Conf);
        final Krb5LoginModule krb5LoginModule = new Krb5LoginModule();
        Subject serviceUserSubject = new Subject();
        final Map<String,String> optionMap = new HashMap<String,String>();
        HashMap<String, String> shared = new HashMap<>();
        if (propertiesFileName == null) {
            optionMap.put("keyTab", ketabPath);
            optionMap.put("principal", spn); // default realm
            optionMap.put("doNotPrompt", "true");
            optionMap.put("refreshKrb5Config", "true");
            optionMap.put("useTicketCache", "true");
            optionMap.put("renewTGT", "false");
            optionMap.put("useKeyTab", "true");
            optionMap.put("storeKey", "true");
            optionMap.put("isInitiator", "true");
            optionMap.put("sun.security.krb5.rcache", "none"); //replay cache disable
            optionMap.put("debug", "true"); // switch on debug of the Java implementation
            krb5LoginModule.initialize(serviceUserSubject, null, shared, optionMap);

            // login using details mentioned inside keytab
            boolean loginOk = krb5LoginModule.login();
            System.out.println("Login success: " + loginOk);

            // This API adds Kerberos Credentials to the the Subject's private credentials set
            boolean commitOk = krb5LoginModule.commit();

        }

        System.out.println("Principal from subject: " + serviceUserSubject.getPrincipals()); // this must display name of user to which the keytab corresponds to

        // load kerberos ticket of some other user
        // byte[] kerberosTicket = loadTokenFromDisk();

        Subject clientSubject = getClientContext(serviceUserSubject, kerberosTicket);
        System.out.println("Client Subject-> " + clientSubject);
        System.out.println("Client principal-> "+clientSubject.getPrincipals().toArray()[0]);

        return clientSubject;
    }
    private Subject getClientContext(Subject subject, final byte[] kerberosTicket) throws PrivilegedActionException {
        Subject clientSubject = Subject.doAs(subject, new KerberosValidateAction(kerberosTicket));
        return clientSubject;
    }

    private class KerberosValidateAction implements PrivilegedExceptionAction<Subject> {
        byte[] kerberosTicket;

        public KerberosValidateAction(byte[] kerberosTicket) {
            this.kerberosTicket = kerberosTicket;
        }


        @Override
        public Subject run() throws Exception {
            GSSManager gssManager = GSSManager.getInstance();
            GSSContext context = gssManager.createContext((GSSCredential) null);
            System.out.println(context.getReplayDetState());

            // Called by the context acceptor upon receiving a token from the peer. This is our context acceptor
            // This method may return an output token which the application will need to send to the peer for further processing by its initSecContext call.
            // We will only accept the incoming token from Peer (browser) and fwd it to third party system
            byte[] nextToken = null;
            while (!context.isEstablished()) {
                nextToken = context.acceptSecContext(kerberosTicket, 0, kerberosTicket.length);
                System.out.println(new String(nextToken));
            }
            context.requestReplayDet(false);
            context.requestSequenceDet(false);
            System.out.println(context.getReplayDetState());
            boolean established = context.isEstablished();
            String user = context.getSrcName().toString();
            String serviceAccnt = context.getTargName().toString();

            //check if the credentials can be delegated
            if (!context.getCredDelegState()) {
                System.out.println("credentials can not be delegated!");
                return null;
            }

            //get the delegated credentials from the calling peer...
            GSSCredential clientCred = context.getDelegCred();
            //Create a Subject out of the delegated credentials.
            //With this Subject the application server can impersonate the client that sent the request.

            Subject clientSubject = GSSUtil.createSubject(context.getSrcName(), clientCred);

            return clientSubject;
        }
    }

    /*
     private Object getServiceTicket(GSSCredential clientCred) throws PrivilegedActionException {
    Object o = Subject.doAs(new Subject(), (PrivilegedExceptionAction<Object>) () -> {

        GSSManager manager = GSSManager.getInstance();
        Oid SPNEGO_OID = new Oid("1.3.6.1.5.5.2");
        Oid KRB5_PRINCIPAL_OID = new Oid("1.2.840.113554.1.2.2.1");
        GSSName servicePrincipal = manager.createName("HTTP/TEST", KRB5_PRINCIPAL_OID); // service to which the service user is allowed to delegate credentials
        ExtendedGSSContext extendedContext = (ExtendedGSSContext) manager.createContext(servicePrincipal, SPNEGO_OID, clientCred, GSSContext.DEFAULT_LIFETIME);
        extendedContext.requestCredDeleg(true);

        byte[] token = new byte[0];
        token = extendedContext.initSecContext(token, 0, token.length); // this token is the end user's TGS for "HTTP/TEST" service, you can pass this to the actual HTTP/TEST service endpoint in "Authorization" header.

        return token;
    });
    return o;
}
     */

    public static void main(String[] args) throws Exception {
        String ketabPath = "C:\\kerberos_files\\sapuser.keytab";
        String spn ="HTTP/VINW10KB25221.EQSECTEST.LOCAL@EQSECTEST.LOCAL";
        String krb5Conf= "C:\\kerberos_files\\krb5.conf";
        System.out.println("A property file with the login context can be specified as the 1st and the only paramater.");
        final KerberosTest krb = new KerberosTest(ketabPath, spn, krb5Conf);
//        krb.loginImpl(args.length == 0 ? null : args[0]);
    }


    // Load the security token from disk and decode it. Return the raw GSS token.
    private static byte[] loadTokenFromDisk() throws IOException {
        String kerberosTokenFile = "C:\\Users\\administrator.EQSECTEST\\krb5cc_administrator";
        long fileSize = new File(kerberosTokenFile).length();
        byte[] allBytes = new byte[(int) fileSize];

        FileInputStream inputStream = new FileInputStream(kerberosTokenFile);
        inputStream.read(allBytes);
        inputStream.close();
        return allBytes;
    }
}
