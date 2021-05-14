package com.eq.saml.ntlm;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.netbios.Name;
import jcifs.netbios.NbtAddress;
import jcifs.netbios.UniAddress;
import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.*;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

/**
 * Add the Java doc here
 *
 * @author : bhushan.karmarkar@1eq.com
 * @Project : Security service
 * @Date : 21-01-2021
 * @since :
 */

public class NTLMAuthenticator {
    private CIFSContext cifsContext;
    private Properties properties;
    private String domainName;
    private String clientUserName;
    private String clientPassword;
    private NtlmPasswordAuthenticator ntlmPasswordAuthenticator;
    private SSPContext context;

    public NTLMAuthenticator(String domainName, String clientUserName, String clientPassword) throws CIFSException {
        this.domainName = domainName;
        this.clientUserName = clientUserName;
        this.clientPassword = clientPassword;
        initProperties();
        ntlmPasswordAuthenticator = new NtlmPasswordAuthenticator(domainName, clientUserName, clientPassword);
        cifsContext = new BaseContext(new PropertyConfiguration(properties));
    }

    private byte[] extractTokenFromRequest(HttpServletRequest request) throws UnsupportedEncodingException, Base64DecodingException {
        String header = request.getHeader("Authorization");

        if ((header != null) /*&& header.startsWith("Negotiate ")*/) {
            System.out.println("Received Negotiate Header for request " + request.getRequestURL() + ": " + header);
            byte[] base64Token = header.replace("NTLM", "").trim().getBytes("US-ASCII");
            byte[] decodedToken = Base64.decode(base64Token);
            return decodedToken;
        } else return null;
    }

    private void negotiate(HttpServletResponse response) throws UnsupportedEncodingException {
        String redirectHeader = "NTLM";
        // just some message
        response.setHeader("Connection", "Keep-Alive");
        response.setHeader("WWW-Authenticate", redirectHeader);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void sendType2Response(HttpServletResponse response, byte[] tokenFromRequest) throws Exception {
        Type2Message type2Message = new Type2Message(cifsContext, (Type1Message) constructNTLMMessage(tokenFromRequest), domainName.getBytes("US-ASCII"), null);
        // respond with a type 2 message, where the challenge is null since we don't
        // care about the server response (type-3 message) since we're already authenticated
        // (This is just a by-pass - see method javadoc)
        String msg = new String(Base64.encode(type2Message.toByteArray()));
        response.setHeader("Connection", "Keep-Alive");
        response.setHeader("WWW-Authenticate", "NTLM " + msg);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentLength(0);
        response.flushBuffer();
        return;
    }

    public void authenticate(HttpServletRequest request, HttpServletResponse response) throws Exception {
        byte[] tokenFromRequest = extractTokenFromRequest(request);

        // step 0 - Send Negotiate header
        if (tokenFromRequest == null || tokenFromRequest.length == 0) {
            negotiate(response);
            return;
        }

        // step 1 - client sends negotiation token, which is called as Type1Token
        NtlmMessage message = constructNTLMMessage(tokenFromRequest);
        if (message instanceof Type1Message) {
            // create new context here - LOL not thread safe of course !
            context = ntlmPasswordAuthenticator.createContext(cifsContext, domainName, null, null, false);
            byte[] type1TokenBytes = context.initSecContext(tokenFromRequest, 0, tokenFromRequest.length);  //type2 message is created and returned as byte array

            sendType2Response(response, tokenFromRequest);
            return;
        }

        // step 2 - client sends type3 message, which contains actual information
        byte[] type1TokenBytes = context.initSecContext(tokenFromRequest, 0, tokenFromRequest.length);
        context.dispose(); // auth is completed

        System.out.println(context);
    }


    // The Client will only ever send a Type1 or Type3 message ... try 'em both
    protected NtlmMessage constructNTLMMessage(byte[] token) {
        NtlmMessage message = null;
        try {
            message = new Type1Message(token);
            return message;
        } catch (IOException e) {
            if ("Not an NTLMSSP message.".equals(e.getMessage())) {
                return null;
            }
        }

        try {
            message = new Type3Message(token);
            return message;
        } catch (IOException e) {
            if ("Not an NTLMSSP message.".equals(e.getMessage())) {
                return null;
            }
        }

        return message;
    }

    private void initProperties() {
        properties = new Properties();
        properties.setProperty("jcifs.smb.client.domain", domainName);
        properties.setProperty("jcifs.smb.client.username", clientUserName);
        properties.setProperty("jcifs.smb.client.password", clientPassword);
        properties.setProperty("jcifs.netbios.hostname", domainName); // TODO will it work?
        properties.setProperty("jcifs.smb.useRawNTLM", "true"); // needed to create ntlm context, else it creates kerberos context
    }

}
