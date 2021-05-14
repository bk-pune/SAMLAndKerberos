package com.eq.saml.controller;

import com.eq.saml.DSL.DSLWithBSH;
import com.eq.saml.exchange.SamlClient;
import com.eq.saml.exchange.SamlException;
import com.eq.saml.exchange.SamlResponse;
import kerberos.KerberosTest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.util.Base64;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * @Author bhushank
 */
@Configuration
@RestController
public class SAMLController {

    private SamlClient samlClient;
    private KerberosTest kerberosTest;
    private DSLWithBSH dslWithBSH;
    private String dslForm;

    public SAMLController() throws IOException, SamlException {
        String keytabPath =  "C:\\kerberos_files\\kerberosuser.keytab";
        String spn =  "HTTP/VINW10KB25221.EQSECTEST.LOCAL"; //HTTP/VINW10KB25221.EQSECTEST.LOCAL@EQSECTEST.LOCAL
        String krb5Conf =  "C:/kerberos_files/krb5.conf";


        kerberosTest = new KerberosTest(keytabPath, spn, krb5Conf);
        /*samlClient = SamlClient.fromMetadata(
                "https://dt01070418.technologic.com:8443/samladfs/",
                "https://dt01070418.technologic.com:8443/samladfs/saml/postLogin",
                getXml("D:\\Security Service Framework\\POC\\SAML_ADFS_TEST\\src\\main\\resources\\config\\adfs.xml"),
                SamlClient.SamlIdpBinding.POST);*/
        dslWithBSH = new DSLWithBSH();
        dslForm = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<body>\n" +
                "\n" +
                "<h2>eQ Security DSL</h2>\n" +
                "<p>You can update the DSL by pasting the contents in this text area.</p>\n" +
                "\n" +
                "<form action=\"CONTEXT_PATH/UPDATE_ACTION\" method=\"POST\">\n" +
                "  <textarea name =\"dsl\" rows=\"30\" cols=\"150\">\n" +
                "EXISTING_DSL" +
                "</textarea>\n" +
                "  <br><br>\n" +
                "<input type=\"submit\" value=\"Save\">" +"\n" +
                "<input type=\"submit\" formaction=\"CONTEXT_PATH/EXECUTE_ACTION\" formtarget=\"_blank\" formmethod = \"GET\" value=\"Execute\">" +"\n" +
                "</form> \n" +
                "<br><br>" +
                "<h3>DSL-STATS:EMPTY</h3>" +

                "</body>\n" +
                "</html>";
    }

    @RequestMapping(value = "/xml", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_XML_VALUE)
    @ResponseBody
    public String testXML(HttpServletRequest request, HttpServletResponse response) throws IOException, SamlException {

        return "<?xml version=\"1.0\"?>\n" +
                "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"\n" +
                "                     validUntil=\"2030-05-09T05:01:59Z\"\n" +
                "                     cacheDuration=\"PT604800S\"\n" +
                "                     entityID=\"https://dt01070418.technologic.com:8443/samladfs2/\">\n" +
                "    <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n" +
                "        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
                "                                     Location=\"https://dt01070418.technologic.com:8443/samladfs/saml/postLogin\"\n" +
                "                                     index=\"1\" />\n" +
                "        \n" +
                "    </md:SPSSODescriptor>\n" +
                "</md:EntityDescriptor>";
    }


    @RequestMapping(value = "/saml/login", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException, SamlException {
        samlClient.redirectToIdentityProvider(response, "https://dt01070418.technologic.com:8443/samladfs/saml/hello");
    }

    @RequestMapping(value = "/saml/postLogin", method = RequestMethod.POST, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public void postLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // String samlResponse = request.getParameter("SAMLResponse"); // new String(Base64.decode(request.getParameter("SAMLResponse")));
        StringBuilder sb = new StringBuilder();
        SamlResponse samlResponse = samlClient.processPostFromIdentityProvider(request);
        Assertion assertion = samlResponse.getAssertion();
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        List<Attribute> attributes = attributeStatements.get(0).getAttributes();
        for (Attribute attribute : attributes) {
            if(attribute.getName().equals("NameId")) {
                Map<String, Object> accordingToValues = samlClient.getAccordingToValues(attribute, attribute.getAttributeValues());
                sb.append("USER: " + accordingToValues.toString());
            }
        }
        String write = samlClient.write(assertion);
        sb.append("\n\n\n\n").append(write);

        URL url = new URL("destination post login url");
        url.openConnection();
        // relayState="app1/demo"
        // SAMLResponse="";

//        return sb.toString();

        response.sendRedirect(request.getParameter("RelayState"));
    }

    @RequestMapping(value = "/saml/metadata", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_XML_VALUE)
    @ResponseBody
    public String getSPMetadata(HttpServletRequest request, HttpServletResponse response) throws IOException {
        return "<?xml version=\"1.0\"?>\n" +
                "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"\n" +
                "                     validUntil=\"2030-05-09T05:01:59Z\"\n" +
                "                     cacheDuration=\"PT604800S\"\n" +
                "                     entityID=\"https://dt01070418.technologic.com:8443/samladfs/\">\n" +
                "    <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n" +
                "        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
                "                                     Location=\"https://dt01070418.technologic.com:8443/samladfs/saml/postLogin\"\n" +
                "                                     index=\"1\" />\n" +
                "        \n" +
                "    </md:SPSSODescriptor>\n" +
                "</md:EntityDescriptor>";
    }

    @RequestMapping(value = "/saml/hello", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String helloSAML(HttpServletRequest request, HttpServletResponse response) throws IOException, SamlException {
        return "Hello SAML World !";
    }


    @RequestMapping(value = "/kerb/hello", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String helloKerb(HttpServletRequest request, HttpServletResponse response) throws Exception {
        final String authorizationHeader = request.getHeader("Authorization");
        if (!StringUtils.hasText(authorizationHeader)) {
            System.out.println("Authorization header not found. Sending WWW-Authenticate header");
            response.setHeader("WWW-Authenticate", "Negotiate");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return "";
        }
        final byte[] token = Base64.decode(authorizationHeader.substring("Negotiate".length()));
        Subject clientSubject = kerberosTest.loginImpl(token, null);

      /*  System.out.println("Reusing the ticket 2");
        clientSubject = kerberosTest.loginImpl(token, null);*/

    /*    System.out.println("Reusing the ticket 3");
        clientSubject = kerberosTest.loginImpl(token, null);*/

       /* System.out.println("Reusing the ticket 4");
        clientSubject = kerberosTest.loginImpl(token, null);*/
        return "Kerb worked !<br/>Principal > <h1>"+ clientSubject.getPrincipals().toArray()[0] +"</h1>";
    }

    @RequestMapping(value = "/execute/dsl", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String testDSL(HttpServletRequest request, HttpServletResponse response) {
        request.getContextPath();
        return (String)dslWithBSH.execute(request, response);
    }

    @RequestMapping(value = "/get/dsl", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String getDSL(HttpServletRequest request) {
        return dslForm.replace("EXISTING_DSL", dslWithBSH.getMethodImpl()).replace("CONTEXT_PATH/UPDATE_ACTION", request.getContextPath()+"/update/dsl")
                .replace("CONTEXT_PATH/EXECUTE_ACTION", request.getContextPath()+"/execute/dsl");
    }

    @RequestMapping(value = "/update/dsl", method = RequestMethod.POST, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String updateDSL(HttpServletRequest request) {
        String incomingDSL = request.getParameter("dsl");
        String status = dslWithBSH.setMethodImpl(incomingDSL);

        // for display purpose, keep the incoming dsl as it is
        return dslForm.replace("EXISTING_DSL", incomingDSL).replace("CONTEXT_PATH/UPDATE_ACTION", request.getContextPath()+"/update/dsl")
                .replace("CONTEXT_PATH/EXECUTE_ACTION", request.getContextPath()+"/execute/dsl").replace("DSL-STATS:EMPTY", status);
    }

    private Reader getXml(String name) throws IOException {
        return new InputStreamReader(new FileInputStream(name), "UTF-8");
    }

}