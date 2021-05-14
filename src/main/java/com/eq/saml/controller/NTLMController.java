package com.eq.saml.controller;

import com.eq.saml.ntlm.NTLMAuthenticator;
import jcifs.CIFSException;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Add the Java doc here
 *
 * @author : bhushan.karmarkar@1eq.com
 * @Project : Security service
 * @Date : 27-01-2021
 * @since :
 */

@Configuration
@RestController
public class NTLMController {
    private NTLMAuthenticator ntlmAuthenticator;

    public NTLMController() throws CIFSException {
        ntlmAuthenticator = new NTLMAuthenticator("eqsectest.local", "ntlmtest", "eQ@12345");
    }

    @RequestMapping(value = "/ntlm/hello", method = RequestMethod.GET, consumes = MediaType.ALL_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public void helloNtlm(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String username = null;
        ntlmAuthenticator.authenticate(request, response);
//        return "Hello <h1>"+username+"</h1>";
    }
}
