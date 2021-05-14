package com.eq.saml.DSL;

import kerberos.KerberosTest;
import org.opensaml.xml.util.Base64;
import org.springframework.util.StringUtils;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import javax.servlet.http.HttpServletResponse;

public class CustomDSL {
    public Object authenticate(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return null; // Write your implementation here
    }
}