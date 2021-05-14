package com.eq.saml.DSL;

import bsh.EvalError;
import bsh.Interpreter;
import org.opensaml.xml.signature.P;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * Executors for the given DSL.
 *
 * @author : bhushan.karmarkar@1eq.com
 * @Project : Security service
 * @Date : 13-01-2020
 * @since :
 */

public class DSLWithBSH {
    private String templateCode;
    private String actualCode;
    private String methodTemplate;
    private String methodImpl="";
    private Interpreter interpreter;

    public DSLWithBSH() {
        methodTemplate = "public Object authenticate(HttpServletRequest request, HttpServletResponse response) throws Exception {\n" +
                "        return null;\n" +
                "    }";
        templateCode ="package com.eq.saml.DSL;\n" +
                "\n" +
                "import kerberos.KerberosTest;\n" +
                "import org.opensaml.xml.util.Base64;\n" +
                "import org.springframework.util.StringUtils;\n" +
                "\n" +
                "import javax.security.auth.Subject;\n" +
                "import javax.servlet.http.HttpServletRequest;\n" +
                "\n" +
                "import javax.servlet.http.HttpServletResponse;\n" +
                "\n" +
                "public class CustomDSL {\n" +
                "    private KerberosTest kerberosTest = new KerberosTest();\n" +
                "\n" +
                methodTemplate +
                "}"; // Read From File

        methodImpl = methodTemplate;

        interpreter = new Interpreter();
        interpreter.setStrictJava(true);
        interpreter.setClassLoader(this.getClass().getClassLoader());
    }

    public Object execute(HttpServletRequest request, HttpServletResponse response) {
        Object output = null;

        try {
            String javaSourceCode = actualCode;
            interpreter.eval(javaSourceCode);
            Object dslClass = interpreter.eval("new CustomDSL()");
            // only request and response to be passed
            Method dslMethod = dslClass.getClass().getMethod("authenticate", HttpServletRequest.class, HttpServletResponse.class);
            output = dslMethod.invoke(dslClass, request, response);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return output;
    }

    public String setMethodImpl(String methodImpl) {
        String tempCode = null;
        try {
            tempCode = templateCode.replace(methodTemplate, methodImpl);
            compile(tempCode);
        } catch (Exception e) {
            return "DSL update failed. There are errors in your implementation -> " + e.getMessage();
        }
        actualCode = tempCode;
        this.methodImpl = methodImpl;
        return "DSL updated successfully !";
    }

    private void compile(String sourceCode) throws EvalError {
        interpreter.eval(sourceCode);
    }

    public String getMethodImpl() {
        return methodImpl;
    }
}

