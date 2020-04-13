package com.restoratio.monaco.ruletest.findbugs.noncompliant;

public class REC_CATCH_EXCEPTION {

    private void resolve(Class c) {
        try {
            c.getGenericSuperclass();
            c.getGenericInterfaces();
        } catch (Exception x) {
            throw (LinkageError) new LinkageError("Failed to resolve " + c).initCause(x);
        }
    }
}
