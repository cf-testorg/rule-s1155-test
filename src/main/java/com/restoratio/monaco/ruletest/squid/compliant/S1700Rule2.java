package com.restoratio.monaco.ruletest.squid.compliant;

public class S1700Rule2 {

    private static S1700Rule2 S1700Rule2;

    public S1700Rule2 getInstance() {
        if(S1700Rule2==null) {
            S1700Rule2 = new S1700Rule2();
        }
        return S1700Rule2;
    }

}
