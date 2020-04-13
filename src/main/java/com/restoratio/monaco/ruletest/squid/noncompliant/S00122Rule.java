package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.util.logging.Level;
import java.util.logging.Logger;

public final class S00122Rule {

    private Logger log;

    public void doSomething() {
        boolean someCondition = true;
        if(someCondition) doSomething();
    }

    public void do1(){
        String st = "" ;
        if(st != null){
            try{
                st.length();
            }catch(Exception ignore){log.log(Level.SEVERE, ignore.toString(), ignore);}
        }
    }

    public void do2(){
        String st = "" ;
        if(st != null){
            try{
                st.length();
            }catch(Exception ignore){log.log(Level.SEVERE, ignore.toString(), ignore);}
            finally{log.log(Level.SEVERE, "this is cool");}
        }
    }

}
