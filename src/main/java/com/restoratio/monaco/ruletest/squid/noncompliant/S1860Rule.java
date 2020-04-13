package com.restoratio.monaco.ruletest.squid.noncompliant;


public class S1860Rule{

    public void simpleCalls(){
        complaint();
        nonComplaint1();
        nonComplaint2();
        nonComplaint3();
        nonComplaint4();
    }

    private void complaint() {
        Object lock=null;
        synchronized (lock)
        {
            System.out.println("complaint()");
        }
    }


    private void nonComplaint1() {
            Integer lock=1;
            synchronized (lock)
            {
                System.out.println("nonComplaint2()");
            }
        }


    private void nonComplaint2 () {
            java.lang.Integer lock=1;
           synchronized (lock) {
                System.out.println("nonComplaint3()");
            }
        }
    
    private void nonComplaint3 () {
        Boolean lock = new Boolean();
       synchronized (lock) {
            System.out.println("nonComplaint3()");
        }
    }    

    private void nonComplaint4 () {
        java.lang.Boolean lock = false;
       synchronized (lock) {
            System.out.println("nonComplaint3()");
        }
    }    
}

class Boolean{
	//*Dummy class
}
