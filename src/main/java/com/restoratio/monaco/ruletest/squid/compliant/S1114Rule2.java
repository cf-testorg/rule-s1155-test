package com.restoratio.monaco.ruletest.squid.compliant;

public class S1114Rule2 extends AbstractS1114Rule {

	protected void finalize() throws Throwable {
		try {
			doSomething();
		} catch (Throwable t) {
			releaseSomeResources();
		} 
		super.finalize(); //compliant- Super is at the end of the method.
	}

	public void releaseSomeResources() {

	}
}
