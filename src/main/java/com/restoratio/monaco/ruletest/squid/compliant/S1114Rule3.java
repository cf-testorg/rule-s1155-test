package com.restoratio.monaco.ruletest.squid.compliant;

public class S1114Rule3 extends AbstractS1114Rule {

	protected void finalize() throws Throwable {
		try {
			releaseSomeResources();
		} catch (Throwable t) {
			System.err.println("Error");
		} finally {
			super.finalize(); //compliant- Super is at the end of the method.
		}
	}

	public void releaseSomeResources() {

	}
}
