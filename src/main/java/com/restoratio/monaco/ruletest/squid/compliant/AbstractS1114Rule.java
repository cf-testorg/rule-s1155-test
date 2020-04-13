package com.restoratio.monaco.ruletest.squid.compliant;

public abstract class AbstractS1114Rule {

	protected void doSomething() {
		System.out.println("something");
	}
	
	@Override
	protected void finalize() throws Throwable {
	}
}
