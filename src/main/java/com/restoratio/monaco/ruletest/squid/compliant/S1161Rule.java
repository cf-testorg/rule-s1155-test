package com.restoratio.monaco.ruletest.squid.compliant;

public class S1161Rule extends AbstractS1161Rule {

	@Override
	protected void someMethod(String aParam) {
		// compliant, since it provides @Overrride annotation.
	}

	public String toString() {
		// compliant, since it is overriding object methods. Does not require
		// annotation
		return super.toString();
	}

	@Override
	public String parentMethod() {
		// compliant
		return null;
	}

}
