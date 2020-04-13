package com.restoratio.monaco.ruletest.squid.noncompliant;

import com.restoratio.monaco.ruletest.squid.compliant.AbstractS1114Rule;

public class S1114Rule2 extends AbstractS1114Rule {

	@Override
	protected void finalize() throws Throwable {
		super.finalize(); // Noncompliant; this call should come last
		releaseSomeResources();
	}

	public void releaseSomeResources() {

	}

}
