package com.restoratio.monaco.ruletest.squid.compliant;

public class S2222Rule2 extends MyLock {

		public void doSomething() {
				try {
						super.lock();
				    System.out.println("in doSomethingMethod");
				} finally {
						super.unlock();
				}
		}

		public boolean isInitialized() {
				return true;
		}
}
