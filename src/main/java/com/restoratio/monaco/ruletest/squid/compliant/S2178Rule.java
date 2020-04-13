package com.restoratio.monaco.ruletest.squid.compliant;

public class S2178Rule {

	public void doCheckBooleanBitwise1() {

		if (getTrue() && getFalse()) { // compliant; both sides evaluated
			System.out.println(1);
		}
	}

	public void doCheckBooleanBitwise2() {

		if (getTrue() || getFalse()) { // compliant; both sides evaluated
			System.out.println(1);
		}
	}
	
	public void doUseBitwiseInNotBooleanContext1() { //should not be detected. It is not used in boolean context
		int a = 2;
		int b = 3;
		System.out.println(a & b);
	}

	public void doUseBitwiseInNotBooleanContext2() { //should not be detected. It is not used in boolean context
		System.out.println(2 & 5);
	}

	
	public boolean getTrue() {
		return true;
	}

	public boolean getFalse() {
		return true;
	}
	
}
