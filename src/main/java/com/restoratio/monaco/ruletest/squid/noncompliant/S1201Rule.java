package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1201Rule {
	private int foo = 1;

	public boolean equals(S1201Rule o) { // Noncompliant; does not override
											// Object.equals(Object)
		return o != null && o.foo == this.foo;
	}

	public static void main(String[] args) {
		S1201Rule o1 = new S1201Rule();
		Object o2 = new S1201Rule();
		System.out.println(o1.equals(o2)); // Prints "false" because o2 an
											// Object not a MyClass
	}

}
