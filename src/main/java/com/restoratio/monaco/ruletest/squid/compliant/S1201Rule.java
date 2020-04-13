package com.restoratio.monaco.ruletest.squid.compliant;

public class S1201Rule {
	private int foo = 1;

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		S1201Rule other = (S1201Rule) o;
		return this.foo == other.foo;
	}

	class MyClass2 {
		public boolean equals(MyClass2 o) { // Ignored; `boolean equals(Object) also present
			return true;
		}

		public boolean equals(Object o) {
			return false;
		}
	}

}
