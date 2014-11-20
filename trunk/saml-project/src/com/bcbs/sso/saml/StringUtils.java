package com.bcbs.sso.saml;

public class StringUtils {

	public static boolean isEmpty(String str) {
		boolean isTrue = true;

		if (str != null || str != "" || str.length() > 0) {
			isTrue = false;
		}

		return isTrue;
	}
}
