package com.akamai.siem;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.splunk.modularinput.Event;

public class MainTest {
	@Test
	public void testMain() throws Exception {

		String testFile = "com/akamai/siem/test_dlrs.json";

		InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

		while (reader.ready()) {
			String line = reader.readLine();

			if ((line != null) && (line.isEmpty() == false)) {
				JsonParser parser = new JsonParser();
				JsonObject jObj = parser.parse(line).getAsJsonObject();
				// String s = jObj.get("offset").getAsString();
				JsonObject newJsonObj = Main.processData(jObj);
				System.out.println(newJsonObj);
				Event event = new Event();
				event.setStanza("teststanza");
				event.setData(newJsonObj.toString());

			}
		}

		System.out.println("Done");
	}
}
