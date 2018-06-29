package com.akamai.siem;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


public class MainTest {
	@Test
	public void testMain() throws Exception
	{				
		String testFile = "com/akamai/siem/test_dlrs.json";

		InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

		while(reader.ready())
		{
			String line = reader.readLine();
			
			if(   (line != null) 
			   && (line.isEmpty() == false))
			{
				JsonParser parser = new JsonParser();	
				JsonObject jObj = parser.parse(line).getAsJsonObject();
			 	JsonObject newJsonObj = Main.processData(jObj);
			 	System.out.println(newJsonObj);
			}
		     
		}
		
		System.out.println("Done");
	}
}
