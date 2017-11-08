/*******************************************************************************
 * Copyright 2017 Akamai Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 ******************************************************************************/
package com.akamai.siem;

import com.akamai.siem.stanza_state;

import com.splunk.Args;
import com.splunk.HttpService;
import com.splunk.Job;
import com.splunk.Receiver;
import com.splunk.RequestMessage;
import com.splunk.ResponseMessage;
import com.splunk.SSLSecurityProtocol;
import com.splunk.Service;
import com.splunk.ServiceArgs;
import com.splunk.modularinput.*;

import javax.xml.stream.XMLStreamException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
//import org.apache.commons.codec.binary.StringUtils;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import com.akamai.edgegrid.signer.ClientCredential;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridInterceptor;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridRoutePlanner;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;



//All modular inputs should inherit from the abstract base class com.splunk.modularinput.Script. They must override
//the getScheme and streamEvents methods, and, if the scheme returned by getScheme had
//Scheme.setUseExternalValidation(true) called on it, the validateInput method. The user must provide a main
//method since static methods can't be inherited in Java. However, the main is very simple.
public class Main extends Script 
{   
    private static String _KV_STORE_NAME_ = "akamai_state";
    private static String _KV_STORE_AKAMAI_OFFSET_BASED_TOKEN_ = "offset";
    private static String _KV_STORE_AKAMAI_STANZA_TOKEN_ = "stanza";
    private static String _KV_STORE_AKAMAI_ERROR_COUNT_TOKEN_ = "error_count";
    private static String _KV_STORE_AKAMAI_STANZA_CHANGE_TOKEN_ = "stanza_change";
    
    private static String _AKAMAI_API_PARAM_OFFSET_BASED_ = "?offset=%s";
    private static String _AKAMAI_API_PARAM_TIME_BASED_ = "?from=%s";
    private static String _AKAMAI_API_PARAM_TIME_TO_BASED_ = "&to=%s";
    private static String _AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_ = "?to=%s";
    private static String _AKAMAI_API_PARAM_LIMIT_BASED = "&limit=%s";
    private static String _AKAMAI_API_DATA_FETCH_LIMIT_TOKEN_ = "limit";
    private static String _AKAMAI_API_URL_PATH_ = "/siem/v1/configs/%s";
    private static String _AKAMAI_API_SECURITY_CONFIG_DELIMITER_ = ";";
    private static Integer _AKAMAI_API_MAX_LIMIT_= 600000;
    private static Integer _AKAMAI_API_DEFAULT_LIMIT_ = 150000;
    private static Integer _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_ = 5;
    
    private static final Set<String> base64fields = new HashSet<String>(Arrays.asList(
             new String[] {
                "rules",
                "ruleVersions",
                "ruleMessages",
                "ruleTags",
                "ruleData",
                "ruleSelectors",
                "ruleActions" 
             }
        ));
    
    private static final Map<String, String> transform;
        
    static 
    {
        HashMap<String, String> myTransform = new HashMap<String, String>();
        myTransform.put("ruleActions", "action");
        myTransform.put("ruleData", "data");
        myTransform.put("ruleMessages", "message");
        myTransform.put("ruleSelectors", "selector");
        myTransform.put("ruleTags", "tag");
        myTransform.put("ruleVersions", "version");
        myTransform.put("rules", "id");
        
        transform = Collections.unmodifiableMap(myTransform);
        
    }
    
    public static String decode(String value) throws Exception 
    {       
        return new String(Base64.decodeBase64(value), StandardCharsets.UTF_8);
    }
    
    private static JsonObject parseData(JsonObject d, boolean isCustom) throws Exception
    {
        StringBuilder sb = new StringBuilder("");
        
        for(Entry<String, JsonElement> entry : d.entrySet())
        {
            if(entry.getValue().isJsonObject() == true)
            {
                boolean isCustomEntry = false;
                if("custom".equalsIgnoreCase(entry.getKey()) == true)
                {
                    isCustomEntry = true;
                }
                parseData(entry.getValue().getAsJsonObject(), isCustomEntry);
            }
            else
            {                       
                String k = entry.getKey();
                JsonElement je = entry.getValue();
                
                String v = entry.getValue().getAsString();
                
                String urlDecodeValue = v;
                try
                {
                    urlDecodeValue = java.net.URLDecoder.decode(v, "UTF-8");
                }
                catch(Exception ex)
                {
                }
                
                String[] tokenizedResult = urlDecodeValue.split(";");
                
                if(tokenizedResult.length > 1)
                {
                    ArrayList<String> decodedValues = new ArrayList<String>();
                    for(String s : tokenizedResult)
                    {
                        if(   (base64fields.contains(k) == true)
                           || (isCustom == true))
                        {
                            String[] detectSpaces = s.split(" ");
                            StringBuilder sb2 = new StringBuilder();
                            for(String ss : detectSpaces)
                            {
                                if(sb2.length() > 0)
                                {
                                    sb2.append(" ");
                                }
                                
                                sb2.append(decode(ss));
                                
                            }
                            
                            decodedValues.add(sb2.toString());
                        }
                        else
                        {
                            decodedValues.add(s);
                        }
                    }
                    
                    JsonParser parser = new JsonParser();
                    Gson gson = new Gson();
                    entry.setValue(parser.parse(gson.toJson(decodedValues)));
                }
                else if(tokenizedResult.length > 0)
                {
                    if(   (base64fields.contains(k) == true)
                       || (isCustom == true))
                    {
                        String[] detectSpaces = tokenizedResult[0].split(" ");
                        StringBuilder sb2 = new StringBuilder();
                        for(String ss : detectSpaces)
                        {
                            if(sb2.length() > 0)
                            {
                                sb2.append(" ");
                            }
                            
                            sb2.append(decode(ss));
                            
                        }
                        
                        JsonElement element = new JsonPrimitive(sb2.toString());
                        entry.setValue(element);
                    }
                    else
                    {
                        JsonElement element = new JsonPrimitive(urlDecodeValue);
                        entry.setValue(element);
                    }
                }
                else
                {
                    JsonElement element = new JsonPrimitive("");
                    entry.setValue(element);
                    
                    System.out.println("tokenizedResult is zero");
                }
            }
        }
        
        return(d);
    }

    public static JsonObject processData(JsonObject d) throws Exception
    {
        JsonObject parsedData = parseData(d, false);
        
        JsonElement attackData = parsedData.get("attackData");
        JsonObject attackDataJsonObj = attackData.getAsJsonObject();

        Boolean isRulesArray = parsedData.get("attackData").getAsJsonObject().get("rules").isJsonArray();
        JsonArray rulesArray = null;
        Integer i = 0;
        Integer size = 1;
        
        if(isRulesArray == true)
        {
            rulesArray = parsedData.get("attackData").getAsJsonObject().get("rules").getAsJsonArray();
            size = rulesArray.size();
        }

        ArrayList<Map<String, String>> parsedRules = new ArrayList<Map<String, String>>();
        while(i < size)
        {
            Map<String, String> ruleData = new HashMap<String, String>();
            
            Iterator<Entry<String, String>> it = transform.entrySet().iterator();
            while (it.hasNext() == true) 
            {
                Map.Entry<String, String> pair = (Map.Entry<String, String>)it.next();

                if(parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).isJsonArray() == true)
                {
                    if(i < parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsJsonArray().size())
                    {
                        ruleData.put(pair.getValue(), parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsJsonArray().get(i).getAsString());
                    }
                    else
                    {
                        ruleData.put(pair.getValue(), "");
                    }
                }
                else
                {
                    ruleData.put(pair.getValue(), parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsString());
                }
  
                //it.remove(); // avoids a ConcurrentModificationException
            }

            parsedRules.add(ruleData);

            i++;
        }
        
        Iterator<Entry<String, String>> it = transform.entrySet().iterator();
        while (it.hasNext() == true) 
        {
            Map.Entry<String, String> pair = (Map.Entry<String, String>)it.next();

            attackDataJsonObj.remove(pair.getKey());

            //it.remove(); // avoids a ConcurrentModificationException
        }

        JsonParser parser = new JsonParser();
        Gson gson = new Gson();
        
        attackDataJsonObj.add("rules", parser.parse(gson.toJson(parsedRules)));
            
        return(parsedData);

    }
    
    private static String processQueryString(String initialEpochTime, String finalEpochTime, String offset, String limit)
    {
        String retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
        if(StringUtils.isEmpty(finalEpochTime) == false)
        {
            if(StringUtils.isEmpty(initialEpochTime) == false)
            {
                retVal = String.format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
                retVal = retVal + String.format(_AKAMAI_API_PARAM_TIME_TO_BASED_, finalEpochTime);
            }
            else
            {
                retVal = String.format(_AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_, finalEpochTime);
            }
            
            if(StringUtils.isEmpty(limit) == false)
            {
                retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
            }
            else
            {
                retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
            }
            
        }
        else if(StringUtils.isEmpty(initialEpochTime) == false)
        {
            if(StringUtils.isEmpty(offset) == true)
            {
                retVal = String.format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
            }
            else
            {
                retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
            }
            
            if(StringUtils.isEmpty(limit) == false)
            {
                retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
            }
            else
            {
                retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
            }
            
        }
        else
        {
            if(StringUtils.isEmpty(offset) == true)
            {
                retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, "NULL");
            }
            else
            {
                retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
            }
            
            if(StringUtils.isEmpty(limit) == false)
            {
                retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
            }
            else
            {
                retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
            }
        }
        
        return(retVal);
        
    }
    
    public static void main(String[] args) throws Exception
    {
        new Main().run(args);
    }

    // When Splunk starts, it looks for all the modular inputs defined by its configuration, and tries to run them
    // with the argument --scheme. Splunkd expects the modular inputs to print a description of the input in XML
    // on stdout. The modular input framework takes care of all the details of formatting XML and printing it. The
    // user need only override getScheme and return a new Scheme object.
    @Override
    public Scheme getScheme() 
    {
        Scheme scheme = new Scheme("AKAMAI SIEM API");
        scheme.setDescription("Security Information and Event Management");
        scheme.setUseExternalValidation(true);
        scheme.setUseSingleInstance(false);     
        
        Argument hostnameArgument = new Argument("hostname");
        hostnameArgument.setName("hostname");
        hostnameArgument.setDescription("");
        hostnameArgument.setRequiredOnCreate(true);
        hostnameArgument.setRequiredOnEdit(false);
        scheme.addArgument(hostnameArgument);
        
        Argument security_configuration_id_s_Argument = new Argument("security_configuration_id_s_");
        security_configuration_id_s_Argument.setName("security_configuration_id_s_");
        security_configuration_id_s_Argument.setDescription("Fetch data for specific Security Configuration(s) [semicolon delimited]");
        security_configuration_id_s_Argument.setRequiredOnCreate(true);
        security_configuration_id_s_Argument.setRequiredOnEdit(false);
        scheme.addArgument(security_configuration_id_s_Argument);
        
        Argument client_tokenArgument = new Argument("client_token");
        client_tokenArgument.setName("client_token");
        client_tokenArgument.setDescription("");
        client_tokenArgument.setRequiredOnCreate(true);
        client_tokenArgument.setRequiredOnEdit(false);
        scheme.addArgument(client_tokenArgument);
        
        Argument client_secretArgument = new Argument("client_secret");
        client_secretArgument.setName("client_secret");
        client_secretArgument.setDescription("");
        client_secretArgument.setRequiredOnCreate(true);
        client_secretArgument.setRequiredOnEdit(false);
        scheme.addArgument(client_secretArgument);
        
        Argument access_tokenArgument = new Argument("access_token");
        access_tokenArgument.setName("access_token");
        access_tokenArgument.setDescription("");
        access_tokenArgument.setRequiredOnCreate(true);
        access_tokenArgument.setRequiredOnEdit(false);
        scheme.addArgument(access_tokenArgument);
        
        Argument initial_epoch_timeArgument = new Argument("initial_epoch_time");
        initial_epoch_timeArgument.setName("initial_epoch_time");
        initial_epoch_timeArgument.setDescription("");
        initial_epoch_timeArgument.setRequiredOnCreate(false);
        initial_epoch_timeArgument.setRequiredOnEdit(false);
        scheme.addArgument(initial_epoch_timeArgument);
        
        Argument final_epoch_timeArgument = new Argument("final_epoch_time");
        final_epoch_timeArgument.setName("final_epoch_time");
        final_epoch_timeArgument.setDescription("");
        final_epoch_timeArgument.setRequiredOnCreate(false);
        final_epoch_timeArgument.setRequiredOnEdit(false);
        scheme.addArgument(final_epoch_timeArgument);
        
        Argument limitArgument = new Argument("limit");
        limitArgument.setName("limit");
        limitArgument.setDescription("");
        limitArgument.setRequiredOnCreate(false);
        limitArgument.setRequiredOnEdit(false);
        scheme.addArgument(limitArgument);
                
        return(scheme);
    }

    private StringBuilder checkStringSingleValue(StringBuilder sb, SingleValueParameter svp, String inputName)
    {
        if(svp != null)
        {
            String str_value = svp.getValue();
            if(   (str_value != null)
               && (str_value.isEmpty() == false))
            {
                // good
            }
            else
            {
                sb.append(inputName + "  is required");
            }
        }
        else
        {
            sb.append(inputName + "  is required");
        }
        
        return(sb);
    }
    
    // In this example we are using external validation, since we want max to always be greater than min.
    // If validateInput does not throw an Exception, the input is assumed to be valid. Otherwise it prints the
    // exception as an error message when telling splunkd that the configuration is not valid.
    //
    // When using external validation, after splunkd calls the modular input with --scheme to get a scheme, it calls it
    // again with --validate-arguments for each instance of the modular input in its configuration files, feeding XML
    // on stdin to the modular input to get it to do validation. It calls it the same way again whenever a modular
    // input's configuration is changed.
    @Override
    public void validateInput(ValidationDefinition definition) throws Exception 
    {
        // Get the values of the two parameters. There are also methods getFloat, getInt, getBoolean, etc.,
        // and getValue to get the string representation.
        
        StringBuilder errors = new StringBuilder();
        
        errors = checkStringSingleValue(errors, ((SingleValueParameter)definition.getParameters().get("hostname")), "hostname");
        errors = checkStringSingleValue(errors, ((SingleValueParameter)definition.getParameters().get("security_configuration_id_s_")), "security_configuration_id_s_");
        errors = checkStringSingleValue(errors, ((SingleValueParameter)definition.getParameters().get("client_token")), "client_token");
        errors = checkStringSingleValue(errors, ((SingleValueParameter)definition.getParameters().get("client_secret")), "client_secret");
        errors = checkStringSingleValue(errors, ((SingleValueParameter)definition.getParameters().get("access_token")), "access_token");
        
        if(errors.length() > 0)
        {
            throw new Exception(errors.toString());
        }
        
        //String initial_epoch_time
        //String final_epoch_time
        //String limit

        
    }

    // Finally, the real action: splunk calls the modular input with no arguments, streams a bunch of XML describing
    // the inputs to stdin, and waits for XML on stdout describing events.
    //
    // If you set setUseSingleInstance(true) on the scheme in getScheme, it will pass all the instances of this input
    // to a single instance of this script and it's your job to handle them all. Otherwise, it starts a JVM for each
    // instance of the input.
  
    @Override
    public void streamEvents(InputDefinition inputs, EventWriter ew) throws
            MalformedDataException, XMLStreamException, IOException 
    {
        ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"begin streamEvents\"");
        //ew.synchronizedLog(EventWriter.INFO, inputs.getInputs().keySet().toString());
        
        for(String inputName: inputs.getInputs().keySet())
        {
            ew.synchronizedLog(EventWriter.DEBUG, inputName);
            
            ew.synchronizedLog(EventWriter.DEBUG, inputs.getInputs().get(inputName).toString());
            
            String hostname = ((SingleValueParameter)inputs.getInputs().get(inputName).get("hostname")).getValue();
            ew.synchronizedLog(EventWriter.DEBUG, hostname);
            
            String security_configuration_id_s_ = ((SingleValueParameter)inputs.getInputs().get(inputName).get("security_configuration_id_s_")).getValue();
            ew.synchronizedLog(EventWriter.DEBUG, security_configuration_id_s_);
            
            String client_token = ((SingleValueParameter)inputs.getInputs().get(inputName).get("client_token")).getValue();
            ew.synchronizedLog(EventWriter.DEBUG, client_token);
            
            String client_secret = ((SingleValueParameter)inputs.getInputs().get(inputName).get("client_secret")).getValue();
            ew.synchronizedLog(EventWriter.DEBUG, client_secret);
            
            String access_token = "";
            try
            {
                access_token = ((SingleValueParameter)inputs.getInputs().get(inputName).get("access_token")).getValue();
            }
            catch(Exception ex)
            {
            }
            
            ew.synchronizedLog(EventWriter.DEBUG, access_token);
            
            String initial_epoch_time = "";
            try
            {
                initial_epoch_time = ((SingleValueParameter)inputs.getInputs().get(inputName).get("initial_epoch_time")).getValue();
            }
            catch(Exception ex)
            {
            }
            
            ew.synchronizedLog(EventWriter.DEBUG, initial_epoch_time);
            
            String final_epoch_time = "";
            try
            {
                final_epoch_time = ((SingleValueParameter)inputs.getInputs().get(inputName).get("final_epoch_time")).getValue();
            }
            catch(Exception ex)
            {   
            }
              
            ew.synchronizedLog(EventWriter.DEBUG, final_epoch_time);
            
            String limit = "";
            try
            {
                limit = ((SingleValueParameter)inputs.getInputs().get(inputName).get("limit")).getValue();
            }
            catch(Exception ex)
            {   
            }
            
            String sessionKey = inputs.getSessionKey();
            ew.synchronizedLog(EventWriter.DEBUG, sessionKey);
            
            
            ew.synchronizedLog(EventWriter.DEBUG, limit.toString());
            
            // Splunk Enterprise calls the modular input, 
            //   streams XML describing the inputs to stdin, 
            //   and waits for XML on stdout describing events.

            ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"Processing Data...\"");

            
            HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);
            
            ServiceArgs serviceArgs = new ServiceArgs();
            
            serviceArgs.setHost("localhost");
            //serviceArgs.setToken(sessionKey);
            serviceArgs.setPort(8089);
            serviceArgs.setScheme("https");
            serviceArgs.setApp("kvstore");
            
            
            Service splunkService = Service.connect(serviceArgs);
            
            ResponseMessage rm = splunkService.get("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state");
            
            ew.synchronizedLog(EventWriter.DEBUG, "infoMsg=\"KVStore response = " + String.valueOf(rm.getStatus()) + "\"");
            BufferedReader reader = new BufferedReader(new InputStreamReader(rm.getContent(), "UTF-8"));
            stanza_state kvStoreStanza = null;
            String offset = null;
            Integer error_count = 0;
            while (true) 
            {
                String line = reader.readLine();
                
                if (line == null) 
                {   
                    break;
                }
                
                
                Gson gson = new Gson();
                stanza_state[] stans = gson.fromJson(line,  stanza_state[].class);
                for(stanza_state ss : stans)
                {
                    if(inputName.equalsIgnoreCase(ss.stanza) == true)
                    {
                        kvStoreStanza = ss;
                        offset = ss.offset;
                        if(ss.error_count == null)
                        {
                            error_count = 0;
                        }
                        else
                        {
                            error_count = ss.error_count;
                        }
                        
                    }
                }
               
            }
            
            String queryString = processQueryString(initial_epoch_time, final_epoch_time, offset, limit);
            
            String urlToRequest = "https://" + hostname + "/siem/v1/configs/" + security_configuration_id_s_ + queryString;
            ew.synchronizedLog(EventWriter.INFO, "urlToRequest=" + urlToRequest);
            
            ClientCredential credential = ClientCredential.builder()
                    .accessToken(access_token)
                    .clientToken(client_token)
                    .clientSecret(client_secret)
                    .host(hostname)
                    .build();
            
            HttpClient client = HttpClientBuilder.create()
                    .addInterceptorFirst(new ApacheHttpClientEdgeGridInterceptor(credential))
                    .setRoutePlanner(new ApacheHttpClientEdgeGridRoutePlanner(credential))
                    .build();

            
            
            HttpGet request = new HttpGet(urlToRequest);
            HttpResponse response = null;
            int statusCode = 0;
            
            try {
                 response = client.execute(request);
                 statusCode = response.getStatusLine().getStatusCode();

                 if(statusCode == 200)
                 {
                     
                     //String responseData = EntityUtils.toString(response.getEntity());
                     //String lines[] = responseData.split("\\r?\\n");

                     JsonParser parser = new JsonParser();
                     InputStream instream = response.getEntity().getContent();
                     BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(instream));

                     String line = "";

                     long numLines = 0;
                     
                     String next = "";
                     line = bufferedreader.readLine();
                     for (boolean first = true, last = (line == null); !last; first = false, line = next) 
                     {
                         try 
                         {
                             last = ((next = bufferedreader.readLine()) == null);

                             if (last) 
                             {

                                 if(numLines == 0)
                                 {
                                     Event event = new Event();
                                     event.setStanza(inputName);
                                     event.setData("No New Data");
                                     ew.writeEvent(event);
                                 }
                                 
                                 
                                 ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"parsing last line\"");
                                 ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"numLines=" + String.valueOf(numLines) + "\"");
                                 ew.synchronizedLog(EventWriter.INFO, "line=" + line);
                                 
                                 String newOffset = "";
                                 if("Bad offset, expired data requested".equalsIgnoreCase(line) == false)
                                 {
                                     JsonObject jo = parser.parse(line).getAsJsonObject();
                                     newOffset = jo.get("offset").getAsString();                     
                                 }
                                 
                                 ew.synchronizedLog(EventWriter.INFO, "offset=\"" + newOffset + "\"");
                                 
                                 Gson gson = new Gson();
                                 if(kvStoreStanza != null)
                                 {
                                     kvStoreStanza.offset = newOffset;
                                     kvStoreStanza.error_count = 0;
                                     kvStoreStanza.stanza_change = false;
                                     
                                     ew.synchronizedLog(EventWriter.INFO, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"");
                                     
                                     RequestMessage requestMessage = new RequestMessage("POST");
                                     requestMessage.getHeader().put("Content-Type",  "application/json");
                                     requestMessage.setContent(gson.toJson(kvStoreStanza));
                                     
                                     ResponseMessage rm2 = splunkService.send(String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key), requestMessage);
                                     ew.synchronizedLog(EventWriter.DEBUG, String.valueOf(rm2.getStatus()));
                                 }
                                 else
                                 {
                                     
                                     kvStoreStanza = new stanza_state();
                                     kvStoreStanza.offset = newOffset;
                                     kvStoreStanza.stanza = inputName;
                                     
                                     ew.synchronizedLog(EventWriter.INFO, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"");
                                                        
                                     RequestMessage requestMessage = new RequestMessage("POST");
                                     requestMessage.getHeader().put("Content-Type",  "application/json");
                                     requestMessage.setContent(gson.toJson(kvStoreStanza));
                                     
                                     ResponseMessage rm2 = splunkService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/", requestMessage);
                                     ew.synchronizedLog(EventWriter.DEBUG, String.valueOf(rm2.getStatus()));
                                 }
                             } 
                             else 
                             {
                                 numLines++;

                                 ew.synchronizedLog(EventWriter.DEBUG, line);
                                 JsonObject jObj = parser.parse(line).getAsJsonObject();
                                 JsonObject newJsonObj = processData(jObj);
                                 ew.synchronizedLog(EventWriter.DEBUG, newJsonObj.toString());
                                 
                                 Event event = new Event();
                                 event.setStanza(inputName);
                                 event.setData(newJsonObj.toString());
                                 
                                 try
                                 {
                                     ew.writeEvent(event);
                                 }
                                 catch(MalformedDataException e)
                                 {
                                     ew.synchronizedLog(EventWriter.ERROR, "MalformedDataException writing to input " + inputName + ": " + e.toString());
                                 }
                             }
                         } 
                         catch (Exception ex) 
                         {
                             ew.synchronizedLog(EventWriter.ERROR, "Exception processing line: " + line + ": " + ex.toString());
                         }
                     }
                 }
                 else
                 {
                     
                     String responseData = EntityUtils.toString(response.getEntity());
                     String errorEvent = "error=Status Code not 200: [" + statusCode + "] : " + responseData;
                     
                     ew.synchronizedLog(EventWriter.INFO, errorEvent);
                     
                     Event event = new Event();
                     event.setStanza(inputName);
                     event.setData(errorEvent);
                     ew.writeEvent(event);
                     
                     error_count++;
                     if(error_count >= _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_)
                     {
                         ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"" + _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_ + " consecutive errors.  Clearing offset and error count\"");
                         offset = "";
                         error_count = 0;
                     }
                     
                     
                     Gson gson = new Gson();
                     kvStoreStanza.offset = offset;
                     kvStoreStanza.error_count = error_count;
                     kvStoreStanza.stanza_change = false;
                     
                     ew.synchronizedLog(EventWriter.INFO, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"");
                     
                     RequestMessage requestMessage = new RequestMessage("POST");
                     requestMessage.getHeader().put("Content-Type",  "application/json");
                     requestMessage.setContent(gson.toJson(kvStoreStanza));
                     
                     ResponseMessage rm2 = splunkService.send(String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key), requestMessage);
                     ew.synchronizedLog(EventWriter.DEBUG, "infoMsg=\"KVStore response = " + String.valueOf(rm2.getStatus()) + "\"");
                     
                 }
                                  
             } catch (IOException e) {   
                 e.printStackTrace();
                 
                 String responseData = EntityUtils.toString(response.getEntity());
                 String errorEvent = "error=\"Exception processing response\"";
                 
                 ew.synchronizedLog(EventWriter.INFO, errorEvent);
                 
                 Event event = new Event();
                 event.setStanza(inputName);
                 event.setData(errorEvent);
                 ew.writeEvent(event);
                 
                 error_count++;
                 if(error_count >= _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_)
                 {
                     ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"" + _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_ + " consecutive errors.  Clearing offset and error count\"");
                     offset = "";
                     error_count = 0;
                 }
                 
                 
                 Gson gson = new Gson();
                 kvStoreStanza.offset = offset;
                 kvStoreStanza.error_count = error_count;
                 kvStoreStanza.stanza_change = false;
                 
                 ew.synchronizedLog(EventWriter.INFO, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"");
                 
                 RequestMessage requestMessage = new RequestMessage("POST");
                 requestMessage.getHeader().put("Content-Type",  "application/json");
                 requestMessage.setContent(gson.toJson(kvStoreStanza));
                 
                 ResponseMessage rm2 = splunkService.send(String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key), requestMessage);
                 ew.synchronizedLog(EventWriter.INFO, String.valueOf(rm2.getStatus()));
                 
             }
        }
        
        ew.synchronizedLog(EventWriter.INFO, "end streamEvents");
    }
}