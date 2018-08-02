package com.akamai.siem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
//import org.apache.commons.codec.binary.StringUtils;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import com.akamai.edgegrid.signer.ClientCredential;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridInterceptor;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridRoutePlanner;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.splunk.HttpService;
import com.splunk.Password;
import com.splunk.PasswordCollection;
import com.splunk.RequestMessage;
import com.splunk.ResponseMessage;
import com.splunk.SSLSecurityProtocol;
import com.splunk.Service;
import com.splunk.ServiceArgs;
import com.splunk.modularinput.Argument;
import com.splunk.modularinput.Argument.DataType;
import com.splunk.modularinput.Event;
import com.splunk.modularinput.EventWriter;
import com.splunk.modularinput.InputDefinition;
import com.splunk.modularinput.MalformedDataException;
import com.splunk.modularinput.Scheme;
import com.splunk.modularinput.Scheme.StreamingMode;
import com.splunk.modularinput.Script;
import com.splunk.modularinput.SingleValueParameter;
import com.splunk.modularinput.ValidationDefinition;

//All modular inputs should inherit from the abstract base class com.splunk.modularinput.Script. They must override
//the getScheme and streamEvents methods, and, if the scheme returned by getScheme had
//Scheme.setUseExternalValidation(true) called on it, the validateInput method. The user must provide a main
//method since static methods can't be inherited in Java. However, the main is very simple.
public class Main extends Script {
	private static String _MASK_ = "<hidden>";

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
	private static Integer _AKAMAI_API_MAX_LIMIT_ = 600000;
	private static Integer _AKAMAI_API_DEFAULT_LIMIT_ = 150000;
	private static Integer _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_ = 5;

	private static final Set<String> base64fields = new HashSet<String>(Arrays.asList(new String[] { "rules",
			"ruleVersions", "ruleMessages", "ruleTags", "ruleData", "ruleSelectors", "ruleActions" }));

	private static final Map<String, String> transform;
	private static final Map<String, Integer> logLevel;

	static {
		HashMap<String, String> myTransform = new HashMap<String, String>();
		myTransform.put("ruleActions", "action");
		myTransform.put("ruleData", "data");
		myTransform.put("ruleMessages", "message");
		myTransform.put("ruleSelectors", "selector");
		myTransform.put("ruleTags", "tag");
		myTransform.put("ruleVersions", "version");
		myTransform.put("rules", "id");

		transform = Collections.unmodifiableMap(myTransform);

		HashMap<String, Integer> mylogLevel = new HashMap<String, Integer>();
		mylogLevel.put(EventWriter.DEBUG, 0);
		mylogLevel.put(EventWriter.INFO, 1);
		mylogLevel.put(EventWriter.WARN, 2);
		mylogLevel.put(EventWriter.ERROR, 3);
		mylogLevel.put(EventWriter.FATAL, 4);

		logLevel = Collections.unmodifiableMap(mylogLevel);

	}

	public static String decode(String value) throws Exception {
		return new String(Base64.decodeBase64(value), StandardCharsets.UTF_8);
	}

	private static JsonObject parseData(JsonObject d, boolean isCustom) throws Exception {
		StringBuilder sb = new StringBuilder("");

		for (Entry<String, JsonElement> entry : d.entrySet()) {
			if (entry.getValue().isJsonObject() == true) {
				boolean isCustomEntry = false;
				if ("custom".equalsIgnoreCase(entry.getKey()) == true) {
					isCustomEntry = true;
				}
				parseData(entry.getValue().getAsJsonObject(), isCustomEntry);
			} else {
				String k = entry.getKey();
				JsonElement je = entry.getValue();

				String v = entry.getValue().getAsString();

				String urlDecodeValue = v;
				try {
					urlDecodeValue = java.net.URLDecoder.decode(v, "UTF-8");
				} catch (Exception ex) {
				}

				String[] tokenizedResult = urlDecodeValue.split(";");

				if (tokenizedResult.length > 1) {
					ArrayList<String> decodedValues = new ArrayList<String>();
					for (String s : tokenizedResult) {
						if ((base64fields.contains(k) == true) || (isCustom == true)) {
							String[] detectSpaces = s.split(" ");
							StringBuilder sb2 = new StringBuilder();
							for (String ss : detectSpaces) {
								if (sb2.length() > 0) {
									sb2.append(" ");
								}

								sb2.append(decode(ss));
							}

							decodedValues.add(sb2.toString());
						} else {
							decodedValues.add(s);
						}
					}

					JsonParser parser = new JsonParser();
					Gson gson = new Gson();
					entry.setValue(parser.parse(gson.toJson(decodedValues)));
				} else if (tokenizedResult.length > 0) {
					if ((base64fields.contains(k) == true) || (isCustom == true)) {
						String[] detectSpaces = tokenizedResult[0].split(" ");
						StringBuilder sb2 = new StringBuilder();
						for (String ss : detectSpaces) {
							if (sb2.length() > 0) {
								sb2.append(" ");
							}

							sb2.append(decode(ss));
						}

						JsonElement element = new JsonPrimitive(sb2.toString());
						entry.setValue(element);
					} else {
						JsonElement element = new JsonPrimitive(urlDecodeValue);
						entry.setValue(element);
					}
				} else {
					JsonElement element = new JsonPrimitive("");
					entry.setValue(element);
				}
			}
		}

		return (d);
	}

	public static JsonObject processData(JsonObject d) throws Exception {
		JsonObject parsedData = parseData(d, false);

		JsonElement attackData = parsedData.get("attackData");
		JsonObject attackDataJsonObj = attackData.getAsJsonObject();

		Boolean isRulesArray = parsedData.get("attackData").getAsJsonObject().get("rules").isJsonArray();
		JsonArray rulesArray = null;
		Integer i = 0;
		Integer size = 1;

		if (isRulesArray == true) {
			rulesArray = parsedData.get("attackData").getAsJsonObject().get("rules").getAsJsonArray();
			size = rulesArray.size();
		}

		ArrayList<Map<String, String>> parsedRules = new ArrayList<Map<String, String>>();
		while (i < size) {
			Map<String, String> ruleData = new HashMap<String, String>();

			Iterator<Entry<String, String>> it = transform.entrySet().iterator();
			while (it.hasNext() == true) {
				Map.Entry<String, String> pair = (Map.Entry<String, String>) it.next();

				if (parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).isJsonArray() == true) {
					if (i < parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsJsonArray().size()) {
						ruleData.put(pair.getValue(), parsedData.get("attackData").getAsJsonObject().get(pair.getKey())
								.getAsJsonArray().get(i).getAsString());
					} else {
						ruleData.put(pair.getValue(), "");
					}
				} else {
					ruleData.put(pair.getValue(),
							parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsString());
				}

				// it.remove(); // avoids a ConcurrentModificationException
			}

			parsedRules.add(ruleData);

			i++;
		}

		Iterator<Entry<String, String>> it = transform.entrySet().iterator();
		while (it.hasNext() == true) {
			Map.Entry<String, String> pair = (Map.Entry<String, String>) it.next();

			attackDataJsonObj.remove(pair.getKey());

			// it.remove(); // avoids a ConcurrentModificationException
		}

		JsonParser parser = new JsonParser();
		Gson gson = new Gson();

		attackDataJsonObj.add("rules", parser.parse(gson.toJson(parsedRules)));

		return (parsedData);

	}

	private static String processQueryString(String initialEpochTime, String finalEpochTime, String offset,
			String limit) {
		String retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
		if (StringUtils.isEmpty(finalEpochTime) == false) {
			if (StringUtils.isEmpty(initialEpochTime) == false) {
				retVal = String.format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
				retVal = retVal + String.format(_AKAMAI_API_PARAM_TIME_TO_BASED_, finalEpochTime);
			} else {
				retVal = String.format(_AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_, finalEpochTime);
			}

			if (StringUtils.isEmpty(limit) == false) {
				retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
			} else {
				retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
			}

		} else if (StringUtils.isEmpty(initialEpochTime) == false) {
			if (StringUtils.isEmpty(offset) == true) {
				retVal = String.format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
			} else {
				retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
			}

			if (StringUtils.isEmpty(limit) == false) {
				retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
			} else {
				retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
			}

		} else {
			if (StringUtils.isEmpty(offset) == true) {
				retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, "NULL");
			} else {
				retVal = String.format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
			}

			if (StringUtils.isEmpty(limit) == false) {
				retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
			} else {
				retVal = retVal + String.format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
			}
		}

		return (retVal);

	}

	private static void writeLog(String log_level, String log_threshold, String message, EventWriter ew) {

		if ((logLevel.containsKey(log_level) == true) && (logLevel.containsKey(log_threshold) == true)) {
			int ilogLevel = logLevel.get(log_level);
			int ilogThreshold = logLevel.get(log_threshold);

			if (ilogLevel >= ilogThreshold) {
				ew.synchronizedLog(EventWriter.INFO, message);
			}
		}
	}

	public static void main(String[] args) throws Exception {
		new Main().run(args);
	}

	// When Splunk starts, it looks for all the modular inputs defined by its
	// configuration, and tries to run them
	// with the argument --scheme. Splunkd expects the modular inputs to print a
	// description of the input in XML
	// on stdout. The modular input framework takes care of all the details of
	// formatting XML and printing it. The
	// user need only override getScheme and return a new Scheme object.
	@Override
	public Scheme getScheme() {

		Scheme scheme = new Scheme("AKAMAI SIEM API");
		scheme.setDescription("Security Information and Event Management");
		scheme.setUseExternalValidation(true);
		scheme.setStreamingMode(StreamingMode.XML);
		scheme.setUseSingleInstance(false);

		Argument hostnameArgument = new Argument("hostname");
		hostnameArgument.setName("hostname");
		hostnameArgument.setDescription("");

		hostnameArgument.setRequiredOnCreate(true);
		hostnameArgument.setRequiredOnEdit(true);
		scheme.addArgument(hostnameArgument);

		Argument security_configuration_id_s_Argument = new Argument("security_configuration_id_s_");
		security_configuration_id_s_Argument.setName("security_configuration_id_s_");
		security_configuration_id_s_Argument.setDescription("[semicolon delimited]");
		security_configuration_id_s_Argument.setRequiredOnCreate(true);
		security_configuration_id_s_Argument.setRequiredOnEdit(true);
		scheme.addArgument(security_configuration_id_s_Argument);

		Argument client_tokenArgument = new Argument("client_token");
		client_tokenArgument.setName("client_token");
		client_tokenArgument.setDescription("");
		client_tokenArgument.setRequiredOnCreate(true);
		client_tokenArgument.setRequiredOnEdit(true);
		scheme.addArgument(client_tokenArgument);

		Argument client_secretArgument = new Argument("client_secret");
		client_secretArgument.setName("client_secret");
		client_secretArgument.setDescription("");
		client_secretArgument.setRequiredOnCreate(true);
		client_secretArgument.setRequiredOnEdit(true);
		scheme.addArgument(client_secretArgument);

		Argument access_tokenArgument = new Argument("access_token");
		access_tokenArgument.setName("access_token");
		access_tokenArgument.setDescription("");
		access_tokenArgument.setRequiredOnCreate(true);
		access_tokenArgument.setRequiredOnEdit(true);
		scheme.addArgument(access_tokenArgument);

		Argument initial_epoch_timeArgument = new Argument("initial_epoch_time");
		initial_epoch_timeArgument.setName("initial_epoch_time");
		initial_epoch_timeArgument.setDescription("");
		initial_epoch_timeArgument.setRequiredOnCreate(false);
		initial_epoch_timeArgument.setRequiredOnEdit(false);
		initial_epoch_timeArgument.setDataType(DataType.NUMBER);
		scheme.addArgument(initial_epoch_timeArgument);

		Argument final_epoch_timeArgument = new Argument("final_epoch_time");
		final_epoch_timeArgument.setName("final_epoch_time");
		final_epoch_timeArgument.setDescription("");
		final_epoch_timeArgument.setRequiredOnCreate(false);
		final_epoch_timeArgument.setRequiredOnEdit(false);
		final_epoch_timeArgument.setDataType(DataType.NUMBER);
		scheme.addArgument(final_epoch_timeArgument);

		Argument limitArgument = new Argument("limit");
		limitArgument.setName("limit");
		limitArgument.setDescription("");
		limitArgument.setRequiredOnCreate(false);
		limitArgument.setRequiredOnEdit(false);
		limitArgument.setDataType(DataType.NUMBER);
		scheme.addArgument(limitArgument);

		Argument log_levelArgument = new Argument("log_level");
		log_levelArgument.setName("log_level");
		log_levelArgument.setDescription("DEBUG, INFO, WARN, ERROR, FATAL");
		log_levelArgument.setRequiredOnCreate(false);
		log_levelArgument.setRequiredOnEdit(false);

		scheme.addArgument(log_levelArgument);

		return (scheme);
	}

	// In this example we are using external validation, since we want max to always
	// be greater than min.
	// If validateInput does not throw an Exception, the input is assumed to be
	// valid. Otherwise it prints the
	// exception as an error message when telling splunkd that the configuration is
	// not valid.
	//
	// When using external validation, after splunkd calls the modular input with
	// --scheme to get a scheme, it calls it
	// again with --validate-arguments for each instance of the modular input in its
	// configuration files, feeding XML
	// on stdin to the modular input to get it to do validation. It calls it the
	// same way again whenever a modular
	// input's configuration is changed.

	@Override
	public void validateInput(ValidationDefinition definition, EventWriter ew) throws Exception {
		// Get the values of the two parameters. There are also methods getFloat,
		// getInt, getBoolean, etc.,
		// and getValue to get the string representation.

		try {

			HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

			ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"begin validate input\"");

			ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"stanza name = " + definition.getName() + "\"");

			String log_level = ((SingleValueParameter) definition.getParameters().get("log_level")).getValue();
			ew.synchronizedLog(EventWriter.INFO, String.format("log_level=%s", log_level));

			String session_key = definition.getSessionKey();
			writeLog(EventWriter.DEBUG, log_level, String.format("session_key=%s", session_key), ew);

			String hostname = ((SingleValueParameter) definition.getParameters().get("hostname")).getValue();
			if ((hostname != null) && (hostname.isEmpty() == false)) {
				hostname = "https://" + hostname;
			}
			writeLog(EventWriter.DEBUG, log_level, String.format("hostname=%s", hostname), ew);

			String security_configuration_id_s_ = ((SingleValueParameter) definition.getParameters()
					.get("security_configuration_id_s_")).getValue();
			writeLog(EventWriter.DEBUG, log_level,
					String.format("security_configuration_id_s_=%s", security_configuration_id_s_), ew);

			String client_token = ((SingleValueParameter) definition.getParameters().get("client_token")).getValue();
			writeLog(EventWriter.DEBUG, log_level, String.format("client_token=%s", client_token), ew);

			String client_secret = ((SingleValueParameter) definition.getParameters().get("client_secret")).getValue();
			// writeLog(EventWriter.DEBUG, log_level, String.format("client_secret=%s",
			// client_secret), ew);

			String access_token = ((SingleValueParameter) definition.getParameters().get("access_token")).getValue();
			writeLog(EventWriter.DEBUG, log_level, String.format("access_token=%s", access_token), ew);

			String initial_epoch_time = "";
			SingleValueParameter svp = ((SingleValueParameter) definition.getParameters().get("initial_epoch_time"));
			if (svp != null) {
				initial_epoch_time = svp.getValue();
			}
			writeLog(EventWriter.DEBUG, log_level, String.format("initial_epoch_time=%s", initial_epoch_time), ew);

			String final_epoch_time = "";
			svp = ((SingleValueParameter) definition.getParameters().get("final_epoch_time"));
			if (svp != null) {
				final_epoch_time = svp.getValue();
			}
			writeLog(EventWriter.DEBUG, log_level, String.format("final_epoch_time=%s", final_epoch_time), ew);

			String limit = "";
			svp = ((SingleValueParameter) definition.getParameters().get("limit"));
			if (svp != null) {
				limit = svp.getValue();
			}
			writeLog(EventWriter.DEBUG, log_level, String.format("limit=%s", limit), ew);

			List<String> errors = new ArrayList<String>();

			writeLog(EventWriter.DEBUG, log_level, "Begin Log Level validation", ew);
			if ((log_level != null) && (log_level.isEmpty() == false)) {
				if ((log_level.equalsIgnoreCase(EventWriter.DEBUG) == false)
						&& (log_level.equalsIgnoreCase(EventWriter.WARN) == false)
						&& (log_level.equalsIgnoreCase(EventWriter.ERROR) == false)
						&& (log_level.equalsIgnoreCase(EventWriter.FATAL) == false)
						&& (log_level.equalsIgnoreCase(EventWriter.INFO) == false)) {
					errors.add(String.format("%s is not valid Log Level", log_level));
					log_level = EventWriter.INFO;
				}
			} else {
				log_level = EventWriter.INFO;
			}
			writeLog(EventWriter.DEBUG, log_level, "Log Level validation complete", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Hostname validation", ew);
			if ((hostname != null) && (hostname.isEmpty() == false)) {
				String[] schemes = { "https" };
				UrlValidator urlValidator = new UrlValidator(schemes);
				if (urlValidator.isValid(hostname) == false) {
					errors.add(String.format("%s is an invalid Hostname", hostname));
				}
			} else {
				errors.add("Please specify a valid Hostname");
			}
			writeLog(EventWriter.DEBUG, log_level, "Hostname validation complete", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Security Configuration ID(s) validation", ew);
			if ((security_configuration_id_s_ != null) && (security_configuration_id_s_.isEmpty() == false)) {
				String[] parts = security_configuration_id_s_.split(_AKAMAI_API_SECURITY_CONFIG_DELIMITER_);
				for (String part : parts) {
					if (NumberUtils.isNumber(part) == true) {
						if (Integer.parseInt(part) <= 0) {
							errors.add(String.format("%s is not valid Security Configuration ID(s)", part));
						}
					} else {
						errors.add(String.format("%s is not valid Security Configuration ID(s)", part));
					}
				}
			} else {
				errors.add("Please specify a valid Security Configuration ID(s)");
			}
			writeLog(EventWriter.DEBUG, log_level, "Security Configuration ID(s) validation complete", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Client Token validation", ew);
			if ((client_token != null) && (client_token.isEmpty() == false)) {

			} else {
				errors.add("Please specify a valid Client Token");
			}
			writeLog(EventWriter.DEBUG, log_level, "Client Token validation complete", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Client Secret validation", ew);
			if ((client_secret != null) && (client_secret.isEmpty() == false)) {

				ServiceArgs akamaiServiceArgs = new ServiceArgs();
				akamaiServiceArgs.setHost("localhost");
				akamaiServiceArgs.setToken("Splunk " + session_key);
				akamaiServiceArgs.setPort(8089);
				akamaiServiceArgs.setScheme("https");
				akamaiServiceArgs.setApp("TA-Akamai_SIEM");

				writeLog(EventWriter.INFO, log_level, "infoMsg=\"Service connect...\"", ew);
				Service akamaiSplunkService = Service.connect(akamaiServiceArgs);

				writeLog(EventWriter.DEBUG, log_level, "get password service...", ew);
				PasswordCollection pColl = akamaiSplunkService.getPasswords();
				writeLog(EventWriter.DEBUG, log_level, "construct stanza...", ew);
				String key = String.format("%s:client_secret:", definition.getName());
				writeLog(EventWriter.DEBUG, log_level, key, ew);

				if (this._MASK_.equalsIgnoreCase(client_secret) == true) {
					if (pColl.containsKey(key) == false) {
						errors.add("Please specify a valid Client Secret");
					}
				}

				writeLog(EventWriter.DEBUG, log_level, "password validation complete", ew);

			} else {
				errors.add("Please specify a valid Client Secret");
			}
			writeLog(EventWriter.DEBUG, log_level, "Client Secret validation complete", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Access Token validation", ew);
			if ((access_token != null) && (access_token.isEmpty() == false)) {

			} else {
				errors.add("Please specify a valid Access Token");
			}
			writeLog(EventWriter.DEBUG, log_level, "Access Token validation complete ", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Initial Epoch Time validation", ew);
			if ((initial_epoch_time != null) && (initial_epoch_time.isEmpty() == false)) {
				if (NumberUtils.isNumber(initial_epoch_time) == true) {
					if (Integer.parseInt(initial_epoch_time) <= 0) {
						errors.add(String.format("%s is not valid Initial Epoch Time", initial_epoch_time));
					} else {

					}
				} else {
					errors.add(String.format("%s is not valid Initial Epoch Time", initial_epoch_time));
				}
			} else {
				if ((final_epoch_time != null) && (final_epoch_time.isEmpty() == false)) {
					errors.add(String.format("Initial Epoch Time must be specified"));
				}
			}
			writeLog(EventWriter.DEBUG, log_level, "Initial Epoch Time validation complete ", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Final Epoch Time validation", ew);
			if ((final_epoch_time != null) && (final_epoch_time.isEmpty() == false)) {
				if (NumberUtils.isNumber(final_epoch_time) == true) {
					if (Integer.parseInt(final_epoch_time) <= 0) {
						errors.add(String.format("%s is not valid Final Epoch Time", final_epoch_time));
					} else {

					}
				} else {
					errors.add(String.format("%s is not valid Final Epoch Time", final_epoch_time));
				}
			} else {
			}
			writeLog(EventWriter.DEBUG, log_level, "Final Epoch Time validation complete", ew);

			writeLog(EventWriter.DEBUG, log_level, "Begin Limit validation", ew);
			if ((limit != null) && (limit.isEmpty() == false)) {
				if (NumberUtils.isNumber(limit) == true) {
					if (Integer.parseInt(limit) <= 0) {
						errors.add(String.format("%s is not valid Limit", limit));
					} else if (Integer.parseInt(limit) > _AKAMAI_API_MAX_LIMIT_) {
						errors.add(String.format("%s is not valid Limit", limit));
					}
				} else {
					errors.add(String.format("%s is not valid Limit", limit));
				}
			} else {

			}
			writeLog(EventWriter.DEBUG, log_level, "Limit validation complete", ew);

			if (errors.size() > 0) {
				String formattedErrors = "";
				for (String error : errors) {
					if (formattedErrors.length() > 0) {
						formattedErrors += ", " + error;
					} else {
						formattedErrors = error;
					}
				}
				ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"found errors : " + formattedErrors + "\"");
				throw new InputException(formattedErrors);
			}
			writeLog(EventWriter.DEBUG, log_level, "Error Checking complete", ew);

			String instance_stanza = definition.getName();

			writeLog(EventWriter.DEBUG, log_level, String.format("instance_stanza=%s", instance_stanza), ew);

			ServiceArgs serviceArgs = new ServiceArgs();

			serviceArgs.setHost("localhost");
			serviceArgs.setToken("Splunk " + session_key);
			serviceArgs.setPort(8089);
			serviceArgs.setScheme("https");
			serviceArgs.setApp("kvstore");

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"KVStore connect...\"", ew);
			Service splunkService = Service.connect(serviceArgs);

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"KVStore get...\"", ew);
			ResponseMessage rm = null;
			try {
				writeLog(EventWriter.DEBUG, log_level, "getToken=" + splunkService.getToken(), ew);
				RequestMessage requestMessage = new RequestMessage("GET");
				rm = splunkService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state",
						requestMessage);
				writeLog(EventWriter.DEBUG, log_level,
						"infoMsg=\"KVStore response = " + String.valueOf(rm.getStatus()) + "\"", ew);

			} catch (Exception ex) {
				writeLog(EventWriter.ERROR, log_level, "exception=" + ex.toString(), ew);
			}

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Parse KVstore data...\"", ew);
			BufferedReader reader = new BufferedReader(new InputStreamReader(rm.getContent(), "UTF-8"));
			stanza_state kvStoreStanza = null;
			String offset = null;
			Integer error_count = 0;
			while (true) {
				String line = reader.readLine();

				if (line == null) {
					break;
				}

				Gson gson = new Gson();
				stanza_state[] stans = gson.fromJson(line, stanza_state[].class);
				for (stanza_state ss : stans) {
					String stanza_name = ss.stanza.substring(ss.stanza.indexOf("://") + 3);

					if (instance_stanza.equalsIgnoreCase(stanza_name) == true) {
						kvStoreStanza = ss;
						offset = ss.offset;
						if (ss.error_count == null) {
							error_count = 0;
						} else {
							error_count = ss.error_count;
						}

					}
				}

			}
			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Parse KVstore data...Complete!\"", ew);

			if (kvStoreStanza != null) {
				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"Found kvStoreStanza\"", ew);
				Gson gson = new Gson();
				kvStoreStanza.stanza_change = "1";
				writeLog(EventWriter.DEBUG, log_level, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"", ew);

				RequestMessage requestMessage = new RequestMessage("POST");
				requestMessage.getHeader().put("Content-Type", "application/json");
				requestMessage.setContent(gson.toJson(kvStoreStanza));

				ResponseMessage rm2 = splunkService.send(
						String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s",
								kvStoreStanza._key),
						requestMessage);
				writeLog(EventWriter.DEBUG, log_level, "getStatus=" + String.valueOf(rm2.getStatus()), ew);
			} else {
				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"Did NOT find kvStoreStanza\"", ew);
			}

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"end validate input\"", ew);
		} catch (InputException iex) {
			throw (iex);
		} catch (Exception ex) {
			writeLog(EventWriter.ERROR, EventWriter.ERROR, "exception=" + ex.toString(), ew);
		}
	}

	// Finally, the real action: splunk calls the modular input with no arguments,
	// streams a bunch of XML describing
	// the inputs to stdin, and waits for XML on stdout describing events.
	//
	// If you set setUseSingleInstance(true) on the scheme in getScheme, it will
	// pass all the instances of this input
	// to a single instance of this script and it's your job to handle them all.
	// Otherwise, it starts a JVM for each
	// instance of the input.

	@Override
	public void streamEvents(InputDefinition inputs, EventWriter ew)
			throws MalformedDataException, XMLStreamException, IOException {

		HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

		// try {
		// BasicConfigurator.configure();
		ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"begin streamEvents\"");
		// writeLog(EventWriter.INFO, inputs.getInputs().keySet().toString());

		for (String inputName : inputs.getInputs().keySet()) {

			String log_level = "";
			try {
				log_level = ((SingleValueParameter) inputs.getInputs().get(inputName).get("log_level")).getValue();
				log_level = log_level.toUpperCase();
				if ((log_level != null) && (log_level.isEmpty() == false)) {
					if ((log_level.equalsIgnoreCase(EventWriter.DEBUG) == false)
							&& (log_level.equalsIgnoreCase(EventWriter.WARN) == false)
							&& (log_level.equalsIgnoreCase(EventWriter.ERROR) == false)
							&& (log_level.equalsIgnoreCase(EventWriter.FATAL) == false)
							&& (log_level.equalsIgnoreCase(EventWriter.INFO) == false)) {
						ew.synchronizedLog(EventWriter.INFO,
								"infoMsg=\"Errors while processing Log Level.  Please check instance stanza configuration.  Defaulting to INFO\"");
						log_level = EventWriter.INFO;
					}
				} else {
					ew.synchronizedLog(EventWriter.INFO,
							"infoMsg=\"Errors while processing Log Level.  Please check instance stanza configuration.  Defaulting to INFO\"");
					log_level = EventWriter.INFO;
				}
			} catch (Exception ex) {
				ew.synchronizedLog(EventWriter.INFO,
						"infoMsg=\"Errors while processing Log Level.  Please check instance stanza configuration.  Defaulting to INFO\"");
				log_level = EventWriter.INFO;
			}

			writeLog(EventWriter.DEBUG, log_level, "log_level=" + log_level, ew);

			writeLog(EventWriter.DEBUG, log_level, "inputName=" + inputName, ew);

			writeLog(EventWriter.DEBUG, log_level, "inputNametoString=" + inputs.getInputs().get(inputName).toString(),
					ew);

			String hostname = ((SingleValueParameter) inputs.getInputs().get(inputName).get("hostname")).getValue();
			writeLog(EventWriter.DEBUG, log_level, "hostname=" + hostname, ew);

			String security_configuration_id_s_ = ((SingleValueParameter) inputs.getInputs().get(inputName)
					.get("security_configuration_id_s_")).getValue();
			writeLog(EventWriter.DEBUG, log_level, "security_configuration_id_s_=" + security_configuration_id_s_, ew);

			String client_token = ((SingleValueParameter) inputs.getInputs().get(inputName).get("client_token"))
					.getValue();
			writeLog(EventWriter.DEBUG, log_level, "client_token=" + client_token, ew);

			String client_secret = ((SingleValueParameter) inputs.getInputs().get(inputName).get("client_secret"))
					.getValue();
			// writeLog(EventWriter.DEBUG, log_level, "client_secret=" + client_secret, ew);

			String access_token = ((SingleValueParameter) inputs.getInputs().get(inputName).get("access_token"))
					.getValue();

			writeLog(EventWriter.DEBUG, log_level, "access_token=" + access_token, ew);

			String initial_epoch_time = "";
			try {
				initial_epoch_time = ((SingleValueParameter) inputs.getInputs().get(inputName)
						.get("initial_epoch_time")).getValue();
			} catch (Exception ex) {
			}

			writeLog(EventWriter.DEBUG, log_level, "initial_epoch_time=" + initial_epoch_time, ew);

			String final_epoch_time = "";
			try {
				final_epoch_time = ((SingleValueParameter) inputs.getInputs().get(inputName).get("final_epoch_time"))
						.getValue();
			} catch (Exception ex) {
			}

			writeLog(EventWriter.DEBUG, log_level, "final_epoch_time=" + final_epoch_time, ew);

			String limit = "";
			try {
				limit = ((SingleValueParameter) inputs.getInputs().get(inputName).get("limit")).getValue();
			} catch (Exception ex) {
			}

			writeLog(EventWriter.DEBUG, log_level, "limit=" + limit, ew);

			String sessionKey = inputs.getSessionKey();
			writeLog(EventWriter.DEBUG, log_level, "sessionKey=" + sessionKey, ew);

			if (this._MASK_.equalsIgnoreCase(client_secret) == true) {

				ServiceArgs akamaiServiceArgs = new ServiceArgs();

				akamaiServiceArgs.setHost("localhost");
				akamaiServiceArgs.setToken("Splunk " + sessionKey);
				akamaiServiceArgs.setPort(8089);
				akamaiServiceArgs.setScheme("https");
				akamaiServiceArgs.setApp("TA-Akamai_SIEM");

				writeLog(EventWriter.INFO, log_level, "infoMsg=\"Service connect...\"", ew);
				Service akamaiSplunkService = Service.connect(akamaiServiceArgs);

				RequestMessage akamaiRequestMessage = new RequestMessage("GET");
				// inputName=TA-Akamai_SIEM://csxcz
				String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");
				String modInput = String.format(
						"/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json",
						URLEncoder.encode(inputStanza, "UTF-8"));

				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"" + modInput + "\"", ew);
				ResponseMessage akamairm = akamaiSplunkService.send(modInput, akamaiRequestMessage);
				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"" + akamairm.getStatus() + "\"", ew);

				BufferedReader akamaiReader = new BufferedReader(new InputStreamReader(akamairm.getContent(), "UTF-8"));
				while (true) {
					String line = akamaiReader.readLine();
					if (line == null) {
						break;
					}

					Gson gson = new Gson();

					InputStanza is = gson.fromJson(line, InputStanza.class);
					List<com.akamai.siem.Entry> entries = is.getEntry();
					if (entries != null) {
						for (com.akamai.siem.Entry entry : entries) {
							Content content = entry.getContent();
							String clientSecret = content.getClientSecret();

							PasswordCollection pColl = akamaiSplunkService.getPasswords();

							String key = String.format("%s:client_secret:", inputStanza);
							if (pColl.containsKey(key) == true) {
								Password p = pColl.get(key);
								client_secret = p.getClearPassword();
							}
						}
					}
				}
			}

			writeLog(EventWriter.DEBUG, log_level, "client_secret=" + client_secret, ew);

			// Splunk Enterprise calls the modular input,
			// streams XML describing the inputs to stdin,
			// and waits for XML on stdout describing events.

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Processing Data...\"", ew);

			ServiceArgs serviceArgs = new ServiceArgs();

			serviceArgs.setHost("localhost");
			serviceArgs.setToken("Splunk " + sessionKey);
			serviceArgs.setPort(8089);
			serviceArgs.setScheme("https");
			serviceArgs.setApp("kvstore");

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Service connect...\"", ew);
			Service splunkService = Service.connect(serviceArgs);

			// stanza_state kvStoreStanza = getKvStoreStanza(splunkService, inputName, ew);

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Service get...\"", ew);
			ResponseMessage rm = null;
			try {
				writeLog(EventWriter.DEBUG, log_level, "getToken=" + splunkService.getToken(), ew);
				RequestMessage requestMessage = new RequestMessage("GET");
				rm = splunkService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state",
						requestMessage);
				writeLog(EventWriter.DEBUG, log_level,
						"infoMsg=\"KVStore response = " + String.valueOf(rm.getStatus()) + "\"", ew);

			} catch (Exception ex) {
				writeLog(EventWriter.ERROR, log_level, "exception=" + ex.toString(), ew);
			}

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Parse KVstore data...\"", ew);
			BufferedReader reader = new BufferedReader(new InputStreamReader(rm.getContent(), "UTF-8"));
			stanza_state kvStoreStanza = null;
			String offset = null;
			Integer error_count = 0;
			while (true) {
				String line = reader.readLine();

				if (line == null) {
					break;
				}

				Gson gson = new Gson();
				stanza_state[] stans = gson.fromJson(line, stanza_state[].class);
				for (stanza_state ss : stans) {
					if (inputName.equalsIgnoreCase(ss.stanza) == true) {
						kvStoreStanza = ss;
						offset = ss.offset;
						if (ss.error_count == null) {
							error_count = 0;
						} else {
							error_count = ss.error_count;
						}

					}
				}

			}

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"Parse KVstore data...Complete!\"", ew);

			String queryString = processQueryString(initial_epoch_time, final_epoch_time, offset, limit);

			String urlToRequest = "https://" + hostname + "/siem/v1/configs/" + security_configuration_id_s_
					+ queryString;
			writeLog(EventWriter.INFO, log_level, "urlToRequest=" + urlToRequest, ew);

			ClientCredential credential = ClientCredential.builder().accessToken(access_token).clientToken(client_token)
					.clientSecret(client_secret).host(hostname).build();

			HttpClient client = HttpClientBuilder.create()
					.addInterceptorFirst(new ApacheHttpClientEdgeGridInterceptor(credential))
					.setRoutePlanner(new ApacheHttpClientEdgeGridRoutePlanner(credential)).build();

			HttpGet request = new HttpGet(urlToRequest);
			HttpResponse response = null;
			int statusCode = 0;

			try {
				response = client.execute(request);
				statusCode = response.getStatusLine().getStatusCode();
				writeLog(EventWriter.DEBUG, log_level, "statusCode=" + Integer.toString(statusCode), ew);

				if (statusCode == 200) {

					// String responseData = EntityUtils.toString(response.getEntity());
					// String lines[] = responseData.split("\\r?\\n");

					JsonParser parser = new JsonParser();
					InputStream instream = response.getEntity().getContent();
					BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(instream));

					String line = "";

					long numLines = 0;
					String next = "";
					line = bufferedreader.readLine();
					for (boolean first = true, last = (line == null); !last; first = false, line = next) {
						try {
							last = ((next = bufferedreader.readLine()) == null);

							if (last) {

								if (numLines == 0) {
									Event event = new Event();
									event.setStanza(inputName);
									event.setData("{\"infoMsg\": \"noNewData\"}");
									ew.writeEvent(event);
								}

								writeLog(EventWriter.INFO, log_level, "infoMsg=\"parsing last line\"", ew);
								writeLog(EventWriter.INFO, log_level,
										"infoMsg=\"numLines is " + String.valueOf(numLines) + "\"", ew);
								writeLog(EventWriter.INFO, log_level, "line=" + line, ew);

								String newOffset = "";
								if ("Bad offset, expired data requested".equalsIgnoreCase(line) == false) {
									JsonObject jo = parser.parse(line).getAsJsonObject();
									newOffset = jo.get("offset").getAsString();
								}

								writeLog(EventWriter.DEBUG, log_level, "offset=\"" + newOffset + "\"", ew);

								Gson gson = new Gson();
								if (kvStoreStanza != null) {
									kvStoreStanza.offset = newOffset;
									kvStoreStanza.error_count = 0;
									kvStoreStanza.stanza_change = "0";
									kvStoreStanza.stanza = inputName;

									writeLog(EventWriter.DEBUG, log_level,
											"kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"", ew);

									RequestMessage requestMessagex = new RequestMessage("POST");
									requestMessagex.getHeader().put("Content-Type", "application/json");
									requestMessagex.setContent(gson.toJson(kvStoreStanza));

									ResponseMessage rm2 = splunkService.send(String.format(
											"/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s",
											kvStoreStanza._key), requestMessagex);
									writeLog(EventWriter.DEBUG, log_level,
											"getStatus=" + String.valueOf(rm2.getStatus()), ew);
								} else {

									kvStoreStanza = new stanza_state();
									kvStoreStanza.offset = newOffset;
									kvStoreStanza.stanza = inputName;

									writeLog(EventWriter.DEBUG, log_level,
											"kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"", ew);

									RequestMessage requestMessagex = new RequestMessage("POST");
									requestMessagex.getHeader().put("Content-Type", "application/json");
									requestMessagex.setContent(gson.toJson(kvStoreStanza));

									ResponseMessage rm2 = splunkService.send(
											"/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/",
											requestMessagex);
									writeLog(EventWriter.DEBUG, log_level,
											"getStatus=" + String.valueOf(rm2.getStatus()), ew);
								}
							} else {
								numLines++;

								writeLog(EventWriter.DEBUG, log_level, "line=" + line, ew);

								JsonObject jObj = parser.parse(line).getAsJsonObject();
								JsonObject newJsonObj = processData(jObj);
								writeLog(EventWriter.DEBUG, log_level, "jsonObj=" + newJsonObj.toString(), ew);

								Event event = new Event();
								event.setStanza(inputName);
								event.setData(newJsonObj.toString());

								try {
									writeLog(EventWriter.DEBUG, log_level, "event:" + event.toString(), ew);
									// writeLog(EventWriter.DEBUG, log_level, "getData=" + event.getData(), ew);
									writeLog(EventWriter.DEBUG, log_level, "getHost=" + event.getHost(), ew);
									writeLog(EventWriter.DEBUG, log_level, "getIndex=" + event.getIndex(), ew);
									writeLog(EventWriter.DEBUG, log_level, "getSource=" + event.getSource(), ew);
									writeLog(EventWriter.DEBUG, log_level, "getSourceType=" + event.getSourceType(),
											ew);
									writeLog(EventWriter.DEBUG, log_level, "getStanza=" + event.getStanza(), ew);
									writeLog(EventWriter.DEBUG, log_level, "getTime=" + event.getTime(), ew);
									writeLog(EventWriter.DEBUG, log_level, "end event" + event.toString(), ew);
									ew.writeEvent(event);
									writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"writeEvent complete\"", ew);
								} catch (MalformedDataException e) {
									writeLog(EventWriter.ERROR, log_level, "MalformedDataException writing to input "
											+ inputName + ": " + e.toString(), ew);
								}
							}
						} catch (Exception ex) {
							writeLog(EventWriter.ERROR, log_level,
									"Exception processing line: " + line + ": " + ex.toString(), ew);
						}
					}
				} else {

					String responseData = EntityUtils.toString(response.getEntity());
					String errorEvent = "\"Status Code not 200 (" + statusCode + ")\"";

					writeLog(EventWriter.ERROR, log_level, "errorEvent=" + errorEvent, ew);
					writeLog(EventWriter.ERROR, log_level, responseData, ew);

					Event event = new Event();
					event.setStanza(inputName);
					event.setData(errorEvent);
					ew.writeEvent(event);

					error_count++;
					if (error_count >= _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_) {
						writeLog(EventWriter.WARN, log_level, "infoMsg=\"" + _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_
								+ " consecutive errors.  Clearing offset and error count\"", ew);
						offset = "";
						error_count = 0;
					}

					Gson gson = new Gson();
					boolean stanzaExists = true;
					if (kvStoreStanza == null) {
						kvStoreStanza = new stanza_state();
						stanzaExists = false;
					}

					kvStoreStanza.offset = offset;
					kvStoreStanza.error_count = error_count;
					kvStoreStanza.stanza_change = "0";
					kvStoreStanza.stanza = inputName;

					writeLog(EventWriter.DEBUG, log_level, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"", ew);

					RequestMessage requestMessage = new RequestMessage("POST");
					requestMessage.getHeader().put("Content-Type", "application/json");
					requestMessage.setContent(gson.toJson(kvStoreStanza));

					ResponseMessage rm2 = null;
					if (stanzaExists == true) {
						rm2 = splunkService.send(String.format(
								"/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s",
								kvStoreStanza._key), requestMessage);
					} else {
						rm2 = splunkService.send(
								"/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/",
								requestMessage);
					}

					writeLog(EventWriter.DEBUG, log_level,
							"infoMsg=\"KVStore response = " + String.valueOf(rm2.getStatus()) + "\"", ew);

				}

			} catch (IOException e) {
				e.printStackTrace();

				String responseData = EntityUtils.toString(response.getEntity());
				String errorEvent = "\"Exception processing response\"";

				writeLog(EventWriter.ERROR, log_level, "errorEvent=" + errorEvent, ew);

				Event event = new Event();
				event.setStanza(inputName);
				event.setData(errorEvent);
				ew.writeEvent(event);

				error_count++;
				if (error_count >= _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_) {
					writeLog(EventWriter.WARN, log_level, "infoMsg=\"" + _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_
							+ " consecutive errors.  Clearing offset and error count\"", ew);
					offset = "";
					error_count = 0;
				}

				Gson gson = new Gson();
				boolean stanzaExists = true;
				if (kvStoreStanza == null) {
					kvStoreStanza = new stanza_state();
					stanzaExists = false;
				}

				kvStoreStanza.offset = offset;
				kvStoreStanza.error_count = error_count;
				kvStoreStanza.stanza_change = "0";
				kvStoreStanza.stanza = inputName;

				writeLog(EventWriter.DEBUG, log_level, "kvStoreStanza=\"" + gson.toJson(kvStoreStanza) + "\"", ew);

				RequestMessage requestMessagex = new RequestMessage("POST");
				requestMessagex.getHeader().put("Content-Type", "application/json");
				requestMessagex.setContent(gson.toJson(kvStoreStanza));

				ResponseMessage rm2 = null;
				if (stanzaExists == true) {
					rm2 = splunkService.send(
							String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s",
									kvStoreStanza._key),
							requestMessagex);
				} else {
					rm2 = splunkService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/",
							requestMessagex);
				}

				writeLog(EventWriter.DEBUG, log_level, "getStatus=" + String.valueOf(rm2.getStatus()), ew);

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			MyRunnable myRunnable = new MyRunnable(sessionKey, log_level, inputName, this._MASK_, ew);
			Thread t = new Thread(myRunnable);
			t.start();
		}

		ew.synchronizedLog(EventWriter.INFO, "infoMsg=\"end streamEvents\"");
	}

	public class MyRunnable implements Runnable {

		private String sessionKey;
		private String log_level;
		private String inputName;
		private String _MASK_;
		private EventWriter ew;

		public MyRunnable(String sessionKey, String log_level, String inputName, String _MASK_, EventWriter ew) {
			this.sessionKey = sessionKey;
			this.log_level = log_level;
			this.inputName = inputName;
			this._MASK_ = _MASK_;
			this.ew = ew;
		}

		public void run() {
			try {
				HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

				writeLog(EventWriter.INFO, log_level, "infoMsg=\"Begin client secret crypto...\"", ew);

				ServiceArgs akamaiServiceArgs = new ServiceArgs();

				akamaiServiceArgs.setHost("localhost");
				akamaiServiceArgs.setToken("Splunk " + sessionKey);
				akamaiServiceArgs.setPort(8089);
				akamaiServiceArgs.setScheme("https");
				akamaiServiceArgs.setApp("TA-Akamai_SIEM");

				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"Service connect...\"", ew);
				Service akamaiSplunkService = Service.connect(akamaiServiceArgs);

				RequestMessage akamaiRequestMessage = new RequestMessage("GET");
				// inputName=TA-Akamai_SIEM://csxcz
				String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");
				String modInput = String.format(
						"/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json",
						URLEncoder.encode(inputStanza, "UTF-8"));

				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"" + modInput + "\"", ew);
				ResponseMessage akamairm = akamaiSplunkService.send(modInput, akamaiRequestMessage);
				writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"" + akamairm.getStatus() + "\"", ew);

				BufferedReader akamaiReader = new BufferedReader(new InputStreamReader(akamairm.getContent(), "UTF-8"));
				while (true) {
					String line = akamaiReader.readLine();
					if (line == null) {
						break;
					}

					Gson gson = new Gson();

					InputStanza is = gson.fromJson(line, InputStanza.class);
					List<com.akamai.siem.Entry> entries = is.getEntry();
					if (entries != null) {
						for (com.akamai.siem.Entry entry : entries) {
							Content content = entry.getContent();
							String clientSecret = content.getClientSecret();
							if (this._MASK_.equals(clientSecret) == false) {
								PasswordCollection pColl = akamaiSplunkService.getPasswords();

								String key = String.format("%s:client_secret:", inputStanza);
								if (pColl.containsKey(key) == true) {
									pColl.remove(key);
								}
								pColl.create("client_secret", clientSecret, inputStanza);

								content.setClientSecret(this._MASK_);

								RequestMessage requestMessage2 = new RequestMessage("POST");
								requestMessage2.getHeader().put("Content-Type", "application/x-www-form-urlencoded");

								String formurlencoded = "access_token="
										+ URLEncoder.encode(content.getAccessToken(), "UTF-8") + "&client_secret="
										+ URLEncoder.encode(content.getClientSecret(), "UTF-8") + "&client_token="
										+ URLEncoder.encode(content.getClientToken(), "UTF-8") + "&hostname="
										+ URLEncoder.encode(content.getHostname(), "UTF-8")
										+ "&security_configuration_id_s_="
										+ URLEncoder.encode(content.getSecurityConfigurationIdS(), "UTF-8");

								if (content.getFinalEpochTime() != null) {
									formurlencoded += ("&final_epoch_time="
											+ URLEncoder.encode(content.getFinalEpochTime().toString(), "UTF-8"));
								}

								if (content.getHost() != null) {
									formurlencoded += ("&host=" + URLEncoder.encode(content.getHost(), "UTF-8"));
								}

								if (content.getIndex() != null) {
									formurlencoded += ("&index=" + URLEncoder.encode(content.getIndex(), "UTF-8"));
								}

								if (content.getInitialEpochTime() != null) {
									formurlencoded += ("&initial_epoch_time="
											+ URLEncoder.encode(content.getInitialEpochTime().toString(), "UTF-8"));
								}

								if (content.getInterval() != null) {
									formurlencoded += ("&interval="
											+ URLEncoder.encode(content.getInterval(), "UTF-8"));
								}

								if (content.getLimit() != null) {
									formurlencoded += ("&limit="
											+ URLEncoder.encode(content.getLimit().toString(), "UTF-8"));
								}

								if (content.getLogLevel() != null) {
									formurlencoded += ("&log_level="
											+ URLEncoder.encode(content.getLogLevel(), "UTF-8"));
								}

								if (content.getSourcetype() != null) {
									formurlencoded += ("&sourcetype="
											+ URLEncoder.encode(content.getSourcetype(), "UTF-8"));
								}

								writeLog(EventWriter.DEBUG, log_level, "infoMsg=\"" + formurlencoded + "\"", ew);

								requestMessage2.setContent(formurlencoded);

								/*
								 * client_secret=%3Cfothing%20to%20see%20here%3E" &access_token=fdsajkl
								 * &client_token=fjskdal &hostname=fdjlksajfdasl
								 * &security_configuration_id_s_=fkjdslflsdkjfds");
								 */
								ResponseMessage rm2 = akamaiSplunkService.send(String.format(
										"/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json",
										URLEncoder.encode(inputStanza, "UTF-8")), requestMessage2);
								writeLog(EventWriter.DEBUG, log_level, "getStatus=" + String.valueOf(rm2.getStatus()),
										ew);
								BufferedReader reader2 = new BufferedReader(
										new InputStreamReader(rm2.getContent(), "UTF-8"));

							}

						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			writeLog(EventWriter.INFO, log_level, "infoMsg=\"End client secret crypto\"", ew);
		}
	}

}
