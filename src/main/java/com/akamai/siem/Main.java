package com.akamai.siem;

import static com.splunk.modularinput.EventWriter.ERROR;
import static com.splunk.modularinput.EventWriter.INFO;
import static com.splunk.modularinput.EventWriter.WARN;
import static com.splunk.modularinput.EventWriter.DEBUG;
import static java.lang.String.format;
import static java.lang.String.join;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.math.NumberUtils.isDigits;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
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
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
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
import com.splunk.modularinput.Parameter;
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

	private static String _AKAMAI_API_PARAM_OFFSET_BASED_ = "?offset=%s";
	private static String _AKAMAI_API_PARAM_TIME_BASED_ = "?from=%s";
	private static String _AKAMAI_API_PARAM_TIME_TO_BASED_ = "&to=%s";
	private static String _AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_ = "?to=%s";
	private static String _AKAMAI_API_PARAM_LIMIT_BASED = "&limit=%s";
	private static String _AKAMAI_API_SECURITY_CONFIG_DELIMITER_ = ";";
	private static Integer _AKAMAI_API_MAX_LIMIT_ = 600000;
	private static Integer _AKAMAI_API_DEFAULT_LIMIT_ = 150000;
	private static Integer _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_ = 5;

	private static final Set<String> base64fields = new HashSet<String>(
			Arrays.asList(new String[] { "rules", "ruleVersions", "ruleMessages", "ruleTags", "ruleData", "ruleSelectors", "ruleActions" }));

	private static final Map<String, String> transform;
	private static final Map<String, Integer> logLevel;

	private static final String EMPTY = "";

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

	public static void main(String[] args) throws Exception {
		new Main().run(args);
	}

	@Override
	public Scheme getScheme() {

		Scheme scheme = new Scheme("AKAMAI SIEM API");
		scheme.setDescription("Security Information and Event Management");
		scheme.setUseExternalValidation(true);
		scheme.setStreamingMode(StreamingMode.XML);
		scheme.setUseSingleInstance(false);

		createSchemeArgument(scheme, "hostname", EMPTY, true, true, DataType.STRING);
		createSchemeArgument(scheme, "security_configuration_id_s_", "[semicolon delimited]", true, true, DataType.STRING);
		createSchemeArgument(scheme, "client_token", EMPTY, true, true, DataType.STRING);
		createSchemeArgument(scheme, "client_secret", EMPTY, true, true, DataType.STRING);
		createSchemeArgument(scheme, "access_token", EMPTY, true, true, DataType.STRING);
		createSchemeArgument(scheme, "initial_epoch_time", EMPTY, false, false, DataType.NUMBER);
		createSchemeArgument(scheme, "final_epoch_time", EMPTY, false, false, DataType.NUMBER);
		createSchemeArgument(scheme, "limit", EMPTY, false, false, DataType.NUMBER);
		createSchemeArgument(scheme, "log_level", "DEBUG, INFO, WARN, ERROR, FATAL", false, false, DataType.STRING);
		createSchemeArgument(scheme, "proxy_host", EMPTY, false, false, DataType.STRING);
		createSchemeArgument(scheme, "proxy_port", EMPTY, false, false, DataType.NUMBER);

		return (scheme);
	}

	@Override
	public void validateInput(final ValidationDefinition definition, final EventWriter ew) throws Exception {
		String methodName = "validateInput";
		try {
			HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);
			ew.synchronizedLog(INFO, format("In %s, begin validate input", methodName));
			ew.synchronizedLog(INFO, format("In %s, stanza name = %s", methodName, definition.getName()));

			String log_level = getInputValueAsString(definition, "log_level");
			ew.synchronizedLog(INFO, format("In %s, log_level=%s", methodName, log_level));

			String session_key = definition.getSessionKey();
			debug(ew, log_level, format("In %s, session_key=%s", methodName, session_key));

			String hostname = getInputValueAsString(definition, "hostname");
			debug(ew, log_level, format("hostname=%s", hostname));

			if ((hostname != null) && !hostname.isEmpty()) {
				hostname = "https://" + hostname;
			}

			String security_configuration_id_s_ = getInputValueAsString(definition, "security_configuration_id_s_");
			debug(ew, log_level, format("security_configuration_id_s_=%s", security_configuration_id_s_));

			String client_token = getInputValueAsString(definition, "client_token");
			debug(ew, log_level, format("client_token=%s", client_token));

			String client_secret = getInputValueAsString(definition, "client_secret");

			String access_token = getInputValueAsString(definition, "access_token");
			debug(ew, log_level, format("access_token=%s", access_token));

			String initial_epoch_time = getInputValueAsString(definition, "initial_epoch_time");
			debug(ew, log_level, format("initial_epoch_time=%s", initial_epoch_time));

			String final_epoch_time = getInputValueAsString(definition, "final_epoch_time");
			debug(ew, log_level, format("final_epoch_time=%s", final_epoch_time));

			String limit = getInputValueAsString(definition, "limit");
			debug(ew, log_level, format("limit=%s", limit));

			String proxy_host = getInputValueAsString(definition, "proxy_host");
			debug(ew, log_level, format("proxy_host=%s", proxy_host));

			String proxy_port = getInputValueAsString(definition, "proxy_port");
			debug(ew, log_level, format("proxy_port=%s", proxy_port));

			debug(ew, log_level, "Begin Log Level validation");
			List<String> errors = new ArrayList<String>();
			if (!isValidLogLevel(log_level)) {
				errors.add(format("%s is not a valid Log Level", log_level));
				log_level = EventWriter.INFO;
			}
			debug(ew, log_level, "Log Level validation complete");

			debug(ew, log_level, "Begin Hostname validation");
			if (!isValidHostName(hostname)) {
				errors.add(format("%s is an invalid Hostname", hostname));
			}
			debug(ew, log_level, "Hostname validation complete");

			debug(ew, log_level, "Begin Security Configuration ID(s) validation");
			validateSecurityConfigIds(security_configuration_id_s_, errors);
			debug(ew, log_level, "Security Configuration ID(s) validation complete");

			debug(ew, log_level, "Begin Client Token validation");
			if (isEmpty(client_token)) {
				errors.add("Please specify a valid Client Token");
			}
			debug(ew, log_level, "Client Token validation complete");

			debug(ew, log_level, "Begin Client Secret validation");
			if (isEmpty(client_secret)) {
				errors.add("Please specify a valid Client Secret");
			} else {
				logMessage(ew, EventWriter.INFO, log_level, format("In %s, Service connect to TA-Akamai_SIEM app ", methodName));
				Service akamaiSplunkService = getServiceForApp(session_key, "TA-Akamai_SIEM");

				debug(ew, log_level, "get password service...");
				PasswordCollection passwordCollection = akamaiSplunkService.getPasswords();
				debug(ew, log_level, "construct stanza...");
				String key = format("%s:client_secret:", definition.getName());
				debug(ew, log_level, key);

				String clearClientSecret = readClearPassword(definition.getName(), "client_secret", passwordCollection);
				String clearClientToken = readClearPassword(definition.getName(), "client_token", passwordCollection);
				String clearAccessToken = readClearPassword(definition.getName(), "access_token", passwordCollection);
				
				if (_MASK_.equalsIgnoreCase(client_secret)) {
					if (isEmpty(clearClientSecret)) {
						errors.add("Please specify a valid Client Secret");
					}
				}
				
				if (_MASK_.equalsIgnoreCase(client_token)) {
					if (isEmpty(clearClientToken)) {
						errors.add("Please specify a valid Client Token");
					}
				}
				
				if (_MASK_.equalsIgnoreCase(access_token)) {
					if (isEmpty(clearAccessToken)) {
						errors.add("Please specify a valid Access Token");
					}
				}
				debug(ew, log_level, "password validation complete");
			}
			debug(ew, log_level, "Client Secret validation complete");

			debug(ew, log_level, "Begin Access Token validation");
			if (isEmpty(access_token)) {
				errors.add("Please specify a valid Access Token");
			}
			debug(ew, log_level, "Access Token validation complete ");

			debug(ew, log_level, "Begin Initial Epoch Time validation");
			validateEpochTime(initial_epoch_time, errors);
			debug(ew, log_level, "Initial Epoch Time validation complete ");

			debug(ew, log_level, "Begin Final Epoch Time validation");
			validateEpochTime(final_epoch_time, errors);
			debug(ew, log_level, "Final Epoch Time validation complete");

			// Initial Epoch time is null or empty but final is not
			if (isEmpty(initial_epoch_time) && !isEmpty(final_epoch_time)) {
				errors.add(format("Initial Epoch Time must be specified"));
			}

			// final > initial
			if (!isEmpty(initial_epoch_time) && !isEmpty(final_epoch_time)) {
				long start = Long.valueOf(initial_epoch_time);
				long end = Long.valueOf(initial_epoch_time);
				if (end < start) {
					errors.add(format("Final Epoch Time must be gearter than Initial Epoch Time"));
				}
			}

			debug(ew, log_level, "Begin Limit validation");
			if (!isEmpty(limit)) {
				if (isDigits(limit)) {
					Integer value = Integer.valueOf(limit);
					if (value <= 0 || value > _AKAMAI_API_MAX_LIMIT_) {
						errors.add(format("%s is not valid Limit", limit));
					}
				} else {
					errors.add(format("%s is not valid Limit", limit));
				}
			}
			debug(ew, log_level, "Limit validation complete");

			debug(ew, log_level, "Begin Proxy Host/Port validation");
			if (!isEmpty(proxy_host)) {
				if (isValidHostName(proxy_host)) {
					errors.add(format("%s is an invalid Proxy Host", proxy_host));
				}

				if (!isEmpty(proxy_port)) {
					if (isDigits(proxy_port)) {
						Integer value = Integer.valueOf(proxy_port);
						if (value <= 0) {
							errors.add(format("%s is not valid Proxy Port", proxy_port));
						}
					} else {
						errors.add(format("%s is not valid Proxy Port", proxy_port));
					}
				}
			}
			debug(ew, log_level, "Proxy Host/port validation complete");

			if (errors.size() > 0) {
				String formattedErrors = join(",", errors);
				ew.synchronizedLog(EventWriter.INFO, format("infoMsg= In %s, found errors : %s", methodName, formattedErrors));
				throw new InputException(formattedErrors);
			}
			debug(ew, log_level, "Error Checking complete");
			
			/*info(ew, log_level, "infoMsg=KVStore connect...");
			Service kvStoreService = getServiceForApp(session_key, "kvstore");

			info(ew, log_level, "infoMsg=KVStore get...");

			String instance_stanza = definition.getName();
			debug(ew, log_level, format("instance_stanza=%s", instance_stanza));

			try {
				debug(ew, log_level, format("getToken=%s", kvStoreService.getToken()));
				RequestMessage requestMessage = new RequestMessage("GET");
				requestMessage.getHeader().put("Content-Type", "application/json");
				ResponseMessage rm = kvStoreService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state", requestMessage);
				debug(ew, log_level, format("infoMsg= In %s, KVStore response = %s", methodName, rm.getStatus()));
				// David Check this
				if (rm.getStatus() != HttpStatus.SC_OK) {
					handleSplunkRestServiceFailure(ew, log_level, requestMessage, "/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state");
				}

				info(ew, log_level, "infoMsg=Parse KVstore data...");
				stanza_state kvStoreStanza = null;

				try (BufferedReader br = new BufferedReader(new InputStreamReader(rm.getContent(), "UTF-8"))) {

					String line = null;
					boolean found = false;
					while ((line = br.readLine()) != null && !found) {
						Gson gson = new Gson();
						stanza_state[] stanzas = gson.fromJson(line, stanza_state[].class);
						for (stanza_state ss : stanzas) {
							String stanza_name = ss.stanza.substring(ss.stanza.indexOf("://") + 3);
							if (instance_stanza.equalsIgnoreCase(stanza_name)) {
								kvStoreStanza = ss;
								found = true;
								break;
							}
						}
					}
				}
				if (kvStoreStanza != null) {
					debug(ew, log_level, "infoMsg=Found kvStoreStanza");
					// Make Some Change
					kvStoreStanza.stanza_change = "1";

					Gson gson = new Gson();
					String json = gson.toJson(kvStoreStanza);
					debug(ew, log_level, format("kvStoreStanza = %s", json));

					RequestMessage postRequestMessage = new RequestMessage("POST");
					postRequestMessage.getHeader().put("Content-Type", "application/json");
					postRequestMessage.setContent(json);
					ResponseMessage postResponse = kvStoreService.send(format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key), postRequestMessage);
					debug(ew, log_level, format("infoMsg= In %s, KVStore response = %s", methodName, postResponse.getStatus()));

					if (postResponse.getStatus() != HttpStatus.SC_OK) {
						handleSplunkRestServiceFailure(ew, log_level, postRequestMessage, format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key));
					}
				} else {
					debug(ew, log_level, "infoMsg=Did NOT find kvStoreStanza");
				}

			} catch (Exception ex) {
				error(ew, log_level, "exception=" + ex.getMessage());
				logException(ew, ex);
				throw ex;
			}
			info(ew, log_level, "infoMsg=Parse KVstore data...Complete!");*/

			info(ew, log_level, "done validation");
		} catch (InputException iex) {
			logException(ew, iex);
			throw (iex);
		} catch (Exception ex) {
			logException(ew, ex);
			throw (ex);
		}
	}

	@Override
	public void streamEvents(InputDefinition inputDefinition, EventWriter ew) throws MalformedDataException, XMLStreamException, IOException {
		String methodName = "streamEvents";
		//synchronized (this) {
			try {

				HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);
				ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, begin streamEvents", methodName));

				Map<String, Map<String, Parameter>> inputs = inputDefinition.getInputs();

				for (String inputName : inputs.keySet()) {
					ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, inputName=%s", methodName, inputName));
					ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, inputName(String)=%s", methodName, inputName.toString()));

					String log_level = getInputValueAsString(inputs.get(inputName), "log_level");
					if (log_level != null) {
						log_level = log_level.toUpperCase();
						if (!logLevel.containsKey(log_level)) {
							ew.synchronizedLog(EventWriter.INFO, "infoMsg=Errors while processing Log Level. Please check instance stanza configuration. Defaulting to INFO");
							log_level = INFO;
						}
					} else {
						log_level = INFO;
					}
					
					debug(ew, log_level, format("log_level=%s", log_level));

					String hostname = getInputValueAsString(inputs.get(inputName), "hostname");
					debug(ew, log_level, format("hostname=%s", hostname));

					String configIds = getInputValueAsString(inputs.get(inputName), "security_configuration_id_s_");
					debug(ew, log_level, format("security_configuration_id_s_=%s", configIds));

					String client_token = getInputValueAsString(inputs.get(inputName), "client_token");
					debug(ew, log_level, format("client_token=%s", client_token));

					String access_token = getInputValueAsString(inputs.get(inputName), "access_token");
					debug(ew, log_level, format("access_token=%s", access_token));

					String initial_epoch_time = getInputValueAsString(inputs.get(inputName), "initial_epoch_time");
					debug(ew, log_level, format("initial_epoch_time=%s", initial_epoch_time));

					String final_epoch_time = getInputValueAsString(inputs.get(inputName), "final_epoch_time");
					debug(ew, log_level, format("final_epoch_time=%s", final_epoch_time));

					String limit = getInputValueAsString(inputs.get(inputName), "limit");
					debug(ew, log_level, format("limit=%s", limit));

					String proxy_host = getInputValueAsString(inputs.get(inputName), "proxy_host");
					String proxy_scheme = null;
					if (!isEmpty(proxy_host)) {
						String lc_proxy_host = proxy_host.toLowerCase();
						if (lc_proxy_host.startsWith("https://")) {
							proxy_scheme = "https";
							proxy_host = lc_proxy_host.replace("https://", "");
						} else if (lc_proxy_host.startsWith("http://") == true) {
							proxy_scheme = "http";
							proxy_host = lc_proxy_host.replace("http://", "");
						}
					}
					debug(ew, log_level, format("proxy_host=%s", proxy_host));
					debug(ew, log_level, format("proxy_scheme=%s", proxy_scheme));

					String proxy_port_string = getInputValueAsString(inputs.get(inputName), "proxy_port");
					Integer proxy_port = null;
					if (!isEmpty(proxy_port_string)) {
						proxy_port = Integer.valueOf(proxy_port_string);
					}
					debug(ew, log_level, format("proxy_port=%s", proxy_port));

					String client_secret = getInputValueAsString(inputs.get(inputName), "client_secret");
					
					String clearClientSecret = client_secret;
					String clearClientToken = client_token;
					String clearAccessToken = access_token;
					
					String sessionKey = inputDefinition.getSessionKey();
					debug(ew, log_level, format("sessionKey=%s", sessionKey));

					if (_MASK_.equalsIgnoreCase(client_secret) == true) {
						info(ew, log_level, format("infoMsg %s Service connect to Akamai_SIEM App...", methodName));
						Service akamaiSplunkService = getServiceForApp(sessionKey, "TA-Akamai_SIEM");
						PasswordCollection passwordCollection = akamaiSplunkService.getPasswords();
						String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");
						
						clearClientSecret = readClearPassword(inputStanza, "client_secret", passwordCollection);
						clearClientToken = readClearPassword(inputStanza, "client_token", passwordCollection);
						if(isEmpty(clearClientToken)) {
							clearClientToken = client_token;
						}
						clearAccessToken = readClearPassword(inputStanza, "access_token", passwordCollection);
						if(isEmpty(clearAccessToken)) {
							clearAccessToken = access_token;
						}
						// Should we validate whether above values are not null...
						// I think these should be validated in validte input method... taking risk here..
						
						/*RequestMessage akamaiAppRequest = new RequestMessage("GET");
						String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");
						String modInput = format("/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json", URLEncoder.encode(inputStanza, "UTF-8"));
						debug(ew, log_level, format("In %s, modInput=%s", methodName, modInput));
						ResponseMessage akamaiAppResponse = akamaiSplunkService.send(modInput, akamaiAppRequest);
						debug(ew, log_level, format("infoMsg= In %s, TA-Akamai_SIEM response = %s", methodName, akamaiAppResponse.getStatus()));

						if (akamaiAppResponse.getStatus() != HttpStatus.SC_OK) {
							handleSplunkRestServiceFailure(ew, log_level, akamaiAppRequest, modInput);
						}

						try (BufferedReader br = new BufferedReader(new InputStreamReader(akamaiAppResponse.getContent(), "UTF-8"))) {

							String line = null;
							boolean found = false;
							while ((line = br.readLine()) != null && !found) {

								Gson gson = new Gson();
								InputStanza is = gson.fromJson(line, InputStanza.class);
								List<com.akamai.siem.Entry> entries = is.getEntry();
								if (entries != null) {
									for (com.akamai.siem.Entry entry : entries) {
										Content content = entry.getContent();
										String clientSecret = content.getClientSecret();
										PasswordCollection passwordCollection = akamaiSplunkService.getPasswords();
										String key = format("%s:client_secret:", inputStanza);
										if (passwordCollection.containsKey(key)) {
											Password p = passwordCollection.get(key);
											client_secret = p.getClearPassword();
											found = true;
											break;
										}
									}
								}
							}
						}*/
					}
					//debug(ew, log_level, format("client_secret=%s", client_secret));
					if(_MASK_.equals(clearClientSecret)) {
						error(ew, log_level, format("clearClientSecret(Wrong Credentials)=%s", clearClientSecret));
						throw new InputException("Client Secret in password store is masked.");
					}
					/*if(_MASK_.equals(clearClientToken)) {
						error(ew, log_level, format("clearClientToken(Wrong Credentials)=%s", clearClientToken));
						throw new InputException("Client Token in password store is masked.");
					}
					if(_MASK_.equals(clearAccessToken)) {
						error(ew, log_level, format("clearAccessToken(Wrong Credentials)=%s", clearAccessToken));
						throw new InputException("Access Token in password store is masked.");
					}*/
					
					info(ew, log_level, format("infoMsg=Processing Data..."));

					String offset = null;
					Integer error_count = 0;
					Service kvStoreService = getServiceForApp(sessionKey, "kvstore");
					stanza_state kvStoreStanza = getValuesFromKVStore(ew, log_level, kvStoreService, inputName);
					if (kvStoreStanza != null) {
						offset = kvStoreStanza.offset;
					}
					String queryString = processQueryString(initial_epoch_time, final_epoch_time, offset, limit);
					String urlToRequest = "https://" + hostname + "/siem/v1/configs/" + configIds + queryString;
					info(ew, log_level, format("urlToRequest=%s", urlToRequest));
					ClientCredential credential = ClientCredential.builder().accessToken(clearAccessToken).clientToken(clearClientToken).clientSecret(clearClientSecret).host(hostname).build();
					HttpClient client = HttpClientBuilder.create().addInterceptorFirst(new ApacheHttpClientEdgeGridInterceptor(credential))
							.setRoutePlanner(new ApacheHttpClientEdgeGridRoutePlanner(credential)).build();
					HttpGet request = new HttpGet(urlToRequest);

					if ((proxy_host != null) && (proxy_host.isEmpty() == false)) {
						HttpHost proxy = new HttpHost(proxy_host, proxy_port, proxy_scheme);
						RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
						request.setConfig(config);
					}
					String newOffset = "";
					try {
						HttpResponse response = client.execute(request);
						int statusCode = response.getStatusLine().getStatusCode();
						info(ew, log_level, format("status code=%s", statusCode));
						if (statusCode == HttpStatus.SC_OK) {
							JsonParser parser = new JsonParser();
							InputStream instream = response.getEntity().getContent();
							String previousLine = null;
							String line = null;
							try (BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(instream))) {
								previousLine = bufferedreader.readLine();

								long count = 0;
								if (previousLine != null) {
									do {
										line = bufferedreader.readLine();
										if (line == null) {
											info(ew, log_level, "infoMsg=parsing last line");
											info(ew, log_level, format("last line=%s", previousLine));
											info(ew, log_level, format("infoMsg=record count is %d", count));
											JsonObject jo = parser.parse(previousLine).getAsJsonObject();
											JsonElement offsetElement = jo.get("offset");

											if (offsetElement == null) {
												error(ew, log_level, "Last row did not have offset, trancated response.");
												throw new IOException("Last row did not have offset, trancated response.");
											}

											newOffset = offsetElement.getAsString();
											
											if (count == 0) {
												Event event = new Event();
												event.setStanza(inputName);
												event.setData(jo.toString());
												ew.writeEvent(event);
											}
											
											debug(ew, log_level, format("new offset=%s", newOffset));

										} else {
											debug(ew, log_level, String.format("line=%s", previousLine));
											try {
												JsonObject jObj = parser.parse(previousLine).getAsJsonObject();
												JsonObject newJsonObj = processData(jObj);
												debug(ew, log_level, String.format("jsonObj=%s", newJsonObj.toString()));
	
												Event event = new Event();
												event.setStanza(inputName);
												event.setData(newJsonObj.toString());
												ew.writeEvent(event);
		
												debug(ew, log_level, format("event:%s", event.toString()));
												debug(ew, log_level, format("data:%s", event.getData()));
												debug(ew, log_level, format("getHost=%s", event.getHost()));
												debug(ew, log_level, format("getIndex=%s", event.getIndex()));
												debug(ew, log_level, format("getSource=%s", event.getSource()));
												debug(ew, log_level, format("getSourceType=%s", event.getSourceType()));
												debug(ew, log_level, format("getStanza=%s", event.getStanza()));
												debug(ew, log_level, format("getTime=%s", event.getTime()));
												debug(ew, log_level, format("end event=%s", event.toString()));
												debug(ew, log_level, format("infoMsg=writeEvent complete"));
											} catch (Exception ex) {
												error(ew, log_level, format("MalformedDataException writing to input %s : Exception Message : %s", inputName, ex.toString()));
												error(ew, log_level, String.format("line=%s", previousLine));
												logException(ew, ex);
											}
											count++;
											previousLine = line;
										}
									} while (line != null);
								}
							} catch (IOException ioe) {
								if (isEmpty(previousLine)) {
									error(ew, log_level, previousLine);
								}
								throw ioe;
							}
						} else {
							// Not 200 response
							String responseData = EntityUtils.toString(response.getEntity());
							error(ew, log_level, format("status code=%s", statusCode));
							logAkamaiSIEMServiceFailure(ew, log_level, request, responseData, urlToRequest);

							Event event = new Event();
							event.setStanza(inputName);
							event.setData(responseData);
							ew.writeEvent(event);

							error_count++;
						}
					} catch (IOException ioe) {
						logException(ew, ioe);
						throw ioe;
					} finally {
						kvStoreService = getServiceForApp(sessionKey, "kvstore");
						try {
							updateValuesInKVStore(ew, log_level, kvStoreService, inputName, newOffset, error_count);
						} catch (InputException e) {
							logException(ew, e);
						}
					}
					if (!(_MASK_.equals(client_secret) && _MASK_.equals(access_token) && _MASK_.equals(client_token))) {
						MyRunnable myRunnable = new MyRunnable(sessionKey, log_level, inputName, _MASK_, ew);
						Thread t = new Thread(myRunnable);
						t.start();
					}
				}
			} catch (Exception ex) {
				logException(ew, ex);
			}
		//}
		ew.synchronizedLog(EventWriter.INFO, format("infoMsg = %s, end streamEvents", methodName));
	}
	
	private String readClearPassword(String inputStanza, String username, final PasswordCollection passwordCollection) {
		String keyWithReamlm = format("%s:%s:", inputStanza, username);

		if (passwordCollection.containsKey(keyWithReamlm)) {
			Password p = passwordCollection.get(keyWithReamlm);
			return p.getClearPassword();
		}
		return null;
	}
	
	private void createSchemeArgument(final Scheme scheme, final String argName, final String argDesc, final boolean requiredOnCreate, final boolean requiredOnedit, final DataType dataType) {
		Argument argument = new Argument(argName);
		argument.setName(argName);
		argument.setDescription(argDesc == null ? "" : argDesc);
		argument.setRequiredOnCreate(requiredOnCreate);
		argument.setRequiredOnEdit(requiredOnedit);
		argument.setDataType(dataType);
		scheme.addArgument(argument);
	}

	public static String decode(String value) throws Exception {
		return new String(Base64.decodeBase64(value), StandardCharsets.UTF_8);
	}

	private static JsonObject parseData(JsonObject d, boolean isCustom) throws Exception {

		for (Entry<String, JsonElement> entry : d.entrySet()) {
			if (entry.getValue().isJsonObject() == true) {
				boolean isCustomEntry = false;
				if ("custom".equalsIgnoreCase(entry.getKey()) == true) {
					isCustomEntry = true;
				}
				parseData(entry.getValue().getAsJsonObject(), isCustomEntry);
			} else {
				String k = entry.getKey();
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
						ruleData.put(pair.getValue(), parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsJsonArray().get(i).getAsString());
					} else {
						ruleData.put(pair.getValue(), "");
					}
				} else {
					ruleData.put(pair.getValue(), parsedData.get("attackData").getAsJsonObject().get(pair.getKey()).getAsString());
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

	private static String processQueryString(String initialEpochTime, String finalEpochTime, String offset, String limit) {
		String retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
		if (!isEmpty(finalEpochTime)) {
			if (!isEmpty(initialEpochTime)) {
				retVal = format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
				retVal = retVal + format(_AKAMAI_API_PARAM_TIME_TO_BASED_, finalEpochTime);
			} else {
				retVal = format(_AKAMAI_API_PARAM_TIME_TO_BASED_NO_FROM_, finalEpochTime);
			}

			if (!isEmpty(limit)) {
				retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
			} else {
				retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
			}

		} else if (!isEmpty(initialEpochTime)) {
			if (isEmpty(offset)) {
				retVal = format(_AKAMAI_API_PARAM_TIME_BASED_, initialEpochTime);
			} else {
				retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
			}

			if (!isEmpty(limit)) {
				retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
			} else {
				retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
			}

		} else {
			if (isEmpty(offset)) {
				retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, "NULL");
			} else {
				retVal = format(_AKAMAI_API_PARAM_OFFSET_BASED_, offset);
			}

			if (!isEmpty(limit)) {
				retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, limit);
			} else {
				retVal = retVal + format(_AKAMAI_API_PARAM_LIMIT_BASED, _AKAMAI_API_DEFAULT_LIMIT_);
			}
		}

		return (retVal);

	}

	private String getInputValueAsString(final ValidationDefinition definition, final String paramName) {
		Parameter parameter = definition.getParameters().get(paramName);
		if (parameter != null) {
			return ((SingleValueParameter) parameter).getValue();
		}
		return null;
	}

	private boolean isLogEnabled(final String log_level, final String log_threshold) {
		if (logLevel.containsKey(log_threshold)) {
			int ilogLevel = logLevel.get(log_level);
			int ilogThreshold = logLevel.get(log_threshold);
			if (ilogLevel >= ilogThreshold) {
				return true;
			}
		}
		return false;
	}

	private void logException(final EventWriter ew, final Exception ex) {
		StringWriter sw = new StringWriter();
		try (PrintWriter pw = new PrintWriter(sw)) {
			ex.printStackTrace(pw);
			pw.flush();
			ew.synchronizedLog(EventWriter.ERROR, format("Message : %s, Exception : %s", ex.getMessage(), sw.toString()));
		}
	}

	private void debug(final EventWriter ew, final String log_threshold, final String message) {
		if (isLogEnabled(DEBUG, log_threshold)) {
			info(ew, log_threshold, message);
		}
	}

	private void error(final EventWriter ew, final String log_threshold, final String message) {
		logMessage(ew, ERROR, log_threshold, message);
	}
	
	private void warn(final EventWriter ew, final String log_threshold, final String message) {
		logMessage(ew, WARN, log_threshold, message);
	}
	
	private void info(final EventWriter ew, final String log_threshold, final String message) {
		logMessage(ew, INFO, log_threshold, message);
	}

	private void logMessage(final EventWriter ew, final String log_level, final String log_threshold, final String message) {
		if (isLogEnabled(log_level, log_threshold)) {
			ew.synchronizedLog(log_level, message);
		}
	}

	private boolean isValidLogLevel(final String inputLogLevel) {
		if (inputLogLevel != null) {
			return logLevel.keySet().contains(inputLogLevel);
		} else {
			return false;
		}
	}

	private boolean isValidHostName(final String hostname) {
		String[] schemes = { "http", "https" };
		UrlValidator urlValidator = new UrlValidator(schemes);
		if (!hostname.isEmpty()) {
			return urlValidator.isValid(hostname);
		} else {
			return false;
		}
	}

	private void validateSecurityConfigIds(final String configIds, final List<String> errors) {
		if ((configIds != null) && (configIds.isEmpty() == false)) {
			String[] configsArray = configIds.split(_AKAMAI_API_SECURITY_CONFIG_DELIMITER_);
			for (String id : configsArray) {
				if (!isDigits(id) || (isDigits(id) && Integer.parseInt(id) <= 0)) {
					errors.add(format("%s is not valid Security Configuration ID(s)", id));
				}
			}
		}
	}

	private void handleSplunkRestServiceFailure(final EventWriter ew, String log_level, final RequestMessage requestMessage, final String endPoint) throws InputException {
		StringBuilder message = new StringBuilder();
		message.append("Following end point failed\n").append("Service end point : ").append(endPoint).append("Method : ").append(requestMessage.getMethod()).append("Content : ")
				.append(requestMessage.getContent());
		error(ew, log_level, message.toString());
		throw new InputException(message.toString());
	}

	private void logAkamaiSIEMServiceFailure(final EventWriter ew, String log_level, final HttpRequest requestMessage, final String response, final String endPoint) {
		StringBuilder message = new StringBuilder();
		message.append("Following end point failed\n").append("Service end point : ").append(endPoint).append("Method : ").append("GET").append("Content : ").append(response);
		error(ew, log_level, message.toString());
	}

	private stanza_state getValuesFromKVStore(final EventWriter ew, String log_level, final Service kvStoreService, final String inputName) throws InputException, IOException {
		info(ew, log_level, format("infoMsg=KV Service get...", ew));

		debug(ew, log_level, format("getToken=%s", kvStoreService.getToken()));
		RequestMessage kvRequestMessage = new RequestMessage("GET");
		kvRequestMessage.getHeader().put("Content-Type", "application/json");
		ResponseMessage kvResponseMessage = kvStoreService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state", kvRequestMessage);

		debug(ew, log_level, format("infoMsg= KVStore response = %s", kvResponseMessage.getStatus()));
		// David Check this
		if (kvResponseMessage.getStatus() != HttpStatus.SC_OK) {
			handleSplunkRestServiceFailure(ew, log_level, kvRequestMessage, "/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state");
		}

		info(ew, log_level, "infoMsg=Parse KVstore data...");
		stanza_state kvStoreStanza = null;

		try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(kvResponseMessage.getContent(), "UTF-8"))) {
			String line = null;
			boolean found = false;
			while ((line = bufferedReader.readLine()) != null && !found) {
				Gson gson = new Gson();
				stanza_state[] stanzas = gson.fromJson(line, stanza_state[].class);
				for (stanza_state ss : stanzas) {
					if (inputName.equalsIgnoreCase(ss.stanza)) {
						kvStoreStanza = ss;
						found = true;
						break;
					}
				}
			}
		}
		info(ew, log_level, "infoMsg=Parse KVstore data...Complete");
		return kvStoreStanza;
	}

	private stanza_state updateValuesInKVStore(final EventWriter ew, String log_level, final Service kvStoreService, final String inputName, final String newOffset, final Integer error_count)
			throws InputException, IOException {
		stanza_state kvStoreStanza = getValuesFromKVStore(ew, log_level, kvStoreService, inputName);
		Gson gson = new Gson();
		if (kvStoreStanza != null) {

			if (kvStoreStanza.error_count >= _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_) {
				error(ew, log_level, format("infoMsg=%d  consecutive errors.  Clearing offset and error count", _AKAMAI_API_MAX_CONSECUTIVE_ERRORS_));
				kvStoreStanza.offset = "";
				kvStoreStanza.error_count = 0;
			} else {
				kvStoreStanza.offset = newOffset;
				kvStoreStanza.error_count = kvStoreStanza.error_count + error_count;
			}
			kvStoreStanza.stanza_change = "0";
			kvStoreStanza.stanza = inputName;

			debug(ew, log_level, format("kvStoreStanza=%s", gson.toJson(kvStoreStanza)));

			RequestMessage requestMessage = new RequestMessage("POST");
			requestMessage.getHeader().put("Content-Type", "application/json");
			requestMessage.setContent(gson.toJson(kvStoreStanza));

			ResponseMessage kvStoreServiceResponse = kvStoreService.send(String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key),
					requestMessage);
			debug(ew, log_level, format("infoMsg= response = %s", kvStoreServiceResponse.getStatus()));
			// David Check this
			if (kvStoreServiceResponse.getStatus() != HttpStatus.SC_OK) {
				handleSplunkRestServiceFailure(ew, log_level, requestMessage, String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/%s", kvStoreStanza._key));
			}
		} else {

			kvStoreStanza = new stanza_state();
			kvStoreStanza.offset = newOffset;
			kvStoreStanza.error_count = error_count;
			kvStoreStanza.stanza_change = "0";
			kvStoreStanza.stanza = inputName;

			debug(ew, log_level, String.format("kvStoreStanza=%s", gson.toJson(kvStoreStanza)));

			RequestMessage requestMessage = new RequestMessage("POST");
			requestMessage.getHeader().put("Content-Type", "application/json");
			requestMessage.setContent(gson.toJson(kvStoreStanza));

			ResponseMessage kvStoreServiceResponse = kvStoreService.send("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/", requestMessage);
			debug(ew, log_level, format("infoMsg= response = %s", kvStoreServiceResponse.getStatus()));
			// David Check this
			if (kvStoreServiceResponse.getStatus() != HttpStatus.SC_OK) {
				handleSplunkRestServiceFailure(ew, log_level, requestMessage, String.format("/servicesNS/nobody/TA-Akamai_SIEM/storage/collections/data/akamai_state/"));
			}
		}
		return kvStoreStanza;
	}

	public void validateEpochTime(final String epochTime, final List<String> errors) {
		if (!isEmpty(epochTime)) {
			if (isDigits(epochTime)) {
				Integer value = Integer.valueOf(epochTime);
				if (value <= 0) {
					errors.add(format("%s is not valid Epoch Time", epochTime));
				}
			} else {
				errors.add(format("%s is not valid Epoch Time", epochTime));
			}
		}
	}

	private Service getServiceForApp(final String session_key, final String app) {
		ServiceArgs akamaiServiceArgs = new ServiceArgs();
		akamaiServiceArgs.setHost("localhost");
		akamaiServiceArgs.setPort(8089);
		akamaiServiceArgs.setScheme("https");
		akamaiServiceArgs.setToken("Splunk " + session_key);
		akamaiServiceArgs.setApp(app);
		Service akamaiSplunkService = Service.connect(akamaiServiceArgs);
		return akamaiSplunkService;
	}

	private String getInputValueAsString(final Map<String, Parameter> inputMap, final String key) {
		Parameter parameter = inputMap.get(key);
		if (parameter != null) {
			return ((SingleValueParameter) parameter).getValue();
		}
		return null;
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
			String methodName = "MyRunnable.run";
			try {
				HttpService.setSslSecurityProtocol(SSLSecurityProtocol.TLSv1_2);

				info(ew, log_level, format("infoMsg=%s, Begin client secret crypto", methodName));

				info(ew, log_level, format("infoMsg=%s, TA-Akamai_SIEM Service connect", methodName));
				Service akamaiSplunkService = getServiceForApp(sessionKey, "TA-Akamai_SIEM");

				RequestMessage akamaiRequestMessage = new RequestMessage("GET");
				akamaiRequestMessage.getHeader().put("Content-Type", "application/json");
				// inputName=TA-Akamai_SIEM://csxcz
				String inputStanza = inputName.replace("TA-Akamai_SIEM://", "");
				String modInputUrl = format("/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json", URLEncoder.encode(inputStanza, "UTF-8"));

				info(ew, log_level, format("infoMsg=%s, modInputUrl=", methodName, modInputUrl));
				ResponseMessage akamairm = akamaiSplunkService.send(modInputUrl, akamaiRequestMessage);
				info(ew, log_level, format("infoMsg=%s, status=%s", methodName, akamairm.getStatus()));

				try (BufferedReader akamaiReader = new BufferedReader(new InputStreamReader(akamairm.getContent(), "UTF-8"))) { 
					String line = null;
					while((line = akamaiReader.readLine()) != null) {
						Gson gson = new Gson();
						InputStanza is = gson.fromJson(line, InputStanza.class);
						if(is != null) {
							List<com.akamai.siem.Entry> entries = is.getEntry();
							if (entries != null) {
								for (com.akamai.siem.Entry entry : entries) {
									Content content = entry.getContent();
									String client_secret = content.getClientSecret();
									String access_token = content.getAccessToken();
									String client_token = content.getClientToken();
									if (!(_MASK_.equals(client_secret) && _MASK_.equals(access_token) && _MASK_.equals(client_token))) {
										warn(ew, log_level, " [client secret | access token | clientToken]  is not masked.");
										PasswordCollection pColl = akamaiSplunkService.getPasswords();
										
										String client_secret_username = "client_secret";
										String access_token_username = "access_token";
										String client_token_username = "client_token";
										
										Map<String, String> userNamePasswordMap = new HashMap<String, String>();
										if(!_MASK_.equals(client_secret)) {
											userNamePasswordMap.put(client_secret_username, client_secret);
										}
										if(!_MASK_.equals(access_token)) {
											userNamePasswordMap.put(access_token_username, access_token);
										}
										if(!_MASK_.equals(client_token)) {
											userNamePasswordMap.put(client_token_username, client_token);
										}
										
										for(String key : userNamePasswordMap.keySet()) {
											String keyWithReamlm = format("%s:%s:", inputStanza, key);
											if (pColl.containsKey(keyWithReamlm)) {
												pColl.remove(key);
											}
											pColl.create(key, userNamePasswordMap.get(key), inputStanza);
										}
										
										content.setClientSecret(_MASK_);
										content.setAccessToken(_MASK_);
										content.setClientToken(_MASK_);
										
										RequestMessage postMessage = new RequestMessage("POST");
										postMessage.getHeader().put("Content-Type", "application/x-www-form-urlencoded");
										
										StringBuilder builder = new StringBuilder()
													.append("access_token=")
													.append(URLEncoder.encode(content.getAccessToken(), "UTF-8"))
													.append("&client_secret=")
													.append(URLEncoder.encode(content.getClientSecret(), "UTF-8"))
													.append("&client_token=")
													.append(URLEncoder.encode(content.getClientToken(), "UTF-8"))
													.append("&hostname=")
													.append(URLEncoder.encode(content.getHostname(), "UTF-8"))
													.append("&security_configuration_id_s_=")
													.append(URLEncoder.encode(content.getSecurityConfigurationIdS(), "UTF-8"));
										
										if(content.getFinalEpochTime() != null) {
											builder
												.append("&final_epoch_time=")
												.append(URLEncoder.encode(content.getFinalEpochTime().toString(), "UTF-8"));
										}
										if (content.getInitialEpochTime() != null) {
											builder
											.append("&initial_epoch_time=")
											.append(URLEncoder.encode(content.getInitialEpochTime().toString(), "UTF-8"));
										}
										if (!isEmpty(content.getHost())) {
											builder
												.append("&host=")
												.append(URLEncoder.encode(content.getHost(), "UTF-8"));
										}
										if (!isEmpty(content.getIndex())) {
											builder
												.append("&index=")
												.append(URLEncoder.encode(content.getIndex(), "UTF-8"));
										}
										
										if (!isEmpty(content.getInterval())) {
											builder
											.append("&interval=")
											.append(URLEncoder.encode(content.getInterval(), "UTF-8"));
										}
										
										if (content.getLimit() != null) {
											builder
											.append("&limit=")
											.append(URLEncoder.encode(content.getLimit().toString(), "UTF-8"));
										}
										

										if (!isEmpty(content.getLogLevel())) {
											builder
											.append("&log_level=")
											.append(URLEncoder.encode(content.getLogLevel(), "UTF-8"));
										}
										
										if (!isEmpty(content.getSourcetype())) {
											builder
											.append("&sourcetype=")
											.append(URLEncoder.encode(content.getSourcetype(), "UTF-8"));
										}
										String formurlencoded = builder.toString();
										debug(ew, log_level, format("infoMsg=%s,formurlencoded=%s", methodName, formurlencoded));
										postMessage.setContent(formurlencoded);
										ResponseMessage rm = akamaiSplunkService
												.send(format("/servicesNS/nobody/TA-Akamai_SIEM/data/inputs/TA-Akamai_SIEM/%s?output_mode=json", URLEncoder.encode(inputStanza, "UTF-8")), postMessage);
										debug(ew, log_level, "getStatus=" + String.valueOf(rm.getStatus()));

									}
								}
							}
						}
					}
				}
			}
			catch (Exception ex) {
				error(ew, log_level, "Exception : " + ex.toString());
			}
			info(ew, log_level, "infoMsg=\"End client secret crypto\"");
		}
	}
}
