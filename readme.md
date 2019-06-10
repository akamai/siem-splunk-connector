# Set up Splunk connector 
<h2 id="4">Version 1.4.7</h2><a name="4"></a>

>**Update:** Version 1.4.7 of the sample Splunk Connector was released in June 2019. Changes include:
>*   Bug fix "Incorrect parsing of header fields" 

<h2 id="4">Version 1.4.5</h2><a name="4"></a>

>**Update:** Version 1.4.5 of the sample Splunk Connector was released in November 2018. Changes include:
>*   Bug fix "java.io.EOFException: Unexpected end of ZLIB input stream" 

<h2 id="4">Version 1.4.2</h2><a name="4"></a>

>**Update:** Version 1.4.2 of the sample Splunk Connector was released in October 2018. Changes include:
>*   Bug fix related to proxy support

<h2 id="4">Version 1.4.1</h2><a name="4"></a>

>**Update:** Version 1.4.1 of the sample Splunk Connector was released in September 2018. Changes include:

>*   Proxy support

>Version 1.3.0 of the sample Splunk Connector was a limited-availability realease in early August 2018, which includes:

>*   You can now set log level. For example, if you have a problem, switch to DEBUG mode.
>*   You no longer need to enter your Splunk username and password.
>*   Client secret is encrypted and is hidden in Splunk interface.
>*   Fixed input validation issue.
>*   Fixed an issue with SLF4J logging exceptions.
>*   Tested on Splunk's new released version 7.1.0.
>
>Veresion 1.3.0 was a limited release and is no longer available, but 1.4.2 includes all its features. Read on for overview and installation instructions.


The sample Splunk connector is a Splunk add-on that captures security events from the Akamai Security Events Collector, which exposes a RESTful API that lets the connector pull events in JSON format. The Splunk add-on converts security events data from JSON into CIM format. The Splunk instance then analyzes high volumes of data by indexing it.

![Splunk connector diagram](https://developer.akamai.com/tools/siem-integration/docs/Content/Resources/Images/splunk_diag.png)

> _**Full SIEM Setup:** There's more to SIEM setup than just installing this connector. You need to turn SIEM integration on, set up administrators, and provision the SIEM API.  [Learn more](https://developer.akamai.com/tools/siem-integration/index.html)_ 

### System Requirements

Akamai’s Splunk Connector requires Sun JRE 1.8+ to be installed. Download the  latest from the Sun Java site (Java Platform, Standard Edition) or install from a software distribution package on Linux.

You must have Java installed on the host running Splunk Enterprise [https://java.com/en/download/](https://java.com/en/download/)

Also, check to make sure that splunk forwarder is NOT installed on your Splunk Enterprise host machine.

#### Proxy server

To access the SIEM API from behind a proxy server, ensure that your proxy:

*   whitelists the domains `*.cloudsecurity.akamaiapis.net`
*   does not interfere with HTTP request headers for those domains. If, due to a strict enterprise security policy, your proxy does change these headers, make sure that at a minimum you allow and don't change the `Host` and `Authorization` headers.


### Hardware Requirements

This application is has been tested with the following operating systems:

* CentOS 7
* Windows Server 2012 R2
* Mac OS X El Capitan Version 10.11.6

Some additional hardware requirements:

* 4 CPU cores
* 16 GB RAM
* 2GB Free Disk Space

### Install

To send Akamai security events to Splunk® instance, download and install the Akamai SIEM add-on:

1.  Go to [https://developer.akamai.com/tools/siem-integration](https://developer.akamai.com/tools/siem-integration) and download `TA-Akamai_SIEM_1_x_0.spl` ( `x` being the latest version available).
2.  In Splunk, on the upper left of the screen, click the **Splunk >** icon.
3.  Next to **Apps** at the top of the navigation bar, click the gear icon.

    ![Splunk gear icon](https://developer.akamai.com/tools/siem-integration/docs/Content/Resources/Images/splunk_211x130.png)

4.  Click **Install app from file**.
5.  Click **Choose File**.
6.  Browse to and select `TA-Akamai_SIEM_1_x_0.spl` then click **Open**.
7.  Click **Upload**.
8. Restart Splunk.
8.  You see AKAMAI SIEM API (Security Information and Event Management).

    ![Akamai SIEM app in menu](https://developer.akamai.com/tools/siem-integration/docs/Content/Resources/Images/add-on_in_splunk_165x212.png)

10.  From the menu, choose **Settings > Data Inputs**.
11.  Click the **Akamai Security Incident Event Manager API**.
12.  Click **New** and complete the following fields:
    *   **Name**. Enter any name you want for the input.
    *   **Hostname**. Enter the host URL you copied when you provisioned the SIEM API.
    *   **Security Configuration(s)**. Enter the **Configuration ID** you copied when you turned on SIEM in the Luna portal (allowed SIEM data collection).
    *   **Client Token**, **Client Secret**, and **Access Token**. Enter the values you copied when you provisioned the SIEM OPEN API.
    *   **proxy_host**. Enter the proxy host name of your proxy server.
    *   **proxy_port**. Enter the port number you use to connect to your proxy server.
    *   **Initial Epoch Time** and **Final Epoch time**. Leave these fields blank. If you ever encounter an issue with your data field, you can use them to [retrieve security event data for a set time period](Retrievepastsecurityevents-Splunkconnector.htm).
    *   **Limit**. If you want to limit the number of security events to pull, you can enter a number here to limit the results for each REST call. If not specified, the API retrieves a maximum of 150000 records per call.
    *   **log level** is automatically set to INFO. You can change it to WARN, ERROR, FATAL, or DEBUG to get more data for certain situations. For example, if you have a problem with the connector, type DEBUG to get more detailed messages and troubleshoot.
    *   **Interval**. Number of seconds between fetch requests. Enter 60, unless you have entered values in both **Initial Epoch Time** and **Final Epoch Time** to retrieve security events from a set time period. In that case, enter 0\.

    > _**Note:** If it takes more than 60 seconds to fetch the data, then increase the interval value to the amount of seconds it takes to fetch the data._ 
    
13.  Return to Splunk home and click **Akamai SIEM**.
    If you see data, setup was successful.
    
    
   ![Security event data in Splunk](https://developer.akamai.com/tools/siem-integration/docs/Content/Resources/Images/splunkreports.png)

14.  If you see no data, go to the menu and choose **Debug > Akamai Logging dashboard**.
    You see Akamai SIEM Errors on the right.

   ![logging](https://developer.akamai.com/tools/siem-integration/docs/Content/Resources/Images/Splunklogs.png)

   In the event of a fatal error prohibiting collection of data, you’d need to review these logs and take corrective actions. This log is also available in `/{splunk_home}/var/log/splunk`. [Read how to retrieve past security events](Retrievepastsecurityevents-Splunkconnector.htm).

15.  To search for SIEM data within Splunk search app (From Splunk home, click **Search and Reporting app**), enter the query `sourcetype=”akamaisiem”`

**Tip:** _Akamai strongly recommends installing the Splunk add-on app_ _**Lookup File Editor**_ _from within Splunk Apps. You need this add-on to [switch retrieval mode](Retrievepastsecurityevents-Splunkconnector.htm)._

### Editing data inputs

Once a data input is enabled, you can't just edit it and run it again. Disable it, clone the data input, make changes to the clone, then run that new input.



