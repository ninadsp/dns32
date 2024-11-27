const char *WIFI_STATUS_FAILED = "failed";
const char *WIFI_STATUS_IN_PROGRESS = "is still in progress";
const char *WIFI_STATUS_COMPLETE = "complete";

const char *HTML_FRAGMENT_HELLO_WORLD = "<!DOCTYPE html>\n"
"<html lang='en'>\n"
"    <head>\n"
"        <title>Hello World</title>\n"
"        <meta name='viewport' content='width=device-width, initial-scale=1.0'/>\n"
"		<meta charset='utf-8' />\n"
"    </head>\n"
"    <body>\n"
"        <h1>Hello World</h1>\n"
"    </body>\n"
"</html>\n";

const char *HTML_FRAGMENT_COMMON_HEADER = "<!DOCTYPE html>\n"
"<html lang='en'>\n"
"    <head>\n"
"        <title>DNS32</title>\n"
"        <meta name='viewport' content='width=device-width, initial-scale=1.0'/>\n"
"		<meta charset='utf-8' />\n"
"    </head>\n"
"    <body>\n";

const char *HTML_FRAGMENT_WIFI_STATUS = "    <h1>dns32</h1>\n"
"    <h4>Current IP Address is: %s</h4>\n"
"    <h4>Current MAC Address is: %02x:%02x:%02x:%02x:%02x:%02x</h4>";

const char *HTML_FRAGMENT_WIFI_SELECTOR_SCAN_STATUS_FRAGMENT = "    <span>WiFi Scan %s</span>\n";

const char *HTML_FRAGMENT_WIFI_SELECTOR_TABLE_HEADER = "    <h3>Found %d WiFi Networks in range</h3>\n"
"\n"
"    <div>Please select your home network:</div>\n"
"    <form method='post' action='/wifi-configure'>\n"
"    <table>\n"
"      <thead>\n"
"        <tr>\n"
"          <td>Name</td>\n"
"          <td>Strength</td>\n"
"          <td>Select</td>\n"
"        </tr>\n"
"      </thead>\n"
"      <tbody>\n";

const char *HTML_FRAGMENT_WIFI_SELECTOR_TABLE_BODY_ROW = "        <tr>\n"
"          <td>%s</td>\n"
"          <td>%d</td>\n"
"          <td><button value='%d' type='button' onclick='setInput(%d)'>Select</button></td>\n"
"        </tr>\n";

const char *HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER = "      </tbody>\n"
"    </table>\n"
"		<input type='hidden' id='wifiindex' name='wifiindex' />\n"
"		<input type='password' id='wifipassword' name='wifipassword' placeholder='Enter Wifi password here' />\n"
"		<button type='submit'>Submit</button>\n"
"    </form>\n"
"		<script>\n"
"		function setInput(wifiIndex) {\n"
"			let inputField = document.querySelector('#wifiindex');\n"
"			inputField.value = wifiIndex;\n"
"		}\n"
"		</script>\n";

const char *HTML_FRAGMENT_STATUS_PAGE = "		<h2>Currently connected to %s</h2>\n";

const char *HTML_FRAGMENT_COMMON_END = "  </body>\n"
"</html>\n";
