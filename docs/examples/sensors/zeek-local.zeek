# Load this from the Zeek site/local configuration.
# Produces JSON-formatted conn.log, dns.log, http.log and ssl.log records.
@load policy/tuning/json-logs
redef LogAscii::use_json = T;
