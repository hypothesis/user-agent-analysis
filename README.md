# User Agent analysis scripts

This repository contains scripts for parsing and analysing user agent information
from nginx access logs.

## Tools

### `parse_access_log.py`

This script parses an nginx access log and extracts browser version information
in CSV format. To use it:

1. Download an nginx access log from a production server or a logging service
   such as Papertrail.

   Services such as Papertrail will prepend additional information in front of each
   log line. The `parse_access_log.py` script will accept such lines but ignore the
   content in front of the IP address at the start of the nginx log line.

   Using the [papertrail-cli](https://github.com/papertrail/papertrail-cli) you can download
   access log entries for machines in a particular group using:

   ```
   papertrail -g <Log group> --min-time '1 day ago' access.log
   ```

2. Pipe the log file through `parse_access_log.py`:

   ```sh
   cat access.log | python parse_access_log.py
   ```

   This will produce CSV output with the following columns:

   - `browser_name` - The name of the browser
   - `browser_version` - The major version of the browser
   - `equivalent_name` - The main browser associated with the rendering engine that this browser uses.
   - `equivalent_version` - The version of the `equivalent_name` browser
   - `ua_string` - The complete User Agent string

   For major browsers with their own engines like Chrome, `browser_name` and `equivalent_name` will be the same.
   For other browsers this will be the main browser associated with the engine. For example,
   modern versions of Edge and Opera will show "Chrome" in this column.
   The `equivalent_*` fields are useful to determine what features the browser is
   likely to support based on information in [MDN](https://developer.mozilla.org/en-US/) or
   [caniuse.com](https://caniuse.com).

3. Load the CSV output into your favorite data processing / visualization tools for
   further analysis
