# User Agent analysis scripts

This repository contains scripts for parsing and analysing user agent information
from nginx access logs.

## `parse_access_log.py`

This script parses an nginx access log and extracts browser version information
in CSV format.

1. Download an nginx access log from a production server or a logging service
   such as Papertrail.

2. Pipe the access log through `parse_access_log.py`:

   ```sh
   cat access.log | python parse_access_log.py
   ```

   This will produce CSV output with the following columns:

   `browser_name` - The name of the browser
   `browser_version` - The major version of the browser
   `equivalent_name` - The closest equivalent major browser (eg. Chrome, Safari, Firefox)
   `equivalent_version` - The equivalent major browser version
   `ua_string` - The complete User Agent string

   For major browsers with their own engines like Chrome, `browser_name` and `equivalent_name` will be the same.
   For other browsers this will be the major browser with the same engine. For example,
   modern versions of Edge and Opera will show "Chrome" in this column.

3. Load the CSV output into your favorite data processing / visualization tools for
   further analysis
