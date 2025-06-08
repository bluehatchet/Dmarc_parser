Things to Know:
This script relies on external python packages: pandas, matplotlib, and xml.etree.ElementTree. Ensure these dependencies are installed in your Python environment.

Paths in the example usage use Windows format with %username%. Adjust these to match your actual system paths or modify the script to accept command-line arguments for more flexibility.

By default the script reads all DMARC reports from the specified directory, parses them, writes a CSV, displays a bar chart of top IP addresses, and then deletes the extracted XML files.


GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007
