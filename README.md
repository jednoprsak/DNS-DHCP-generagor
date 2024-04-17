DNS_DHCP_generator is the script generating configuration files for DNS and DHCP services based on provided data. The script reads information 
about VLANs and hosts from YAML configuration files and then generates configuration files for DNS and DHCP services based on this data.

Here are some key points of the script:

    Configuration Loading: The script reads configuration files in YAML format containing information about VLANs and hosts.

    Configuration Generation for DNS and DHCP: The script iterates through the loaded information about VLANs and hosts and generates corresponding configuration files for DNS and DHCP services.

    Validation of IP and MAC Addresses: The script includes methods to validate the correctness of IP addresses and MAC addresses.

    Logging: The script logs warnings to a log file if it encounters invalid IP addresses or MAC addresses.

    File Manipulation: The script creates and writes configuration files for DNS and DHCP.

    Command-Line Arguments: The script allows specifying the -v switch for logging output to standard output.
