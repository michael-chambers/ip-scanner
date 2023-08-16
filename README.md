# ip-scanner

This tool scans IP addresses to find servers running specified versions of IIS or Nginx. It also looks for directory listings at the root level of a web site (also known as autoindexing). Information is gathered from a HTTP GET request.

Because many sites do not respond to their IP address, the ability to specify a URL is also included. This is not performed automatically (via reverse DNS lookup), as that too frequently does not resolve to a routable website, but rather a server name used by the site's provider.

The tool is a single, Python-based, Windows executable. Results are outputted to the console. Options are specified via command line arguments, as explained below. They can also be found by running `scanner.exe --help`

> `--help, -h` show the help message
>
> `--debug, -d` turn on debug mode for more verbose logging
>
> `--iis` the version of IIS to scan for, if no value is specified, a default value of `7.0` is used
>
> `--nginx` the version of Nginx to scan for, if no value is specified, a default value of `1.2` is used
>
> `--ip-address, -i` a single IP address to scan, this can be used multiple times to specify non-consecutive IPs, for consecutive IP ranges, it is easier to use `--start-ip` and `--end-ip`
>
> `--start-ip` the beginning IP address in a consecutive range to be scanned, must be used alongside `--end-ip`
>
> `--end-ip` the final IP address in a consecutive range to be scanned, must be used alongside `--start-ip`
>
> `--url` a fully-qualified URL to scan, must include the protocol (e.g. `http://` or `https://`) and no subfolder locations, can be used multiple times`

