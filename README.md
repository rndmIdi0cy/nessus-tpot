# nessus-tpot
Nessus-TPOT is a script to optimize a scan policy by removing unused plugins.

This python script will compare the selected policy to vulnerabilities found based on the number of days selected. It will then disable the plugins within the policy that have not been found in the specified number of days.

```
usage: tpot.py [-h] [-p PID] [-l] [-o OUTPUT] [-w] [-d DAYS]

optional arguments:
    -h, --help  show this help message and exit
    -p PID      Scan policy id
    -l          List available policies
    -o OUTPUT   Disabled plugin csv file location (Default: /Users/[username]/disabled_plugins_[timestamp].csv)
    -w          Run but do not commit changes
    -d DAYS     Number of days to search plugins against (Default: 30)

Examples:
    Get available policies (API account must have configure permissions to policies)
    ./tpot.py -l

    Disable plugins checking back 7 days
    ./tpot.py -p 13 -d 7

    Check for vulnerabilities that would be disabled going back 7; but do not disable
    ./tpot.py -p 13 -d 7 -w
```
