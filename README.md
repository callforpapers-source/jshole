# jshole
A simple JavaScript components vulnrability scanner, based on RetireJS.
## Why use JShole instead of RetireJS?
By default, RetireJS only searches one page, but JShole tries to crawl all pages.

## Get Started
### Requirements
 * requests
### Install
  * `git clone https://github.com/callforpapers-source/jshole.git`
  * `cd jshole`
  * `pip3 install -r requirements`
  * `python3 jshole.py`
```
usage: jshole [-h] -u URL [-d] [-l LIMIT] [-t THREAT]
optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url string
  -d, --debug           Web Scrap debugger(default=false)
  -l LIMIT, --limit LIMIT
                        Search Depth limit(default=1)
  -t THREAT, --threat THREAT
                        The number of links that open per round
```
