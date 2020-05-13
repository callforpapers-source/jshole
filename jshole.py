# !/usr/bin/env python3
import sys
import argparse
import json
import scan
from util import web_scrap
################################################
# SEC 1: Initialize aguments with argparsever
# --url, url string with https?:// or without it
# --debug, debug the web scraper actions(or a verbosity) | default=false
# --limit, Web scrap depth level(Using this option users 
# can set a recursion limit for crawling. For
# example, a depth of 2 means crawler will find all the 
# links from the homepage (limit
# and then will crawl those levels as well (limit 2) | default=1)
# --threat, It is possible to make concurrent requests 
# to the target and -t ​ option
# can be used to specify the number of concurrent
 # requests to make | default=1
################################################
parser = argparse.ArgumentParser(prog='jshole')
parser.add_argument('-u', '--url', help='url string', dest='url', action='store', required=True)
parser.add_argument('-d', '--debug', help='Web Scrap debuger(default=false)', dest='debug', default=False, action='store_true', required=False)
parser.add_argument('-l', '--limit', help='Search depth limit(default=1)', default=1, dest='limit', action='store', required=False, type=int)
parser.add_argument('-t', '--threat', help='The number of links that open per round', default=1, dest='threat', action='store', required=False, type=int)
format_help = parser.format_help()
args = parser.parse_args()
################################################
# SEC 2: Get Arguments and Run Web Scrap.
# Get the content of JavaScript pages and files 
# and give them to scan.run()
################################################
def run():
	url = args.url
	debug = args.debug
	limit = args.limit
	threat = args.threat
	scraper = web_scrap.main(url, debug, limit, threat)
	scraper.run_crawl()
	js_links = scraper.js
	print(json.dumps(js_links, indent=4))
	all_pages = scraper.pages
	result = scan.run(js_links, all_pages)
	if result:
		print(f'[*] found {len(result)} vulnrability')
	print(json.dumps(result, indent=4))
################################################
# SEC 3: Run the program
################################################
if __name__ == '__main__':
	try:
		run()
	except Exception as e:
		raise e
	except KeyboardInterrupt:
		print('Canceled by user')