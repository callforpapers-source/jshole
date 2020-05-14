# !/usr/bin/env python3
import argparse
import json
import scan
from util import web_scrap

parser = argparse.ArgumentParser(prog='jshole')
parser.add_argument('-u', '--url', help='url string', dest='url', action='store', required=True)
parser.add_argument('-d', '--debug', help='Web Scrap debuger(default=false)', dest='debug', default=False, action='store_true', required=False)
parser.add_argument('-l', '--limit', help='Search depth limit(default=1)', default=1, dest='limit', action='store', required=False, type=int)
parser.add_argument('-t', '--threat', help='The number of links that open per round', default=1, dest='threat', action='store', required=False, type=int)
format_help = parser.format_help()
args = parser.parse_args()

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
		print(f'[*] found {len(result)} vulnerability')
	print(json.dumps(result, indent=4))

if __name__ == '__main__':
	try:
		run()
	except Exception as e:
		raise e
	except KeyboardInterrupt:
		print('Canceled by user')
