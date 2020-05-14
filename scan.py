import re
import hashlib
import requests
import json

def get_text(*args):
	try:
		req = requests.get(*args)
	except:
		return ''
	else:
		return req.text

def jsonfile():
	with open('data/retirejs.json', 'r') as f:
		result = [line.rstrip(
					'\n').encode('utf-8').decode('utf-8') for line in f]
		result = '\n'.join(result)
		return json.loads(result)

definitions = jsonfile()

def is_defined(o):
	return o is not None

def scan(data, extractor, matcher=None, definitions=definitions):
	matcher = matcher or _simple_match
	detected = []
	final_detected = []
	for component in definitions:
		extractors = definitions[component].get(
			"extractors", None).get(
			extractor, None)
		if (not is_defined(extractors)):
			continue
		for i in extractors:
			match = matcher(i, data)
			if (match):
				detected.append({"version": match,
								 "component": component,
								 "detection": extractor})
	for i in detected:
		if i not in final_detected:
			final_detected.append(i)
	return final_detected

def _simple_match(regex, data):
	match = re.search(regex.replace('\\\\', '\\'), data)
	return match.group(1) if match else None

def _replacement_match(regex, data):
	try:
		regex = regex.replace('\\\\', '\\')
		group_parts_of_regex = r'^\/(.*[^\\])\/([^\/]+)\/$'
		ar = re.search(group_parts_of_regex, regex)
		search_for_regex = "(" + ar.group(1) + ")"
		match = re.search(search_for_regex, data)
		ver = None
		if match:
			ver = re.sub(ar.group(1), ar.group(2), match.group(0))
			return ver
	except:pass
	return None

def _scanhash(hash, definitions=definitions):
	for component in definitions:
		hashes = definitions[component].get("extractors", {}).get("hashes", None)
		if not is_defined(hashes):
			continue
		for i in hashes:
			if i == hash:
				return [{"version": hashes[i],
						 "component": component,
						 "detection": 'hash'}]

	return []

def check(results):
	for r in results:
		result = r

		if (not is_defined(definitions[result.get("component", None)])):
			continue
		vulns = definitions[
			result.get(
				"component",
				None)].get(
			"vulnerabilities",
			None)
		for i in range(len(vulns)):
			if (not _is_at_or_above(result.get("version", None),
								vulns[i].get("below", None))):
				if (is_defined(vulns[i].get("atOrAbove", None)) and not _is_at_or_above(
						result.get("version", None), vulns[i].get("atOrAbove", None))):
					continue

				vulnerability = {"info": vulns[i].get("info", None)}
				if (vulns[i].get("severity", None)):
					vulnerability["severity"] = vulns[i].get("severity", None)

				if (vulns[i].get("identifiers", None)):
					vulnerability["identifiers"] = vulns[
						i].get("identifiers", None)

				result["vulnerabilities"] = result.get(
					"vulnerabilities", None) or []
				result["vulnerabilities"].append(vulnerability)

	return results

def _is_at_or_above(version1, version2):
	v1 = re.split(r'[.-]', version1)
	v2 = re.split(r'[.-]', version2)

	l = len(v1) if len(v1) > len(v2) else len(v2)
	for i in range(l):
		v1_c = _to_comparable(v1[i] if len(v1) > i else None)
		v2_c = _to_comparable(v2[i] if len(v2) > i else None)
		if (not isinstance(v1_c, type(v2_c))):
			return isinstance(v1_c, int)
		if (v1_c > v2_c):
			return True
		if (v1_c < v2_c):
			return False

	return True

def _to_comparable(n):
	if (not is_defined(n)):
		return 0
	if (re.search(r'^[0-9]+$', n)):
		return int(str(n), 10)

	return n

def scan_uri(uri, definitions=definitions):
	result = scan(uri, 'uri', definitions=definitions)
	return check(result)

def scan_filename(fileName, definitions=definitions):
	result = scan(fileName, 'filename', definitions=definitions)
	return check(result)

def scan_file_content(content, definitions=definitions):
	result = scan(content, 'filecontent', definitions=definitions)
	if (len(result) == 0):
		result = scan(content, 'filecontentreplace', _replacement_match, definitions)

	if (len(result) == 0):
		result = _scanhash(
			hashlib.sha1(
				content.encode('utf8')).hexdigest(),
			definitions)

	return check(result)

def scan_endpoint(uri, definitions=definitions):
	uri_scan_result = scan_uri(uri, definitions)

	filecontent = requests.get(uri, verify=False).text
	filecontent_scan_result = scan_file_content(filecontent, definitions)

	uri_scan_result.extend(filecontent_scan_result)
	return uri_scan_result

def run(scripts, response):
	result = []
	file = scan_file_content(response)
	if file:
		result.extend(file)
	for script in scripts:
		response = get_text(script)
		file = scan_file_content(response)
		url = scan_uri(script)
		name = scan_filename(script)
		if file or url or name:
			which = file or url or name
			result.append({script: which})
	return result
