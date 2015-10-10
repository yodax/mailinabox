import sys, getpass, urllib.request, urllib.error, json

def load_environment():
    # Load settings from /etc/mailinabox.conf.
    import collections
    env = collections.OrderedDict()
    for line in open("/etc/mailinabox.conf"):
    	env.setdefault(*line.strip().split("=", 1))
    return env

def mailinabox_management_api(cmd, data=None, is_json=False):
	# The base URL for the management daemon. (Listens on IPv4 only.)
	mgmt_uri = 'http://127.0.0.1:10222'

	setup_key_auth(mgmt_uri)

	req = urllib.request.Request(mgmt_uri + cmd, urllib.parse.urlencode(data).encode("utf8") if data else None)
	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		if e.code == 401:
			try:
				print(e.read().decode("utf8"))
			except:
				pass
			print("The management daemon refused access. The API key file may be out of sync. Try 'service mailinabox restart'.", file=sys.stderr)
		elif hasattr(e, 'read'):
			print(e.read().decode('utf8'), file=sys.stderr)
		else:
			print(e, file=sys.stderr)
		sys.exit(1)
	resp = response.read().decode('utf8')
	if is_json: resp = json.loads(resp)
	return resp

def setup_key_auth(mgmt_uri):
	key = open('/var/lib/mailinabox/api.key').read().strip()

	auth_handler = urllib.request.HTTPBasicAuthHandler()
	auth_handler.add_password(
		realm='Mail-in-a-Box Management Server',
		uri=mgmt_uri,
		user=key,
		passwd='')
	opener = urllib.request.build_opener(auth_handler)
	urllib.request.install_opener(opener)
