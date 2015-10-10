#!/usr/bin/python3
# Provision & install SSL certificates for domains hosted
# by the box using Let's Encrypt.

import sys, os, os.path

from utils import mailinabox_management_api, load_environment

import dns.resolver
import requests.exceptions
import acme.messages

from letsencrypt_simpleclient import client

def my_logger(message):
    # Silence some messages that we expect.
    if "Reusing existing challenges" in message: return
    if "Validation file is not present" in message: return
    print(message)

def provision_new_certificate(domain=None):
    env = load_environment()

    if domain is None:
        # Install a server certificate for all domains hosted by the box.
        install_domain = env['PRIMARY_HOSTNAME']

        # Get the domains this box serves for web from the management daemon.
        web_domains_info = mailinabox_management_api("/web/domains", is_json=True)
        domains = set(web['domain'] for web in web_domains_info)

        # Ensure the PRIMARY_HOSTNAME is in this list. It always should be,
        # since it is always a web domain, but in case that ever changes...
        domains.add(env['PRIMARY_HOSTNAME'])

    else:
        install_domain = domain # check that we host this domain
        domains = [domain] # what about www?
        raise ValueError("Not implemented yet.")

    # See which domains have DNS working now. We can't provision a certificate
    # before DNS is set up.
    ok_domains = filter_resolvable_domains(domains, env)

    # Stop if no domains are working.
    if len(ok_domains) == 0:
        print("No domain names are resolving to this box in DNS yet.", file=sys.stderr)
        print("Run tools/certificates.py once DNS is working. See the", file=sys.stderr)
        print("Status Checks page in the control panel for details.", file=sys.stderr)
        sys.exit(1)

    # Warn if only some domains are working, and provision for the rest.
    if ok_domains != domains:
        print("Provisioning a SSL certificate for:", ok_domains)
        print("Skipped because DNS is not yet resolving:", domains-ok_domains)
        domains = ok_domains

    # Sort to put the PRIMARY_HOSTNAME first so that it becomes the certificate's
    # common name.
    domains = sorted(domains, key = lambda x : x != env["PRIMARY_HOSTNAME"])

    # Where should we put our Let's Encrypt account info and state cache.
    account_path = os.path.join(env['STORAGE_ROOT'], 'ssl/lets_encrypt')
    if not os.path.exists(account_path):
        os.mkdir(account_path)

    # Where should we ACME challenge files.
    challenges_path = os.path.join(account_path, 'acme_challenges')
    if not os.path.exists(challenges_path):
        os.mkdir(challenges_path)

    # Our private key.
    with open(os.path.join(env['STORAGE_ROOT'], 'ssl/ssl_private_key.pem'), 'rb') as f:
        private_key = f.read()

    # Now repeat requests until we get a certificate or encounter an error.
    agree_to_tos_url = None
    break_if_needs_action = False
    while True:
        try:
            cert = client.issue_certificate(
                domains,
                account_path,
                agree_to_tos_url=agree_to_tos_url,
                private_key=private_key,
                logger=my_logger)

        except client.AccountDataIsCorrupt as e:
        	# This is an extremely rare condition.
        	print("The account data stored in", e.account_file_path, "is corrupt.")
        	print("You should probably delete this file and start over.")

        except client.NeedToAgreeToTOS as e:
            print() # because some logging output may have ocurred already
            print("I'm going to provision an SSL certificate for you from")
            print("Let's Encrypt (letsencrypt.org).")
            print()
            print("SSL certificates are cryptographic keys that ensure communication")
            print("between you and this box are secure when getting and sending mail")
            print("and visiting websites hosted on this box. Let's Encrypt is a free")
            print("provider of SSL certificates.")
            print()
            print("Please open this document in your web browser:")
            print()
            print(e.url)
            print()
            print("It is Let's Encrypt's terms of service agreement. If you agree, I")
            print("can provision that SSL certificate. If you don't agree, you will")
            print("have an opportunity to install your own SSL certificate later.")
            print()
            print("Do you agree? Type 'Y' or 'N' and press <ENTER>: ", end='', flush=True)
            if sys.stdin.readline().strip().upper() != "Y":
                print()
                sys.exit(1)

            # Okay, agree on next iteration.
            agree_to_tos_url = e.url
            continue

        except client.InvalidDomainName as e:
        	# One of the domain names provided is not a domain name the ACME
        	# server can issue a certificate for. Weird because it resolved
            # to this box.
        	print(e)

        except client.NeedToTakeAction as e:
            # Write out the ACME challenge files.
            
            if break_if_needs_action:
                # We already tried this once.
                print()
                print("I couldn't install an ACME challenge. This is a Mail-in-a-Box")
                print("bug. Please report the issue.")
                print()
                sys.exit(3)

            for action in e.actions:
                if isinstance(action, client.NeedToInstallFile):
                    with open(os.path.join(challenges_path, action.file_name), 'w') as f:
                        f.write(action.contents)
                else:
                    raise ValueError(str(action))

            break_if_needs_action = True # don't let us infinitely cycle
            continue

        except client.WaitABit as e:
            # We need to hold on for a bit.
            import time, datetime
            print()
            while e.until_when > datetime.datetime.now():
                print ("We have to wait", int(round((e.until_when - datetime.datetime.now()).total_seconds())), "seconds for the certificate to be issued...")
                time.sleep(10)
            continue

        except Exception as e: # acme.messages.Error, requests.exceptions.RequestException
            # A protocol error occurred. If a CSR was supplied, it might
            # be for a different set of domains than was specified, for instance.
            print("Something went wrong:", e)

        else:
            # We got it!
            ret = mailinabox_management_api("/ssl/install", {
                "domain": install_domain,
                "cert": cert['cert'].decode("ascii"),
                "chain": b"\n".join(cert['chain']).decode("ascii"),
            })

            if ret == "OK":
                print("Certificate has been installed.")
                sys.exit(0)
            else:
                print("There was a problem installing the certificate:")
                print(ret)
                sys.exit(1)

        # Something went wrong.
        sys.exit(1)

def filter_resolvable_domains(domains, env):
    # Filter out domain names that don't yet resolve to this box's IP
    # address.
    return set(
        domain for domain in domains
        if query_dns(domain, "A") == env["PUBLIC_IP"]
        )

def query_dns(qname, rtype):
    # Simple DNS lookup so we can verify that our domain names resolve
    # prior to attempting to issue a certificate. Some notes:
    # * Must make qname absolute to prevent a fall-back lookup with a
    #   search domain appended.
    # * Returns the first answer only.
    qname += "."
    try:
        response = dns.resolver.query(qname, rtype)
    except:
        return None
    else:
        return str(response[0])

if __name__ == "__main__":
    provision_new_certificate()
