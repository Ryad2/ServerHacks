#!/usr/bin/env python3

import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
from time import sleep

NAMSERVER = (
    '131.159.15.68'  # IP of netsec.net.in.tum.de. - see `dig netsec.net.in.tum.de +short`
)
DOMAIN = 'totallynormaldomain.com.'
HOST = 'netsec.net.in.tum.de'
PORT = 20110

def get_subdomain(domain):
    if not domain.endswith(DOMAIN):
        raise ValueError(f'Domain {domain} does not match {DOMAIN}')
    if domain.count('.') > 3:
        raise ValueError(f'Domain {domain} has too many sublabels.')
    return domain.replace(f'{DOMAIN}', '').strip('.')


# Parse the DNS message
def get_data_from_msg(response, last_label):
    # Look for NSEC in authority section
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            for rdata in rrset:
                next_name = rdata.next.to_text()
                if next_name.endswith(DOMAIN):
                    # extract the subdomain label
                    next_label = next_name.replace(DOMAIN, '').strip('.')
                    # Return the next label to query
                    return next_label
    return None



def main():
    labels = []
    label = '0'  # Hint: none of the labels start with anything lexicographically lower than 0
    while True:
        # Use this to query the nameserver
        request = dns.message.make_query(
            f'{label}.{DOMAIN}', dns.rdatatype.A, want_dnssec=True
        )
        response = dns.query.udp(request, NAMSERVER, port=30053)

        # Process the data and then assemble your list of secret domain labels
        label = get_data_from_msg(response, label)
        labels.append(label)

        sleep(0.01)  # please don't overwhelm our servers, thx

    # write your list of super secret domains
    with open('labels.txt', 'w') as f:
        f.write('\n'.join(labels))


if __name__ == '__main__':
    main()
