import ipwhois
import pprint

def get_ip_subnets(asn):
    ipw = ipwhois.IPWhois(asn)
    results = ipw.lookup_rdap()
    subnets = []

    if 'objects' in results and 'entities' in results:
        for entity in results['objects']:
            if 'roles' in entity and 'abuse' in entity['roles']:
                if 'v4prefix' in entity:
                    subnets.extend(entity['v4prefix'])
                if 'v6prefix' in entity:
                    subnets.extend(entity['v6prefix'])

    return subnets

if __name__ == '__main__':
    asn = str(input("Please enter ASN: "))  # Replace with the target ASN (e.g., "AS15169" for Google)
    subnets = get_ip_subnets(asn)

    if subnets:
        print("Active IP Subnets for ASN {}:".format(asn))
        pprint.pprint(subnets)
    else:
        print("No subnets found for ASN {}.".format(asn))
