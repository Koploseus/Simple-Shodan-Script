#!/usr/bin/python

import os
import argparse
import sys
import shodan

def clef_api():
    clef_shodan = "" #API KEY
    return clef_shodan



def shodan_local(info_local):
    apikey = clef_api()
    api = shodan.Shodan(apikey)
    print ("Localisation...")
    host = api.host(info_local)
    print ("\nGeneral Information")
    print ("------------------------------")
    print ("""
            Pays: %s
            Ville: %s
            Code Postal:  %s
            Latitude et Longitude: %s %s

    """ % (host['country_code'], host.get('city', 'n/a'), host.get('postal_code', 'n/a'), host.get('latitude'), host.get('longitude')))



################## RECUPERATION DE SIMPLES INFORMATION AVEC L'API SHODAN #######
def simple_information(ip_simple):
    apikey = clef_api()
    api = shodan.Shodan(apikey)
    print ("Recherche en cours...")
    host = api.host(ip_simple)
    print ("\nGeneral Information")
    print ("------------------------------")
    print ("""
            IP: %s
            Organization: %s
            Operating System: %s
            Pays: %s
            Ville: %s

    """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('country_code','n/a'), host.get('city', 'n/a')))



################ RECUPERATION DES BANNIERES D'INFO de TOUS les ports !! ######
def shodan_complete(all_info):
    apikey = clef_api()
    api = shodan.Shodan(apikey)
    print ("Recherche en cours...")
    host = api.host(all_info)
    print ("\nGeneral Information")
    print ("------------------------------")
    print ("""
            IP: %s
            Organization: %s
            Operating System: %s
            Pays: %s
            Ville: %s

    """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('country_code','n/a'), host.get('city', 'n/a')))

    print ("Port Ouvert(s)")
    print ("------------------------------")
    for item in host['data']:
        print ("""
                Port: %s
                Version: %s
                Vulnérabilitée: %s
        """ % (item['port'], item.get('version  '),item.get('cpe')))

    print ("Info DNS")
    print ("------------------------------")
    print ("""
                hostnames: %s

        """ % (item['hostnames']))


def __main__():

    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', '-i', dest='ip', help='IP victime')
    parser.add_argument('--all', '-a', dest='all', help='Info complete avec banniere')
    parser.add_argument('--local', '-l', dest='local', help='Localisation')


    args = parser.parse_args()
    ip_simple = args.ip
    all_info = args.all
    info_local = args.local

    if args.ip:
        simple_information(ip_simple)
    elif args.all:
        shodan_complete(all_info)
    elif args.local:
        shodan_local(info_local)
    else:
        sys.exit(parser.print_help())


if __name__ == '__main__':
    __main__()
