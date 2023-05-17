import json
import urllib.request

print("1 - Download cisa cve json form url")
print("2 - Load cisa cve json local")
print("0 - Exit")
choose = input(str("WDYW? "))

def load_file_local():
    cisa = 'known_exploited_vulnerabilities.json'

    #Load cisa json mean "vulnerabilities":  [{struct1},{struct2}]
    with open(cisa, 'r') as json_file:
        cisa_load = json.load(json_file)
    cisa_cve = cisa_load['vulnerabilities']

    #Load checkpoint json mean "checkpoint_ips": [{struct1},{struct2}]
    with open(checkpoint, 'r') as json_file:
        checkpoint_load = json.load(json_file)
    checkpoint_cve = checkpoint_load['checkpoint_ips']

    find_cve(cisa_cve,checkpoint_cve)

def load_file_url():
    cisa_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

    #Load cisa json mean "vulnerabilities":  [{struct1},{struct2}]
    with urllib.request.urlopen(cisa_url) as url:
        cisa_load = json.load(url)
    cisa_cve = cisa_load['vulnerabilities']

    #Load checkpoint json mean "checkpoint_ips": [{struct1},{struct2}]
    with open(checkpoint, 'r') as json_file:
        checkpoint_load = json.load(json_file)
    checkpoint_cve = checkpoint_load['checkpoint_ips']

    find_cve(cisa_cve,checkpoint_cve)

def find_cve(cisa_cve,checkpoint_cve):
    i = 0
    #Find match cisa with checpoint protections
    for cisa_c in cisa_cve:
        for checkpoint_c in checkpoint_cve:
            if cisa_c['cveID'] == checkpoint_c['Industry Reference']:
                if checkpoint_c['Profile'] == "Prevent":
                    i += 1
                    print("CVE:" + checkpoint_c['Industry Reference'] + " |", "vulnerabilityName:" + checkpoint_c['Protection'] + " |", "Profile:" + checkpoint_c['Profile'] )
                    break
    print("Summ:", i)

if choose == '1':
    checkpoint = 'ips_with_index.json'
    print("Is" + checkpoint + " correct?")
    correct = input(str("Yes/no?")).lower()
    if correct == "no" or correct == "n":
        checkpoint = input("Path to file checkpoint: ")
        load_file_url()
    else:
        load_file_url()

if choose == '2':
    checkpoint = 'ips_with_index.json'
    cisa = 'known_exploited_vulnerabilities.json'
    print("Is path " + checkpoint + " correct?")
    print("Is path " + cisa + " correct?")
    correct = input(str("Yes/no?")).lower()
    if correct == "no" or correct == "n":
        checkpoint = input("Path to file checkpoint: ")
        cisa = input("Path to file cisa: ")
        load_file_local()
    else:
        load_file_local()

if choose == '0':
    exit()