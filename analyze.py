'''
Done on top of the solution show in https://avleonov.com/2017/10/03/downloading-and-analyzing-nvd-cve-feed/
'''
from os import listdir
from os.path import isfile, join
import zipfile
import json
import sys

files = [f for f in listdir("json/") if isfile(join("json/", f))]
files.sort()
for file in files:
    print("Opening: " + file)
    archive = zipfile.ZipFile(join("json/", file), 'r')
    jsonfile = archive.open(archive.namelist()[0])
    cve_dict = json.loads(jsonfile.read())
    jsonfile.close()

print("Dictionary keys:")
print(cve_dict.keys())
print("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp']))
print("CVE_data_version: " + str(cve_dict['CVE_data_version']))
print("CVE_data_format: " + str(cve_dict['CVE_data_format']))
print("CVE_data_numberOfCVEs: " + str(cve_dict['CVE_data_numberOfCVEs']))
print("CVE_data_type: " + str(cve_dict['CVE_data_type']))
'''
print("JSON dump")
print(json.dumps(cve_dict['CVE_Items'][int(sys.argv[1])], sort_keys=True, indent=4, separators=(',', ': ')))

print(cve_dict['CVE_Items'][int(sys.argv[1])].keys())
print("\n")
print(cve_dict['CVE_Items'][int(sys.argv[1])]["configurations"]["nodes"])
print("\n")
print(cve_dict['CVE_Items'][int(sys.argv[1])]["configurations"]["nodes"][0]['cpe'][0]["cpe22Uri"])
'''

cpe = 0
cpe22=0
cpe23=0
contain_ref=0
total_ref=0
desc=0
desc1=0
refsource={}
#print(json.dumps(cve_dict['CVE_Items'][81], sort_keys=True, indent=4, separators=(',', ': ')))
print("Parsing...") 

#description_data[] is always size 1. Why is it even a list?
for i in range(0,len(cve_dict['CVE_Items'])):
    if 'configurations' in cve_dict['CVE_Items'][i]:
        if "nodes" in cve_dict['CVE_Items'][i]["configurations"]:
            if len(cve_dict['CVE_Items'][i]["configurations"]["nodes"]) != 0:
                if 'cpe' in cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]:
                    cpe=cpe+1 
                    if "cpe22Uri" in cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]['cpe'][0]:
                        cpe22=cpe22+1
                    if "cpe23Uri" in cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]['cpe'][0]:
                        cpe23=cpe23+1
        
    if 'cve' in cve_dict['CVE_Items'][i]:
        if 'description' in cve_dict['CVE_Items'][i]['cve']:
            if 'description_data' in cve_dict['CVE_Items'][i]['cve']['description']:
                if len(cve_dict['CVE_Items'][i]['cve']['description']['description_data'])>1:
                    desc1+=1
                if len(cve_dict['CVE_Items'][i]['cve']['description']['description_data'])!=0:
                    desc+=1
                    #acces to description data. Maybe parse this with keywords?
        if 'references' in cve_dict['CVE_Items'][i]['cve']:
            if 'reference_data' in cve_dict['CVE_Items'][i]['cve']['references']:
                if cve_dict['CVE_Items'][i]['cve']['references']['reference_data'] != 0:
                    contain_ref = contain_ref+1
                    #roll through all ref. Maybe use these to download the source file?
                    for ref in cve_dict['CVE_Items'][i]['cve']['references']['reference_data']:
                        total_ref = total_ref+1
                        if ref['refsource'] in refsource:
                            refsource[ref['refsource']] +=1
                        else:
                            refsource[ref['refsource']] = 1    
                        
        
print("Amount of files parsed: {}".format(len(cve_dict['CVE_Items'])))   
print("Number of files that had cpe field: {}".format(cpe))
print("Number of files that had cpe22Uri field: {}".format(cpe22))
print("Number of files that had cpe23Uri field: {}".format(cpe23))
print("\nNumber of files that had references field: {}".format(contain_ref))
print("Total amount of references: {}".format(total_ref)) 
print("\nTotal amount of descriptions: {}".format(desc))
print("Times description_data[] was larger than 1: {}".format(desc1))
print("\nDatabase contains {} different types of reference sources.\nSource types:".format(len(refsource)))

print("Source name #Appearances")
for ref in refsource:
    print("{} #{}".format(ref,refsource[ref]))
    







