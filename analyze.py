'''
Done on top of the solution show in https://avleonov.com/2017/10/03/downloading-and-analyzing-nvd-cve-feed/
'''
from os import listdir
from os.path import isfile, join
import zipfile
import json
import sys
import pickle



#Dictionary of values you want to search for in the database
search_for={'cve_index': 0, 'cpe':0, 'cpe22Uri': {'amount':0,'flag':0, 'list':{}, 'potential_list': {}}, 'cpe23Uri': {'amount':0,'flag':0, 'list' : {}, 'potential_list': {}}, 'description_data': {'amount':0,'flag':0}, 'reference_data': {'amount': 0, 'flag':0, 'list': {}}, 'version_data': {'amount': 0, 'flag' : 0}}

def process(field, content):
    if field == 'version_data':
        if(content[0]['version_value'] != '-'  and search_for['version_data']['flag'] ==0 ):
            #Idea is to capture one versio data per cve. Therefore the flag is set when version data is first met in the cve.
            search_for['version_data']['flag'] +=1
            search_for['version_data']['amount'] += 1
    
    if field == 'cpe23Uri':
        if search_for['cpe23Uri']['flag']==0:
            search_for['cpe23Uri']['flag']+=1
            search_for['cpe23Uri']['amount']+=1
            if(content not in search_for['cpe23Uri']['list']):
                search_for['cpe23Uri']['list'][content]=1
            elif(content in search_for['cpe23Uri']['list']):
                search_for['cpe23Uri']['list'][content]+=1                                        

        elif(content not in search_for['cpe23Uri']['list']):
            search_for['cpe23Uri']['list'][content]=1
        elif(content in search_for['cpe23Uri']['list']):
            search_for['cpe23Uri']['list'][content]+=1 
     

    if field == 'cpe22Uri':
        if search_for['cpe22Uri']['flag']==0:
            search_for['cpe22Uri']['flag']+=1
            search_for['cpe22Uri']['amount']+=1                  
            if(content not in search_for['cpe22Uri']['list']):
                search_for['cpe22Uri']['list'][content]=1
            elif(content in search_for['cpe22Uri']['list']):
                search_for['cpe22Uri']['list'][content]+=1                                        

        elif(content not in search_for['cpe22Uri']['list']):
            search_for['cpe22Uri']['list'][content]=1
        elif(content in search_for['cpe22Uri']['list']):
            search_for['cpe22Uri']['list'][content]+=1


    if field == 'description_data':
        if search_for['description_data']['flag']==0:
            search_for['description_data']['flag']+=1
            search_for['description_data']['amount']+=1         
            
                            

def process_upper_level(field,content):
    if field == 'description_data':
        if search_for['description_data']['flag']==0:
            for lists in content: 
                for value in lists:
                    if value == 'value':
                        search_for['description_data']['flag']+=1
                        search_for['description_data']['amount']+=1     
    
    if field == 'reference_data':
        for dicts in content:
            for value in dicts:
                if value == 'refsource' and dicts[value] not in search_for['reference_data']['list']:
                    search_for['reference_data']['list'][dicts[value]]=1
                elif value == 'refsource' and dicts[value] in search_for['reference_data']['list']:
                    dicts[value]
                    search_for['reference_data']['list'][dicts[value]]+=1                                         
            
        
        
def iterate(d):
    for k, v in d.items():
        #print(k)
        if k in search_for:
            process_upper_level(k,v)
        if isinstance(v, dict):
            iterate(v)
        elif isinstance(v, list):
            for x in v:
                #print(x)
                iterate(x)
        else:
            if k in search_for:
           
                process(k,v)        
                                            
def reset(d):
    search_for['version_data']['flag'] =0
    search_for['cpe22Uri']['flag'] =0 
    search_for['cpe23Uri']['flag'] =0 
    search_for['description_data']['flag']=0        
    

def analysis(cve_dict):
    cpe = 0
    cpe22=0
    cpe23=0
    contain_ref=0
    total_ref=0
    desc=0
    desc1=0
    refsource={}
    potential22=[]
    potential23=[]
    potential_cve_amount22=[]
    potential_cve_amount23=[]

    
    print("Parsing...") 
    integers=['0','1','2','3','4','5','6','7','8','9']
    #description_data[] is always size 1. Why is it even a list?
    
    for i in range(0,len(cve_dict['CVE_Items'])):
        search_for['cve_index']=i
        reset(search_for)
        iterate(cve_dict['CVE_Items'][i])        
    '''   
     #Dumb parsing. Rework with iterate function
        if 'configurations' in cve_dict['CVE_Items'][i]:
            if "nodes" in cve_dict['CVE_Items'][i]["configurations"]:
                if len(cve_dict['CVE_Items'][i]["configurations"]["nodes"]) != 0:
                    if 'cpe' in cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]:
                        cpe=cpe+1 
                        if "cpe22Uri" in cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]['cpe'][0]:
                            cpe22=cpe22+1
                            #check if uri contans int + , or . + int
                            string = cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]['cpe'][0]['cpe22Uri']
                            #skip the initial cpe part of the string
                            for char in range(3,len(string)):
                                if(char+2 < len(string)):
                                    if string[char] in integers and string[char+1] == ('.' or ',') and string[char+2] in integers:
                                        if string not in potential22:                                        
                                            potential22.append(string)
                                        if i not in potential_cve_amount22:
                                            potential_cve_amount22.append(i)

                        if "cpe23Uri" in cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]['cpe'][0]:
                            cpe23=cpe23+1
                            #check if uri contans int + , or . + int
                            string = cve_dict['CVE_Items'][i]["configurations"]["nodes"][0]['cpe'][0]['cpe23Uri']
                            #string starts with cpe:2.3. skip that by starting from 6                            
                            for char in range(6,len(string)):
                                if(char+2 < len(string)):
                                    if string[char] in integers and string[char+1] == ('.' or ',') and string[char+2] in integers:
                                        if i not in potential_cve_amount23:
                                            potential_cve_amount23.append(i)
                                        if string not in potential23:
                                            potential23.append(string)
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
    '''
    '''         
            if 'affects' in cve_dict['CVE_Items'][i]['cve']:
                if 'vendor' in cve_dict['CVE_Items'][i]['cve']['affects']:
                    if 'vendor_data' in cve_dict['CVE_Items'][i]['cve']['affects']['vendor']:
                        for item in cve_dict['CVE_Items'][i]['cve']['affects']['vendor']['vendor_data']:
    '''                           
                

         
    ##Potential cpe with version info
    for st in search_for['cpe23Uri']['list']:                      
        for char in range(6,len(st)):
            if(char+2 < len(st)):
                if st[char] in integers and st[char+1] == ('.' or ',') and st[char+2] in integers:
                    if st not in search_for['cpe23Uri']['potential_list']:
                        search_for['cpe23Uri']['potential_list'][st]=search_for['cpe23Uri']['list'][st]
                    
    for st in search_for['cpe22Uri']['list']:
                            
        for char in range(3,len(st)):
            if(char+2 < len(st)):
                if st[char] in integers and st[char+1] == ('.' or ',') and st[char+2] in integers:
                    if st not in search_for['cpe22Uri']['potential_list']:
                        search_for['cpe22Uri']['potential_list'][st]=search_for['cpe22Uri']['list'][st]
                                            
                          
   
    #         
                
    print("Amount of files parsed: {}".format(search_for['cve_index']+1))   
    #print("Number of files that had cpe field: {}".format(cpe))
    print("Number of files that had cpe22Uri field: {}".format(search_for['cpe22Uri']['amount']))
    print("Number of files that had cpe23Uri field: {}".format(search_for['cpe23Uri']['amount']))
    print("\nNumber of files that had references field: {}".format(contain_ref))
    print("Total amount of references: {}".format(total_ref)) 
    print("\nTotal amount of descriptions: {}".format(search_for['description_data']['amount']))
    print("\nDatabase contains {} different types of reference sources.".format(len(search_for['reference_data']['list'])))
    print('Out of {} unique cpe22 strings there are in total {} different cpe22 strings that might contain version info  '.format(len(search_for['cpe22Uri']['list']),len(search_for['cpe22Uri']['potential_list'])))
    print('Out of {} unique cpe23 there are in total {} different cpe23 strings that might contain version info  '.format(len(search_for['cpe23Uri']['list']),len(search_for['cpe23Uri']['potential_list'])))
   
    #print(search_for)
    #Extra printing and saving options
    try:
        
        if'-p22' in sys.argv:
            for string in search_for['cpe22Uri']['potential_list']:
                print(string)
        if '-p23' in sys.argv:
            for string in search_for['cpe23Uri']['potential_list']:
                print(string)
        if '-ps' in sys.argv:
            print("Source name #Appearances")
            for ref,val in search_for['reference_data']['list'].items():
                print("{} #{}".format(ref,val))
        if '-s' in sys.argv:
            print('Saved potential cpe strings')
            save_obj(potential22,'potential22')
            save_obj(potential23, 'potential23')
        
    except IndexError:
        print('')    
 

            

def JSONdump(cve_dict,number):    
    print(json.dumps(cve_dict['CVE_Items'][number], sort_keys=True, indent=4, separators=(',', ': ')))
    return 

def JSONloop(max_size, cve_dict):
    
    while True:
        try:
            JSONdump(cve_dict,int(input('Give number between 0-{}. Non number to quit\n'.format(max_size-1))))
        except ValueError:
            break
        except IndexError:
            print('Value too high\n')

def save_obj(obj, name ):
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name):
    with open(name + '.pkl', 'rb') as f:
        return pickle.load(f)

def create_dict():
    files = [f for f in listdir("json/") if isfile(join("json/", f))]
    files.sort()
    for file in files:
        print("Opening: " + file)
        archive = zipfile.ZipFile(join("json/", file), 'r')
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())
        jsonfile.close()
    save_obj(cve_dict, 'cve_dict')
    print("Dictionary keys:")
    print(cve_dict.keys())
    print("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp']))
    print("CVE_data_version: " + str(cve_dict['CVE_data_version']))
    print("CVE_data_format: " + str(cve_dict['CVE_data_format']))
    print("CVE_data_numberOfCVEs: " + str(cve_dict['CVE_data_numberOfCVEs']))
    print("CVE_data_type: " + str(cve_dict['CVE_data_type']))

def help(max_size):
    print('Commands:')
    print(' -j <number> : Shows a jsondump of a cve number <number>. Number is a dict index not actual cve number. Max number is {}'.format(max_size-1))
    print(' -l          : Loop version of -j that keeps asking for numbers')
    print(' -r          : reload dictionary from json files')
    print(' -a          : Analysis')
    print(' -a -s       : Save potential cpe strings to a file')
    print(' -a -p22|p23 : Print cpe22 or cpe23 sting')
    print(' -a -ps      : Print source types')

def main():

    
    '''
    print("JSON dump")
    print(json.dumps(cve_dict['CVE_Items'][int(sys.argv[1])], sort_keys=True, indent=4, separators=(',', ': ')))

    print(cve_dict['CVE_Items'][int(sys.argv[1])].keys())
    print("\n")
    print(cve_dict['CVE_Items'][int(sys.argv[1])]["configurations"]["nodes"])
    print("\n")
    print(cve_dict['CVE_Items'][int(sys.argv[1])]["configurations"]["nodes"][0]['cpe'][0]["cpe22Uri"])
    '''

    
    try:
        cve_dict=load_obj('cve_dict')
        if sys.argv[1] == '-j':
            JSONdump(cve_dict,int(sys.argv[2]))
        elif sys.argv[1] == '-l':
            JSONloop(len(cve_dict['CVE_Items']),cve_dict)
        elif sys.argv[1] == '-r':
            create_dict()
        elif sys.argv[1] == '-a':
            analysis(cve_dict)
        elif sys.argv[1]== '-h':
            help(len(cve_dict['CVE_Items']))  
        else:
            help(len(cve_dict['CVE_Items']))
    except IndexError:
        
        help(len(cve_dict['CVE_Items']))
    except FileNotFoundError:
        print('No dictionary file found. Creating one\n')
        create_dict()            
         




if __name__ == "__main__":
    # execute only if run as a script
    main()





