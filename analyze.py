'''
Done on top of the solution show in https://avleonov.com/2017/10/03/downloading-and-analyzing-nvd-cve-feed/
'''
from os import listdir
from os.path import isfile, join
import zipfile
import json
import sys
import pickle
import xmltodict


'''
Dictionary
Documentation WIP
'''
search_for={'cve_index': 0,
            'cpe':0, 
            'cpe22Uri': {'amount':0,'flag':0, 'list':{}, 'potential_list': {}},
            'cpe23Uri': {'amount':0,'flag':0, 'list' : {}, 'potential_list': {}},
            'description_data': {'amount':0,'flag':0, 'list':{}}, 
            'reference_data': {'amount': 0, 'flag':0, 'list': {}, 'url':[], 'uniq_url': {}}, 
            'version_data': {'amount': 0, 'flag' : 0},
            'problemtype_data': {'amount': 0, 'flag': 0, 'list':{}}}

def cwe_information(cwe_dict,cid):
    name,desc,ext_desc = cwe_description(cwe_dict,cid)
    print('CWE-{}'.format(cid))
    print('Name: {}'.format(name))
    print('Description: {}'.format(desc))
    print('Extra description: {}'.format(ext_desc))

def cwe_description(cwe_dict,cid):
    '''
    Get cwe description from xml file. IDs seem to be in one of two places. Therefore 2 loops
    
    '''
    
    for weakness in range(len(cwe_dict['Weakness_Catalog']['Weaknesses']['Weakness'])):
        if cwe_dict['Weakness_Catalog']['Weaknesses']['Weakness'][weakness]['@ID'] == cid:
            name = cwe_dict['Weakness_Catalog']['Weaknesses']['Weakness'][weakness]['@Name']
            desc = cwe_dict['Weakness_Catalog']['Weaknesses']['Weakness'][weakness]['Description']
            try:
                ext_desc = cwe_dict['Weakness_Catalog']['Weaknesses']['Weakness'][weakness]['Extended_Description']
            except KeyError:
                ext_desc = ''
            return name , desc, ext_desc
         
    
    for category in range(len(cwe_dict['Weakness_Catalog']['Categories']['Category'])):
        if cwe_dict['Weakness_Catalog']['Categories']['Category'][category]['@ID'] == cid:
            name= cwe_dict['Weakness_Catalog']['Categories']['Category'][category]['Summary']
            desc = ''
            ext_desc = ''
            return name,desc,ext_desc
    
    return '','',''
    

def save_unique(field,content):
    if search_for[field]['flag']==0:
        search_for[field]['flag']+=1
        search_for[field]['amount']+=1                  
        if(content not in search_for[field]['list']):
            search_for[field]['list'][content]=1
        else:
            search_for[field]['list'][content]+=1                                        

    elif(content not in search_for[field]['list']):
        search_for[field]['list'][content]=1
    else:
        search_for[field]['list'][content]+=1

'''
Processing
'''
def process(field, content):
    if field == 'version_data':
        if(content[0]['version_value'] != '-'  and search_for['version_data']['flag'] ==0 ):
            #Idea is to capture one versio data per cve. Therefore the flag is set when version data is first met in the cve.
            search_for['version_data']['flag'] +=1
            search_for['version_data']['amount'] += 1
    
    if field == 'cpe23Uri':
        save_unique(field,content)
     
    if field == 'cpe22Uri':
        save_unique(field, content)


   # if field == 'description_data':
    #    save_unique(field,content)
        '''
        if search_for['description_data']['flag']==0:
            search_for['description_data']['flag']+=1
            search_for['description_data']['amount']+=1         
        '''      
                            
'''
In these cases the dictionary field contains a list or a dictionary.
Therefore it has to be called in the different place than the above function
'''
def process_upper_level(field,content):
    if field == 'description_data':
            
        for lists in content: 
            for value in lists:
                if value == 'value' and search_for['description_data']['flag']==0:
                    
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
                elif value == 'url':
                    #code could be shorter if everything was done with logic like this?
                    search_for[field][value].append(dicts[value])                                           
            
        
    if field == 'problemtype_data':
        for dicts in content:
            for lists in dicts:
                
                for values in dicts[lists]:
                    if values['value'] not in search_for['problemtype_data']['list']:
                        search_for['problemtype_data']['list'][values['value']]=1
                    else:
                        search_for['problemtype_data']['list'][values['value']]+=1
                    if search_for['problemtype_data']['flag']==0:
                        search_for['problemtype_data']['amount']+=1
                        search_for['problemtype_data']['flag']=1      
                     
		
				
'''
Iteration function
Call process or process_upper when field matches a value in search_for 
'''        
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
                                            
'''
Reset flags
'''
def reset(d):
    search_for['version_data']['flag'] =0
    search_for['cpe22Uri']['flag'] =0 
    search_for['cpe23Uri']['flag'] =0 
    search_for['description_data']['flag']=0
    search_for['problemtype_data']['flag']=0        
    

def analysis(cve_dict,cwe_dict):
    '''
    Parse through the data and gather + print potentially interesting things
    '''
    print("Parsing...") 
    integers=['0','1','2','3','4','5','6','7','8','9']
    #description_data[] is always size 1. Why is it even a list?
    '''
    Parser loop
        Go over each cve in the dictionary.
    '''
    for i in range(0,len(cve_dict['CVE_Items'])):
        search_for['cve_index']=i
        reset(search_for)
        iterate(cve_dict['CVE_Items'][i])                  

    '''
    After parsing operations
    '''         
    ##Potential cpe with version info
    #if cpe string contain <int>.<int> it is likely that there is a version code in it. These can potentially be used to get the specific version of the software.
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
                                            
    #Unique urls
    #Split the url with '/' and take the part between 'https://' and first /. Should capture the source site relatively well                           
    for site in search_for['reference_data']['url']:
        site = site.split('/')[2]
        if site not in search_for['reference_data']['uniq_url']:
            search_for['reference_data']['uniq_url'][site]=1
        else:
            search_for['reference_data']['uniq_url'][site]+=1                   

   
    '''         
    All prints here       
    '''         
    print("Amount of files parsed: {}".format(search_for['cve_index']+1))   
    #print("Number of files that had cpe field: {}".format(cpe))
    print("Number of files that had cpe22Uri field: {}".format(search_for['cpe22Uri']['amount']))
    print("Number of files that had cpe23Uri field: {}".format(search_for['cpe23Uri']['amount']))
    #print("\nNumber of files that had references field: {}".format(contain_ref))
    #print("Total amount of references: {}".format(total_ref)) 
    print("\nTotal amount of descriptions: {}".format(search_for['description_data']['amount']))
    print("\nDatabase contains {} different types of reference sources.".format(len(search_for['reference_data']['list'])))
    print('Out of {} unique cpe22 strings there are in total {} different cpe22 strings that might contain version info  '.format(len(search_for['cpe22Uri']['list']),len(search_for['cpe22Uri']['potential_list'])))
    print('Out of {} unique cpe23 there are in total {} different cpe23 strings that might contain version info  '.format(len(search_for['cpe23Uri']['list']),len(search_for['cpe23Uri']['potential_list'])))

    print('Saved {} site links and detected {} unique urls'.format(len(search_for['reference_data']['url']), len(search_for['reference_data']['uniq_url'])))
    
    print('Total of {} cve had a problemtype_data value field. There were {} different types of cwe'.format(search_for['problemtype_data']['amount'],len(search_for['problemtype_data']['list']) ))
        
    
    
    
    #print(cwe.keys())
   
    '''
    #Extra printing and saving options
    '''
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
        if '-u' in sys.argv:
            for string in search_for['reference_data']['uniq_url']:
                print(string)        
        if '-t' in sys.argv:
            print("Problem type #Appearances Type")
            for ref,val in search_for['problemtype_data']['list'].items():
                
                name,desc,edesc = cwe_description(cwe_dict,ref.replace('CWE-',''))
                
                print("{} #{} {}".format(ref,val, name))
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
    
    cwefile= open('cwec_v3.1.xml','r')
    xml = cwefile.read()
    cwefile.close()
    cwe_dict = xmltodict.parse(xml)
    save_obj(cwe_dict,'cwe_dict')
    
    

def help(max_size):
    print('Commands:')
    print(' -j <number> : Shows a jsondump of a cve number <number>. Number is a dict index not actual cve number. Max number is {}'.format(max_size-1))
    print(' -l          : Loop version of -j that keeps asking for numbers')
    print(' -r          : reload dictionary from json files')
    print(' -a          : Analysis')
    print(' -a -s       : Save potential cpe strings to a file')
    print(' -a -p22|p23 : Print potential cpe22 or cpe23 stings')
    print(' -a -ps      : Print source types')
    print(' -a -u       : Print unique urls')
    print(' -a -t       : Print cwes and their appearance amounts')
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
        cwe_dict = load_obj('cwe_dict')
        if sys.argv[1] == '-j':
            JSONdump(cve_dict,int(sys.argv[2]))
        elif sys.argv[1] == '-l':
            JSONloop(len(cve_dict['CVE_Items']),cve_dict)
        elif sys.argv[1] == '-r':
            create_dict()
        elif sys.argv[1] == '-a':
            analysis(cve_dict,cwe_dict)
        elif sys.argv[1]== '-h':
            help(len(cve_dict['CVE_Items'])) 
        elif '-c' in sys.argv:
            cwe_information(cwe_dict,sys.argv[2]) 
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





