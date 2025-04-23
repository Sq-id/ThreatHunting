from datetime import datetime
import json
import csv


def gatherSigList(SigOption):
    SigOption = SigOption.replace(" ", "_")
    Sigpath = "./Vars/" + SigOption + ".json"
    with open(Sigpath, 'r') as sig_type:
        loadedSig = json.load(sig_type)
    Sig_list_dict = {}
    for sig_json in loadedSig["signatures"]:
        Sig_list_dict.update({sig_json['sig_type']: sig_json['sig_desc']})
    Cleaned_sig_list = []
    for i in Sig_list_dict.keys():
        Cleaned_sig_list.append(i)
    return Cleaned_sig_list


def generate_csv(title, headers, data):
    
    '''
    take in data passed from other functions where we can auto determine field and headers and
    then create a csv output based on datasource_time.csv
    '''
    
    
    date = datetime.now()
    date = str(date)
    date = date.replace(" ", "_")
    filename = "./Data/{title}_{date}.csv".format(title=title, date=date)
    data =str(data)
    
    print(data)
    with open(filename, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        file.writelines(data)

    print(f'CSV file "{filename}" created successfully.')


