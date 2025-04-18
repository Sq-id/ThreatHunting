import json


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
