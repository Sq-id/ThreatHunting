import sys
from pythonclimenu import menu
from Funcs import let_me_func, Signatures_Functions


mainOPTIONS=let_me_func.gatherSigList("Detection List")
mainMenu=menu(title="BLYAT", options=mainOPTIONS, cursor_color="magenta")

if mainMenu == "Exit":
    print("Thanks for using me!")
    sys.exit()
if mainMenu == "Add Signatues":
    print("Going to add in sig add funtion here from the signatures_functions lib")
    sys.exit()

SecondOPTIONS=let_me_func.gatherSigList(mainMenu)
secondMenu=menu(title=mainMenu,options=SecondOPTIONS, cursor_color="magenta")

match mainMenu:
    case "Network Based Signatures":
        secondMenu
        Signatures_Functions.tcp_udp_flag_header()
    case "Host Based Signatures":
        print(secondMenu)


