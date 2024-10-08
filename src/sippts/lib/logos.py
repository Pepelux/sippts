# Art ASCII credits:

# https://fsymbols.com/generators/smallcaps/
# https://patorjk.com/software/taag/ - tmplr - calvin s - small
# https://www.asciiart.eu/electronics/phones

import random
from .color import Color


class Logo:
    def __init__(self, script):
        self.script = script

        self.c = Color()
        
    def print(self):
        print(f'\n' + self.c.RED + u'''☎️  SIPPTS''' + self.c.WHITE +
              ''' BY ''' + self.c.GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + self.c.YELLOW)

        print(self.get_logo() + self.c.WHITE)

        print('' + self.c.BGREEN +
              '''💾 https://github.com/Pepelux/sippts''' + self.c.WHITE)
        print('' + self.c.BBLUE +
              '''🐦 https://twitter.com/pepeluxx\n''' + self.c.WHITE)


    def get_logo(self, color='', local_version='', local_version_status='', local_cve_version='', local_cve_version_status=''):
        rnd = random.randint(1, 4)
        
        if self.script == 'sippts':
            if rnd == 1:
                return f'''
     _________________
    /            __   \\
    |           (__)  |
    | .-----.   .--.  |
    | |     |  /    \\ |
    | '-----'  \\    / |
    |           |  |  |                                    {self.c.BYELLOW}SIPPTS version {local_version}{local_version_status}{color}
    | LI LI LI  |  |  |                                         {self.c.BCYAN}CVE version {local_cve_version}{local_cve_version_status}{color}
    | LI LI LI  |  |  |Oo                     {self.c.BGREEN}https://github.com/Pepelux/sippts{color}
    | LI LI LI  |  |  |`Oo            {self.c.BBLUE}by {self.c.BRED}Pepelux{self.c.BBLUE} - https://twitter.com/pepeluxx{color}
    | LI LI LI  |  |  |  Oo
    |           |  |  |   Oo
    | .------. /    \\ |   oO
    | |      | \\    / |   Oo
    | '------'  '-oO  |   oO
    |           .--Oo |   Oo
    |  SIPPTS   |  | `Oo  oO
    |           '--'  | OoO
    \\_________________/
'''

            elif rnd == 2:
                return f'''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠤⠶⠒⠛⠉⠉⠉⠉⠀⠀⢀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣬⣍⣙⣳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠴⠒⠋⠉⠀⠀⠀⢀⣀⣠⡤⠴⠖⠚⠛⠉⠉⠉⠀⣠⡶⠖⠲⣄⠀⠀⠀⠀⠀⠀⠀⠈⠉⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡤⠖⠋⠁⠀⠀⠀⣀⣤⠴⠖⣛⣉⣁⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⡇⢹⡄⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⡤⠞⠋⠀⠀⠀⢀⣠⠴⠚⠋⠁⠀⠀⡿⡏⠀⠈⣧⣤⠴⠖⠚⠛⠉⠉⠳⢄⡀⠀⣧⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⡞⠧⣄⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⢀⣴⠇⢹⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠉⣲⣿⣀⣠⣼⣦⣤⣀⣀⣀⡀⠀⢀⣀⣠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡿⠀⠀⠈⣿⠉⠀⠀⠀⠀⠀⠀⠙⢄⣰⠏⠀⠀⠘⡇⠀⠀⣇⢀⣀⡤⠤⠖⠒⠛⠉⠉⠉⣁⣀⠀⠀⠀⠉⠙⠛⢿⣿⡛⠛⠛⢻⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣸⣧⣄⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⡄⠀⠀⠀⣷⠴⠚⠋⠉⠀⠀⢀⣠⣴⡖⠛⠉⠿⢻⣿⣉⡉⠙⠓⢲⠦⢤⣈⠙⢶⣶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣏⠙⢦⣹⣼⠀⠀⠀⠀⠀⠀⢀⣴⣾⠟⠁⢀⡏⢀⡞⠀⠀⠀⠀⠀⣰⣯⡟⡀⠀⣼⡏⢘⡢⢠⣷⣾⡿⠿⠿⣷⣤⣞⠀⠙⢦⡀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⡟⠿⡍⢷⢀⡇⠀⠀⠀⠀⠀⠀⠀⣠⣾⠏⣧⠀⢀⡞⠁⠀⠀⠀⠀⢠⡴⠋⠛⠻⣧⣤⡶⢿⡹⡟⠛⢯⣉⣿⢾⣧⣄⡈⠙⠲⢝⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ 
⢠⣏⠙⢦⣹⣼⠀⠀⠀⠀⠀⠀⢀⣴⣾⠟⠁⢀⡏⢀⡞⠀⠀⠀⠀⠀⣰⣯⡟⡀⠀⣼⡏⢘⡢⢠⣷⣾⡿⠿⠿⣷⣤⣞⠀⠙⢦⡀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                     {self.c.BYELLOW}SIPPTS version {local_version}{local_version_status}{color}
⣿⣍⡓⣄⣿⣧⣤⣤⣤⣶⣶⠿⠟⠋⠀⠀⣠⣎⣠⠎⠘⢄⠀⠀⠀⢀⡏⠛⠙⠋⢸⠋⠧⠤⠗⣾⢻⠁⠀⠀⠀⠀⠈⠻⡳⡀⠀⠙⢦⠀⣠⡹⡟⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀                          {self.c.BCYAN}CVE version {local_cve_version}{local_cve_version_status}{color}
⣷⣤⣙⢾⣿⣭⡉⠉⠉⠁⠀⠀⣀⣠⠴⠚⠉⠉⠀⠀⠀⠈⠳⡀⠀⠘⣧⣤⢀⠀⢸⡶⣏⠙⣦⠹⡜⢦⡀⠀⠀⠀⠀⢀⡇⣿⣶⣶⣾⣿⣥⡇⠹⡌⠻⣄⠀⠀⠀⠀⠀⠀⠀⠀        {self.c.BGREEN}https://github.com/Pepelux/sippts{color}
⣿⠤⢬⣿⣇⠈⢹⡟⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢆⠀⢻⡹⡎⠃⠀⠳⡄⣽⠛⠦⠉⠲⣍⣓⣒⢒⣒⣉⡴⠋⣟⠙⢲⣿⠘⠃⠀⣷⠀⠙⢧⡀⠀⠀⠀⠀⠀⠀{self.c.BBLUE}by {self.c.BRED}Pepelux{self.c.BBLUE} - https://twitter.com/pepeluxx{color}
⣿⠶⠒⠺⣿⡀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢣⡀⠳⡄⢀⡀⠀⠙⠮⣗⠚⢠⡖⠲⣌⣉⡭⣍⡡⣞⠓⣾⠉⣽⠃⢠⡄⣼⣿⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀
⠸⡟⠉⣉⣻⣧⣼⠿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠙⢮⡿⢿⡃⠀⠈⠑⠶⢽⣒⣃⣘⣲⣤⣗⣈⣹⠵⠛⠁⠀⠀⡴⣻⠃⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀
⠀⠹⣯⣁⣠⠼⠿⣿⡲⠿⠷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠙⠳⣄⡀⠀⣄⣶⣄⠀⠉⠉⠉⣉⡉⠉⠀⠀⠘⣶⣴⣦⠞⠁⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀
⠀⠀⠘⣧⡤⠖⢋⣩⠿⣶⣤⣈⣙⣷⣤⣀⣠⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⡀⠀⠀⠉⠓⠶⢽⣼⣆⡀⠀⠀⢿⣿⣶⣀⣀⡬⠷⠚⠁⣀⣀⣀⠀⢰⣿⠿⡇⠀⠘⣧⠀⠀
⠀⠀⠀⠀⠙⠾⣏⣤⠞⢁⡞⠉⣿⠋⣹⠉⢹⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⣤⣤⣄⠀⣿⠙⢻⠆⠀⠓⢒⣁⡤⠴⠺⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠒⠻⠤⣴⣇⣀⣿⣀⣾⡤⠿⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⣀⣀⡀⠀⢸⠿⢷⡄⠀⣿⣀⡿⠀⢈⣉⡭⠴⠒⠋⠉⠀⠀⠀⠀⢻⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠰⣟⠛⡇⠀⠘⠧⠞⢁⣀⡤⠴⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣼⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣦⣀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠉⢋⣁⡤⠴⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣴⠶⠚⠛⠉⢉⣽⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⡀⠀⠀⠀⠀⠘⡆⠴⠒⠋⠉⠀⠀      ⢀⣀⣤⠴⠖⠛⠉⠉⠉⠉⠙⠛⠋⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢛⠷⠦⠀⠀⠀⣿⠀⠀   ⠀⠀⠀⢠⠴⡖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
              ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⡀⠀⠘⡆⠴⠒⠋⠉⣤⠴⠖⠛⠀⠀
            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢛⢠⠴⡖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
'''

            elif rnd == 3:
                return f'''
              _              _
             | |------------| |
          .-'| |            | |`-.
        .'   | |   SIPPTS   | |   `.
     .-'      \\ \\          / /      `-.
   .'        _.| |--------| |._        `.
  /    -.  .'  | |        | |  `.  .-    \\
 /       `(    | |________| |    )'       \\
|          \\  .i------------i.  /          |
|        .-')/                \\(`-.        |
\\    _.-'.-'/     ________     \\`-.`-._    /
 \\.-'_.-'  /   .-' ______ `-.   \\  `-._`-./\\
  `-'     /  .' .-' _   _`-. `.  \\     `-' \\\\
         | .' .' _ (3) (2) _`. `. |        //
        / /  /  (4)  ___  (1)_\\  \\ \\       \\\\                                   {self.c.BYELLOW}SIPPTS version {local_version}{local_version_status}{color}
        | | |  _   ,'   `.==' `| | |       //                                        {self.c.BCYAN}CVE version {local_cve_version}{local_cve_version_status}{color}
        | | | (5)  |     | (O) | | |      //                       {self.c.BGREEN}https://github.com/Pepelux/sippts{color}
        | | |   _  `.___.' _   | | |      \\\\               {self.c.BBLUE}by {self.c.BRED}Pepelux{self.c.BBLUE} - https://twitter.com/pepeluxx{color}
        | \\  \\ (6)  _   _ (9) /  / |      //
        /  `. `.   (7) (8)  .' .'  \\      \\\\
       /     `. `-.______.-' .'     \\     //
      /        `-.________.-'        \\ __//
     |                                |--'
     |================================|
     "--------------------------------"
'''
            else:
                return f'''
               __ _
             .: .' '.
            /: /     \\_
           ;: ;  ,-'/`:\\
           |: | |  |() :|
           ;: ;  '-.\\_:/
            \\: \\     /`
             ':_'._.'
                ||
               /__\\
    .---.     |====|
  .'   _,"-,__|::  |
 /    ((O)=;--.::  |
;      `|: |  |::  |
|       |: |  |::  |
|       |: |  |::  |                                                   {self.c.BYELLOW}SIPPTS version {local_version}{local_version_status}{color}
|       |: |  |::  |                                                        {self.c.BCYAN}CVE version {local_cve_version}{local_cve_version_status}{color}
|      /:'__\\ |::  |                                      {self.c.BGREEN}https://github.com/Pepelux/sippts{color}
|     [______]|::  |                              {self.c.BBLUE}by {self.c.BRED}Pepelux{self.c.BBLUE} - https://twitter.com/pepeluxx{color}
|      `----` |::  |__
|         _.--|::  |  ''--._
;       .'  __|====|__      '.
 \\    .'_.-'._ `""` _.'-._    '.
  '--'/`      `'' ''`     `\\    '.__
      '._     SIPPTS     _.'
        # `""--......--""`
'''

        
        rnd = random.randint(1, 3)

        if self.script == 'sipscan':
            if rnd == 1:
                return '''
    ┏┓┳┏┓┏┓┏┳┓┏┓        
    ┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┏┓┏┓
    ┗┛┻┣┛┣┛ ┻ ┗┛  ┛┗┗┻┛┗
                '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌─┐┌─┐┌┐┌
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐│  ├─┤│││
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘└─┘┴ ┴┘└┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                    
 / __|_ _| _ \\ _ \\_   _/ __|  ___ __ __ _ _ _  
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-</ _/ _` | ' \\ 
 |___/___|_| |_|   |_| |___/ /__/\\__\\__,_|_||_|
            '''
        if self.script == 'sipexten':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓           
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┓┏╋┏┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗ ┛┗┗┗ ┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐─┐ ┬┌┬┐┌─┐┌┐┌
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┤ ┌┴┬┘ │ ├┤ │││
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┴ └─ ┴ └─┘┘└┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___           _            
 / __|_ _| _ \\ _ \\_   _/ __|  _____ _| |_ ___ _ _  
 \\__ \\| ||  _/  _/ | | \\__ \\ / -_) \\ /  _/ -_) ' \\ 
 |___/___|_| |_|   |_| |___/ \\___/_\\_\\__\\___|_||_|
                '''

        if self.script == 'siprcrack':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓          ┓ 
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┏┏┓┏┓┏┃┏
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┛ ┗┻┗┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌─┐┬─┐┌─┐┌─┐┬┌─
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘│  ├┬┘├─┤│  ├┴┐
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─└─┘┴└─┴ ┴└─┘┴ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                      _   
 / __|_ _| _ \\ _ \\_   _/ __|  _ _ __ _ _ __ _ __| |__
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_/ _| '_/ _` / _| / /
 |___/___|_| |_|   |_| |___/ |_| \\__|_| \\__,_\\__|_\\_\\
                '''

        if self.script == 'sipdigestleak':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┓    ┓ 
┗┓┃┃┃┃┃ ┃ ┗┓  ┃┏┓┏┓┃┏
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┗ ┗┻┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬  ┌─┐┌─┐┬┌─
╚═╗║╠═╝╠═╝ ║ ╚═╗  │  ├┤ ├─┤├┴┐
╚═╝╩╩  ╩   ╩ ╚═╝  ┴─┘└─┘┴ ┴┴ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___   _          _   
 / __|_ _| _ \\ _ \\_   _/ __| | |___ __ _| |__
 \\__ \\| ||  _/  _/ | | \\__ \\ | / -_) _` | / /
 |___/___|_| |_|   |_| |___/ |_\\___\\__,_|_\\_\\
                '''

        if self.script == 'sipinvite':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  •    •   
┗┓┃┃┃┃┃ ┃ ┗┓  ┓┏┓┓┏┓╋┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┛┗┗┛┗┗┗ 
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬┌┐┌┬  ┬┬┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ││││└┐┌┘│ │ ├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  ┴┘└┘ └┘ ┴ ┴ └─┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___   _         _ _       
 / __|_ _| _ \\ _ \\_   _/ __| (_)_ ___ _(_) |_ ___ 
 \\__ \\| ||  _/  _/ | | \\__ \\ | | ' \\ V / |  _/ -_)
 |___/___|_| |_|   |_| |___/ |_|_||_\\_/|_|\\__\\___|
                '''

        if self.script == 'sipdigestcrack':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓   ┓      ┓ 
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┫┏┏┓┏┓┏┃┏
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┻┗┛ ┗┻┗┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌┬┐┌─┐┬─┐┌─┐┌─┐┬┌─
╚═╗║╠═╝╠═╝ ║ ╚═╗   │││  ├┬┘├─┤│  ├┴┐
╚═╝╩╩  ╩   ╩ ╚═╝  ─┴┘└─┘┴└─┴ ┴└─┘┴ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___      _                _   
 / __|_ _| _ \\ _ \\_   _/ __|  __| |__ _ _ __ _ __| |__
 \\__ \\| ||  _/  _/ | | \\__ \\ / _` / _| '_/ _` / _| / /
 |___/___|_| |_|   |_| |___/ \\__,_\\__|_| \\__,_\\__|_\\_\\
                '''

        if self.script == 'sipsend':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓        ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┗ ┛┗┗┻
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌─┐┌┐┌┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐├┤ │││ ││
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘└─┘┘└┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                   _ 
 / __|_ _| _ \\ _ \\_   _/ __|  ___ ___ _ _  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-</ -_) ' \\/ _` |
 |___/___|_| |_|   |_| |___/ /__/\\___|_||_\\__,_|
                '''

        if self.script == 'sipenumerate':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓                    
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┏┓┓┏┏┳┓┏┓┏┓┏┓╋┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗ ┛┗┗┻┛┗┗┗ ┛ ┗┻┗┗ 
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌┐┌┬ ┬┌┬┐┌─┐┬─┐┌─┐┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┤ ││││ ││││├┤ ├┬┘├─┤ │ ├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┘└┘└─┘┴ ┴└─┘┴└─┴ ┴ ┴ └─┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                                   _       
 / __|_ _| _ \\ _ \\_   _/ __|  ___ _ _ _  _ _ __  ___ _ _ __ _| |_ ___ 
 \\__ \\| ||  _/  _/ | | \\__ \\ / -_) ' \\ || | '  \\/ -_) '_/ _` |  _/ -_)
 |___/___|_| |_|   |_| |___/ \\___|_||_\\_,_|_|_|_\\___|_| \\__,_|\\__\\___|
                '''

        if self.script == 'sipdump':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓   ┓       
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┫┓┏┏┳┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┻┗┻┛┗┗┣┛
                     ┛
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌┬┐┬ ┬┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗   │││ ││││├─┘
╚═╝╩╩  ╩   ╩ ╚═╝  ─┴┘└─┘┴ ┴┴  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___      _                 
 / __|_ _| _ \\ _ \\_   _/ __|  __| |_  _ _ __  _ __ 
 \\__ \\| ||  _/  _/ | | \\__ \\ / _` | || | '  \\| '_ \\
 |___/___|_| |_|   |_| |___/ \\__,_|\\_,_|_|_|_| .__/
                                             |_|  
                '''

        if self.script == 'sipflood':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┏┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ╋┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┗┗┛┗┛┗┻
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┤ │  │ ││ │ ││
╚═╝╩╩  ╩   ╩ ╚═╝  └  ┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___    __ _              _ 
 / __|_ _| _ \\ _ \\_   _/ __|  / _| |___  ___  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ |  _| / _ \\/ _ \\/ _` |
 |___/___|_| |_|   |_| |___/ |_| |_\\___/\\___/\\__,_|
                '''

        if self.script == 'rtpbleed':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓       ┓ ┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┓┣┓┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┣┛┗┛┗┗ ┗ ┗┻
                 ┛          
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ ├─┘├┴┐│  ├┤ ├┤  ││
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ ┴  └─┘┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _        _    _            _ 
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ _ __| |__| |___ ___ __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _| '_ \\ '_ \\ / -_) -_) _` |
 |___/___|_| |_|   |_| |___/ |_|  \\__| .__/_.__/_\\___\\___\\__,_|
                                     |_|                       
                '''

        if self.script == 'rtcpbleed':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓        ┓ ┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┏┓┣┓┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┗┣┛┗┛┗┗ ┗ ┗┻
                  ┛          
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ │  ├─┘├┴┐│  ├┤ ├┤  ││
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ └─┘┴  └─┘┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _           _    _            _ 
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ __ _ __| |__| |___ ___ __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _/ _| '_ \\ '_ \\ / -_) -_) _` |
 |___/___|_| |_|   |_| |___/ |_|  \\__\\__| .__/_.__/_\\___\\___\\__,_|
                                        |_|                      
                '''

        if self.script == 'rtpbleedflood':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓       ┓ ┓     ┓┏┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┓┣┓┃┏┓┏┓┏┫╋┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┣┛┗┛┗┗ ┗ ┗┻┛┗┗┛┗┛┗┻
                 ┛                  
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐┌─┐┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ ├─┘├┴┐│  ├┤ ├┤  ││├┤ │  │ ││ │ ││
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ ┴  └─┘┴─┘└─┘└─┘─┴┘└  ┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _        _    _            _  __ _              _ 
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ _ __| |__| |___ ___ __| |/ _| |___  ___  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _| '_ \\ '_ \\ / -_) -_) _` |  _| / _ \\/ _ \\/ _` |
 |___/___|_| |_|   |_| |___/ |_|  \\__| .__/_.__/_\\___\\___\\__,_|_| |_\\___/\\___/\\__,_|
                                     |_|                                           
                '''

        if self.script == 'rtpbleedinject':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓       ┓ ┓     ┓•  •    
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┓┣┓┃┏┓┏┓┏┫┓┏┓┓┏┓┏╋
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┣┛┗┛┗┗ ┗ ┗┻┗┛┗┃┗ ┗┗
                 ┛             ┛    
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐┬┌┐┌ ┬┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ ├─┘├┴┐│  ├┤ ├┤  ││││││ │├┤ │   │ 
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ ┴  └─┘┴─┘└─┘└─┘─┴┘┴┘└┘└┘└─┘└─┘ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _        _    _            _ _       _        _   
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ _ __| |__| |___ ___ __| (_)_ _  (_)___ __| |_ 
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _| '_ \\ '_ \\ / -_) -_) _` | | ' \\ | / -_) _|  _|
 |___/___|_| |_|   |_| |___/ |_|  \\__| .__/_.__/_\\___\\___\\__,_|_|_||_|/ \\___\\__|\\__|
                                     |_|                            |__/            
                '''

        if self.script == 'arpspoof':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓         ┏
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┓┏┓┏┓╋
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┣┛┗┛┗┛┛
               ┛   
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌─┐┌─┐┌─┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐├─┘│ ││ │├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┴  └─┘└─┘└  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                      __ 
 / __|_ _| _ \\ _ \\_   _/ __|  ____ __  ___  ___ / _|
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-< '_ \\/ _ \\/ _ \\  _|
 |___/___|_| |_|   |_| |___/ /__/ .__/\\___/\\___/_|  
                                |_|                 
                '''

        if self.script == 'sipsniff':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓     •┏┏
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┓┓╋╋
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┛┗┗┛┛                   
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌┐┌┬┌─┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐││││├┤ ├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┘└┘┴└  └  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___           _  __  __ 
 / __|_ _| _ \\ _ \\_   _/ __|  ____ _ (_)/ _|/ _|
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-< ' \\| |  _|  _|
 |___/___|_| |_|   |_| |___/ /__/_||_|_|_| |_|                                                  
                '''

        if self.script == 'sipping':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓    •    
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┓┏┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┣┛┗┛┗┗┫
              ┛     ┛
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┬┌┐┌┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├─┘│││││ ┬
╚═╝╩╩  ╩   ╩ ╚═╝  ┴  ┴┘└┘└─┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___        _           
 / __|_ _| _ \\ _ \\_   _/ __|  _ __(_)_ _  __ _ 
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_ \\ | ' \\/ _` |
 |___/___|_| |_|   |_| |___/ | .__/_|_||_\\__, |
                             |_|         |___/ 
                '''

        if self.script == 'wssend':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┓ ┏┏┓        ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┃┃┃┗┓  ┏┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┻┛┗┛  ┛┗ ┛┗┗┻
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ╦ ╦╔═╗  ┌─┐┌─┐┌┐┌┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ║║║╚═╗  └─┐├┤ │││ ││
╚═╝╩╩  ╩   ╩ ╚═╝  ╚╩╝╚═╝  └─┘└─┘┘└┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___  __      _____                   _ 
 / __|_ _| _ \\ _ \\_   _/ __| \\ \\    / / __|  ___ ___ _ _  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\  \\ \\/\\/ /\\__ \\ (_-</ -_) ' \\/ _` |
 |___/___|_| |_|   |_| |___/   \\_/\\_/ |___/ /__/\\___|_||_\\__,_|                                                               
                '''

        if self.script == 'sippcapdump':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┏┓┏┓┏┓┏┓   ┓       
┗┓┃┃┃┃┃ ┃ ┗┓  ┃┃┃ ┣┫┃┃  ┏┫┓┏┏┳┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┣┛┗┛┛┗┣┛  ┗┻┗┻┛┗┗┣┛
                               ┛ 
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ╔═╗╔═╗╔═╗╔═╗  ┌┬┐┬ ┬┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ╠═╝║  ╠═╣╠═╝   │││ ││││├─┘
╚═╝╩╩  ╩   ╩ ╚═╝  ╩  ╚═╝╩ ╩╩    ─┴┘└─┘┴ ┴┴  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___   ___  ___   _   ___      _                 
 / __|_ _| _ \\ _ \\_   _/ __| | _ \\/ __| /_\\ | _ \\  __| |_  _ _ __  _ __ 
 \\__ \\| ||  _/  _/ | | \\__ \\ |  _/ (__ / _ \\|  _/ / _` | || | '  \\| '_ \\
 |___/___|_| |_|   |_| |___/ |_|  \\___/_/ \\_\\_|   \\__,_|\\_,_|_|_|_| .__/
                                                                  |_|   
                '''

        if self.script == 'astami':
            if rnd == 1:
                return '''
┏┓      • ┓   ┏┓┳┳┓┳
┣┫┏╋┏┓┏┓┓┏┃┏  ┣┫┃┃┃┃
┛┗┛┗┗ ┛ ┗┛┛┗  ┛┗┛ ┗┻
                '''
            elif rnd == 2:
                return '''
╔═╗┌─┐┌┬┐┌─┐┬─┐┬┌─┐┬┌─  ╔═╗╔╦╗╦
╠═╣└─┐ │ ├┤ ├┬┘│└─┐├┴┐  ╠═╣║║║║
╩ ╩└─┘ ┴ └─┘┴└─┴└─┘┴ ┴  ╩ ╩╩ ╩╩
                '''
            elif rnd == 3:
                return '''
    _       _           _    _       _   __  __ ___  
   /_\\   __| |_ ___ _ _(_)__| |__   /_\\ |  \\/  |_ _| 
  / _ \\ (_-<  _/ -_) '_| (_-< / /  / _ \\| |\\/| || |  
 /_/ \\_\\/__/\\__\\___|_| |_/__/_\\_\\ /_/ \\_\\_|  |_|___| 
            '''
