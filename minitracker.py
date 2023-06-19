import sqlite3
import shodan  
from requests import Session
import datetime
import time
import csv
import smtplib



#shodan connexion

SHODAN_API_KEY = "YOUR_KEY"

api = shodan.Shodan(SHODAN_API_KEY)
collecting_date = datetime.datetime.now()

#setting up the heuristics
heuristics_dcrat = {
    'ssl:"DcRat Server"',

    
}


print("""
 ___ ___  ____  ____   ____  ______  ____    ____    __  __  _    ___  ____  
|   |   ||    ||    \ |    ||      ||    \  /    |  /  ]|  |/ ]  /  _]|    \ 
| _   _ | |  | |  _  | |  | |      ||  D  )|  o  | /  / |  ' /  /  [_ |  D  )
|  \_/  | |  | |  |  | |  | |_|  |_||    / |     |/  /  |    \ |    _]|    / 
|   |   | |  | |  |  | |  |   |  |  |    \ |  _  /   \_ |     \|   [_ |    \ 
|   |   | |  | |  |  | |  |   |  |  |  .  \|  |  \     ||  .  ||     ||  .  
|___|___||____||__|__||____|  |__|  |__|\_||__|__|\____||__|\_||_____||__|\_|\n""")

print('[+] Hunting in progress...\n')


#database management

conn = sqlite3.connect('tracker.db')

c = conn.cursor()

c.execute("""

CREATE TABLE IF NOT EXISTS MOA(
    Description TEXT, 
    ip TEXT,
    port TEXT,
    date TEXT,
    tlp TEXT,
    label TEXT
      
   
)
""")

conn.commit()

#querying shodan

try:

    for x in heuristics_dcrat:

        results = api.search(x)

        # Show the results
        
        for result in results['matches']:
        
            dcrat_results = (result['ip_str'])
            dcrat_port = (result['port'])
        
                    
            c.execute('INSERT INTO MOA VALUES (?,?,?,?,?,?)',(('DcRat'),(dcrat_results),(dcrat_port),(collecting_date),('TLP:CLEAR'),('DcRat')))


                         

    conn.commit()

    print("[+] querying services and saving results in database")
    print("[+] Hunting done!")

    print('[+] Creating CSV for export')

 #Exporting data in a CSV

    c.execute("select * from MOA;")
    with open("moa_tracker.csv", 'w',newline='') as csv_file: 
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([i[0] for i in c.description]) 
        csv_writer.writerows(c)
    conn.close()
    
    print('[+] CSV created')

