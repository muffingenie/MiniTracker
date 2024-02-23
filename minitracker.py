import sqlite3
import shodan  
import datetime


#shodan connexion

SHODAN_API_KEY = "YOUR_VERY_OWN_KEY"

api = shodan.Shodan(SHODAN_API_KEY)
collecting_date = datetime.datetime.now()

#setting up the heuristics 
#ADD here the heuristics you want to check on Shodan, here is an example:


heuristic = {"DcRAT certificate":"ssl:'DcRat Server'","Cobalt Strike":"'cobalt strike'"}

#shodan search

def shodan_search():
    for key, signature in heuristic.items():
        results = api.search(signature)
        for result in results['matches']:

            signature_results = (result['ip_str'])
            signature_port = (result['port'])
            #print(f"{key}: {signature_results}")
            
            database_management(key, signature_results, signature_port)


#database management
def database_management(key, signature_results, signature_port):

    conn = sqlite3.connect('tracker.db')

    c = conn.cursor()

    c.execute("""

    CREATE TABLE IF NOT EXISTS MOA(
        Description TEXT, 
        ip TEXT,
        port TEXT,
        date TEXT 
    )
    """)

    c.execute("INSERT INTO MOA (Description, ip, port, date) VALUES (?, ?, ?, ?)",
              (key, signature_results, signature_port, str(collecting_date)))

    conn.commit()
    conn.close()


print("""
 ___ ___  ____  ____   ____  ______  ____    ____    __  __  _    ___  ____  
|   |   ||    ||    \ |    ||      ||    \  /    |  /  ]|  |/ ]  /  _]|    \ 
| _   _ | |  | |  _  | |  | |      ||  D  )|  o  | /  / |  ' /  /  [_ |  D  )
|  \_/  | |  | |  |  | |  | |_|  |_||    / |     |/  /  |    \ |    _]|    / 
|   |   | |  | |  |  | |  |   |  |  |    \ |  _  /   \_ |     \|   [_ |    \ 
|   |   | |  | |  |  | |  |   |  |  |  .  \|  |  \     ||  .  ||     ||  .  
|___|___||____||__|__||____|  |__|  |__|\_||__|__|\____||__|\_||_____||__|\_|\n""")

print('[+] Hunting in progress...\n')

shodan_search()

print('[+] Hunting done.\n')
