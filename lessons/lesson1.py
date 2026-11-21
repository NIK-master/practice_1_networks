import requests
import time

start = time.time()
s = requests.Session()
for i in range(32):
    print(f"{i} requests completed")
    s.get(f"https://ya.ru/{i}", headers= {"Connection": "close"})

print(f"done in {time.time() - start} seconds")