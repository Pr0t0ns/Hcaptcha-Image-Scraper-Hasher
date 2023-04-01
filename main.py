import tls_client, json, hashlib, jwt, math, time, random, os, threading, requests, ctypes
from datetime import datetime
class Main:
  
  def __init__(self,
               site_key: str = "a5f74b19-9e45-40e0-b45d-47ff91b7a6c2",
               host: str = "accounts.hcaptcha.com") -> None: # sets paramaters
    self.host = host
    self.site_key = site_key
    with open("proxies.txt") as f:
      self.proxies = [px.strip() for px in f] # appending all the proxies in a list
    self.v = requests.get(
      "https://js.hcaptcha.com/1/api.js?reportapi=https://accounts.hcaptcha.com&custom=False"
    ).text # Fetching the Hcaptcha Version
    self.v = self.v.split('nt="')[1].split('"')[0] # Parsing the Hcaptcha src code for the Hcaptcha Version
    self.scraped_imgs = 0 
    self.dups = 0
    self.t1 = time.time() # unix timestamp (this timestamp is used to determine how long the app has been running for so I can display those statistics in the console header)

  def hash_images(self, images: list, question: str):
        try:
          question = question.replace("Please click each image containing a ", "")# Parsing Question
          question = question.replace("Please click each image containing an ", "")# Parsing Question
          question = question.replace("Please click each image containing ", "")# Parsing Question  
          question = question.replace("Please click the center of the ", "") # Parsing Question
          path = f"images/{question}"
          if not os.path.exists(path): # checks if path exists
            os.makedirs(path) # creates path
            open(f"{path}/hashes.txt", "a").close() # Creates hashes.txt file
            print(f"[!]: Found New Subject | Question: ({question})") # prints that it found a new subject to console
          for image in images: # goes through the list of hcaptcha image urls and donwloads content
              img_bytes = requests.get(image, allow_redirects=True).content # fetches bytes from imgs.hcaptcha.com urls
              image_hash = hashlib.md5(img_bytes).hexdigest() # calculates the checksum/hash of the image bytes
              try:
                with open(f"{path}/{image_hash}.jpg", 'wb') as f: # makes file
                  f.write(img_bytes) # writes file bytes to file
                with open(f"{path}/hashes.txt", "a+") as f: 
                  data = [line.strip() for line in f] # stores all hashes in the hashes.txt file in this list
                  if image_hash not in data: # check if there is a hash duplicate for the subject
                    f.write(f"{image_hash}\n") # writes image hash to hashes.txt
                  else: # if their is a duplicate
                    raise TypeError # raises error so it can catch it later on
                self.scraped_imgs += 1 # self explanitory
                print(f"[+]: Scraped Image | Hash {image_hash} | Images Scraped: {self.scraped_imgs} | Question: {question}") # prints data to console
              except Exception: # catches hash/image duplicate error
                path = "/images" # file directory
                f = open(f"{path}/hashes.txt", "a") # creates hashes.txt file in /images dir
                f.write(f"{image_hash} | Folder: {path}/{image_hash}.jpg") # writes the duplicate hash it finds to file
                f.close() # closes file
                self.dups += 1 # self explanitory
                print(f"[/]: Duplicate Image/Hash | Hash: {image_hash} | Duplicates: {self.dups} | Type: {question}") # prints data to console
          return # returns function
        except: # catches real errors
          return self.scrape() # returns original function (this basically makes the program restart for the thread)
        
  def update_windowstats(self): # Displays Statistics on Console Title
    while True: # while True thread
      ctypes.windll.kernel32.SetConsoleTitleW(f"[Pr0t0n] Hcaptcha Hash/Image Scraper | Scraped: {self.scraped_imgs} | Duplicate Hashes: {self.dups} | Time: {round(time.time() - self.t1, 2)}") # Displays program stats in console header 
      time.sleep(0.5) # sleep so CPU doesn't blow up

  def generate_hsl(self, req): # this is h0ndes HSL generator (I'm still learning how this works so you won't see a lot of notes)
    x = "0123456789/:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" # idk what this is
    req = jwt.decode(req, options={"verify_signature": False}) # decodes JWT to a dict (JSON) so it can use it to generate some HSL

    def a(r): # no clue what this does yet
      for t in range(len(r) - 1, -1, -1):
        if r[t] < len(x) - 1:
          r[t] += 1
          return True
        r[t] = 0
      return False

    def i(r): # no clue what this does either
      t = ""
      for n in range(len(r)):
        t += x[r[n]]
      return t

    def o(r, e): # no clue what this does either looks like some hashing tho
      n = e
      hashed = hashlib.sha1(e.encode())
      o = hashed.hexdigest()
      t = hashed.digest()
      e = None
      n = -1
      o = []
      for n in range(n + 1, 8 * len(t)):
        e = t[math.floor(n / 8)] >> n % 8 & 1 # SMH im going to have to figure this out
        o.append(e)
      a = o[:r]

      def index2(x, y): 
        if y in x:
          return x.index(y)
        return -1

      return 0 == a[0] and index2(a, 1) >= r - 1 or -1 == index2(a, 1) 

    def get(): # This looks like the main function
      for e in range(25):
        n = [0 for i in range(e)]
        while a(n):
          u = req["d"] + "::" + i(n)
          if o(req["s"], u):
            return i(n)

    result = get()
    hsl = ":".join([ 
        "1",
        str(req["s"]),
        datetime.now().isoformat()[:19] \
            .replace("T", "") \
            .replace("-", "") \
            .replace(":", ""),
        req["d"],
        "",
        result
    ]) # Formats all the data calculated into HSL format (Probably)
    return hsl # returns HSL value

  def c(self, session):
    try:
      headers = {
        'accept': 'application/json',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8,ar;q=0.7',
        'cache-control': 'no-cache',
        'content-type': 'text/plain',
        'origin': 'https://newassets.hcaptcha.com',
        'pragma': 'no-cache',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
      }
      response = session.post(
        f"https://hcaptcha.com/checksiteconfig?v={self.v}&host={self.host}&sitekey={self.site_key}&sc=1&swa=1", # Fetching JWT Token for HSL and etc.
        headers=headers).json()['c'] # parses the json response for the C value
      response['type'] = "hsl" # Changing solve type from hsw to hsl
      return response # returns response
    except: # catches error
      return self.scrape() # returns original function (this basically makes the program restart for the thread)
  def get_captcha(self, c, hsl, session): # c json value from first hcaptcha request, hsl generated from the JWT (Json Web Token), session is just the tls_client session.
    headers = { # headers
      'accept': 'application/json',
      'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8,ar;q=0.7',
      'cache-control': 'no-cache',
      'content-type': 'application/x-www-form-urlencoded',
      'origin': 'https://newassets.hcaptcha.com',
      'pragma': 'no-cache',
      'referer': 'https://newassets.hcaptcha.com/',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-site',
    }
    timestamp = int(time.time()) # Fetching UNIX timestamp for Hcaptcha

    path = [
        {'x': 100.0, 'y': 100.0}, # X and Y cordinate list for Mouse Movement
    ]
    for i in range(4, 42):
      path.append({'x': random.randint(119, 125) + float(i / int(random.randint(9, 10))), 'y': random.uniform(115.94745628783475, 120.0493795438585) + float(i / int(random.uniform(19.6, 20)))})
      # custom motion data algorithim I made from scratch because im to lazy to import python-ghost-cursor (IK it's pretty shitty I'll make changes to it next update)
   

    mm = [[ # mm stands for mouse movement (aka motion data)
      int(p['x']), # X cordinate of mouse
      int(p['y']), # Y cordinate of mouse
      int(time.time()) # Unix Timestamp (Unix is a way of measuring time for the most part)
    ] for p in path] # appending mouse movement data to list
    payload = {
      "v":self.v, # Hcaptcha Version (I believe)
      "sitekey": self.site_key, # Site Key your solving for
      "host": self.host, # Site Host your solving for
      "hl": "en", # Hcaptcha Language
      "motionData": {"st": timestamp, "dct": timestamp, "mm": mm}, # Motion Data that was randomly calculated above
      "n": hsl, #  hsl value that was generated from the JWT (Json Web Token) fetched from the c data 
      "c": json.dumps(c) # The full C data including the JWT
    }

    try:
      r = session.post(f'https://hcaptcha.com/getcaptcha/{self.site_key}',
                          headers=headers,
                          data=payload,
                          timeout_seconds=10) # sends requests to get captcha
    
      return r.json() # returns the response in Dict/JSON 
    except Exception: # catches errors
      return self.scrape() # returns original function (this basically makes the program restart for the thread)
    
  def create_session(self):
    return tls_client.Session(client_identifier=f"chrome_{random.randint(109, 111)}") # creates requests client with chrome version 109-111 (randomly choosen)
    
  def scrape(self): 
    session = self.create_session() # Gets requests session
    proxy = random.choice(self.proxies) # picks random proxy from proxies.txt
    session.proxies = { # sets session proxies
      "http": f"http://{proxy}", # HTTP 
      "https": f"http://{proxy}" # HTTPS
    }
    c = self.c(session) # fetches C response
    hsl = self.generate_hsl(c['req']) # generates hsl with the JWT value inside the C response
    r = self.get_captcha(c, hsl, session) # gets captcha
    images = [] # Image ist
    try:
      question = r['requester_question']['en'] # Parsing response to get the Hcaptcha Question
      for data in r['tasklist']: # parsing to get each hcaptcha image
        images.append(data['datapoint_uri']) # appending each hcaptcha image to list
      self.hash_images(images, question) # responsible for hashing everything and writing/creating files.
    except: # Except Error
      return self.scrape() # returns original function (this basically makes the program restart for the thread)
    return self.scrape() # returns original function (this basically makes the program restart for the thread)
  
    


if __name__ == "__main__": 
  Main = Main() # Initializes Class variables
  if input("Do you want to display window statistics (y/n): ").lower() == 'y': run = True  # checks user input (to see if user want's to display statistics in the header of the console)
  else: run = False 
  for i in range(int(input("Threads: "))): # to lazy 2 explain this part in depth but it's self explanitory for the most part
    threading.Thread(target=Main.scrape).start() # starts thread
  if run: # checks to see if user wants to display console header statistics
    threading.Thread(target=Main.update_windowstats).start() # starts thread 
      
