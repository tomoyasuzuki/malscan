import sys
import hashlib
import requests
import argparse
import os
import zipfile
import io

class Colors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

URL = 'https://bazaar.abuse.ch/export/txt/sha256/full/'
HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) '
           'Chrome/49.0.2623.112 Safari/537.36', 'Connection': 'keep-alive'}

def getSignatures():
    if not os.path.exists("full_sha256.txt"):
        print("%sDownloading malware signatures ...%s" % (Colors.Yellow, Colors.Endc))
        try:
            r = requests.get(URL, headers=HEADERS)
            z = zipfile.ZipFile(io.BytesIO(r.content))
            z.extract('full_sha256.txt')
        except Exception as e:
            print(f'%s{e}%s' % (Colors.Red, Colors.Endc))


def check(hash):
    with open("full_sha256.txt", "r") as db:
        for line in db:
            if str(hash) in str(line.strip()):
            # 9213771d3c51 is substring in full_sha256.txt
            # if '9213771d3c51' in str(line.strip()):
                return True
    return False


def scan(path):
    total = 0
    infected_count = 0
    infected_files = []

    if not os.path.exists(path):
        print("%sError: %s not found. Please Enter valid path.%s" % (Colors.Red, path, Colors.Endc))
        sys.exit(1)

    print("%sScanning ... " % (Colors.Yellow))
    for root, dirs, files in os.walk(path):
        if files == 0: continue

        dirs[:] = [d for d in dirs if not d[:1] == '.']
        targets = [os.path.join(root, f) for f in files]
        total += len(targets)

        for file in targets:
            try:
                if not os.path.exists(file):
                    print("%sError: %s not found%s" % (Colors.Red, file, Colors.Endc))
                    continue
                with open(file, "rb") as f:
                    data = f.read()
                    hash = hashlib.sha256(data).hexdigest()
                    result = check(hash)
                    if result:
                        infected_count += 1
                        infected_files.append(file)
            except Exception as e:
                print(f'%s{e} at {file}%s' % (Colors.Red, Colors.Endc))

    return (infected_count, total - infected_count, infected_files)

if __name__ == '__main__':
    print("\n")
    print("%s%s---------------- Malscan: Simple Malware Scanner ---------------%s" % (Colors.Yellow, Colors.BOLD, Colors.Endc))

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path')

    args = parser.parse_args()
    path = args.path

    getSignatures()

    infected, not_infected, files = scan(path)
    print("%s%s---------------------------- Output ----------------------------%s" % (Colors.Yellow, Colors.BOLD, Colors.Endc))
    print("%sInfected: %d%s" % (Colors.Red, infected, Colors.Endc))
    print("%sNot Infected: %d%s" % (Colors.Green, not_infected, Colors.Endc))
    if infected != 0:
        print("%sInfected Files: " % (Colors.Red), end='')
        for file in files:
            print(f'{file} ', end='')
        print('%s' %(Colors.Endc))
