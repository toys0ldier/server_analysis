'''

H/T to shlerp (https://github.com/schlerp) for magic bytes documentation

'''

import os, requests, sys, shutil, csv

OMS =    [{
        'ascii': 'CWS',
        'description': 'flash .swf',
        'extension': 'swf',
        'hex': '43 57 53',
        'offset': 0,
        'value': 1
    },
    {
        'ascii': 'EWS',
        'description': 'flash .swf',
        'extension': 'swf',
        'hex': '46 57 53',
        'offset': 0,
        'value': 1
    },
    {
        'ascii': 'MSCF',
        'description': 'Microsoft Cabinet file',
        'extension': 'cab',
        'hex': '4D 53 43 46',
        'offset': 0,
        'value': .5
    },
    {
        'ascii': 'PK..',
        'description': 'zip file format (inc. JAR)',
        'extension': 'zip',
        'hex': '50 4B 03 04',
        'offset': 0,
        'value': .25
    },
    {
        'ascii': 'Rar!...',
        'description': 'RAR archive version 1.50 onwards',
        'extension': 'rar',
        'hex': '52 61 72 21 1A 07 00',
        'offset': 0,
        'value': .25
    },
    {
        'ascii': 'Rar!....',
        'description': 'RAR archive version 5.0 onwards',
        'extension': 'rar',
        'hex': '52 61 72 21 1A 07 01 00',
        'offset': 0,
        'value': .25
    },
    {
        'ascii': 'ustar.00ustar  .',
        'description': 'tar archive',
        'extension': 'tar',
        'hex': '75 73 74 61 72 00 30 30 75 73 74 61 72 20 20 00',
        'offset': 257,
        'value': .25
    },
    {
        'ascii': '..',
        'description': 'GZIP',
        'extension': 'tar.gz',
        'hex': '1F 8B',
        'offset': 0,
        'value': .25
    },
        {
        'ascii': '."M.',
        'description': 'LZ4 Frame Format, LZ4 block format does not offer any magic bytes.',
        'extension': 'lz4',
        'hex': '04 22 4D 18',
        'offset': 0,
        'value': .25
    },
    {
        'ascii': 'PK..',
        'description': 'zip file format and formats based on it, such asJAR,ODF,OOXML ',
        'extension': 'apk',
        'hex': '50 4B 07 08',
        'offset': 0,
        'value': .50
    },
    {
        'ascii': 'MZ',
        'description': 'DOS MZ executable file format',
        'extension': 'exe',
        'hex': '4D 5A',
        'offset': 0,
        'value': 1
    },
    {
        'ascii': 'FEEDFACE',
        'description': 'Mach-0 Executable (32-bit)',
        'extension': 'bundle',
        'hex': 'FE ED FA CE',
        'offset': 0,
        'value': 1
    },
    {
        'ascii': 'FEEDFACF',
        'description': 'Mach-0 Executable (64-bit)',
        'extension': 'bundle',
        'hex': 'FE ED FA CF',
        'offset': 0,
        'value': 1
    }]

def scan_tree(path):
    try:
        for entry in os.scandir(path):
            if entry.is_dir(follow_symlinks=False):
                yield from scan_tree(entry)
            else:
                yield entry
    except PermissionError:
        pass
    
def get_kwds_filenames():
    KWDS = requests.get('https://raw.githubusercontent.com/toys0ldier/malware_keywords/main/keywords_filenames_only.txt').content.decode('utf-8-sig').split('\n')
    if KWDS[0] == '404: Not Found':
        print('[!] ERROR: Unable to load remote keywords from GitHub, skipping keyword search!')
        return None
    print('\nLoaded %s keywords from wordlist: %s' % (len(KWDS), 'keywords_filenames_only.txt'))
    print('\nCurrently supported filetypes: %s\n' % ', '.join([d['extension'] for d in OMS][:-1]) + ', and ' + [d['extension'] for d in OMS][-1])
    return dict(zip(KWDS, [.75 for _ in range(0, len(KWDS))]))

def scan_file(wordlist, folder_name, entry):
    results = []
    data = {
        'filename': entry.name,
        'filepath': entry.path,
        'filesize': entry.stat().st_size,
        'mtime': entry.stat().st_mtime,
        'ctime': entry.stat().st_ctime,
        'atime': entry.stat().st_atime,
        'results': []
    }
    with open(entry.path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        lines = f.read().splitlines()
        if lines:
            for i, line in enumerate(lines):
                for key, value in wordlist.items():
                    if key.lower() in line.lower():
                        data['results'].append({
                            'line': i, 
                            'match': key,
                            'text': line if len(line) <= 10000 else line[0:10000],
                            'value': value
                        })
    if data['results']:
        results.append(data)
        try:
            outdir = os.path.join(output, folder_name)
            if not os.path.exists(outdir):
                os.mkdir(outdir)
            shutil.copy(entry.path, outdir)
        except Exception:
            print('Failed to copy file: %s' % entry.path)
            pass
        return results
    return ''

def check_hex(header, _sig):
    found = ''
    for i, _char in enumerate(_sig['hex'].split(' ')):
        _byte = ord(bytes.fromhex(_char))
        try:
            if not _byte:
                continue
            elif _byte != header[i + _sig['offset']]:
                return False
            else:
                found = _sig
        except IndexError:
            pass
    return found

def scan_header(entry):
    data = {
        'filename': entry.name,
        'filepath': entry.path,
        'filesize': entry.stat().st_size,
        'mtime': entry.stat().st_mtime,
        'ctime': entry.stat().st_ctime,
        'atime': entry.stat().st_atime,
        'results': []
    }
    ext = ''
    with open(entry.path, 'rb') as f:
        header = f.read(32)
        for _sig in OMS:
            valid = check_hex(header, _sig)
            if valid:
                data['results'].append({
                    'match': valid['extension'],
                    'value': valid['value']
                })
                ext = valid['extension']
    if data['results']:
        try:
            outdir = os.path.join(output, ext)
            if not os.path.exists(outdir):
                os.mkdir(outdir)
            shutil.copy(entry.path, outdir)
        except Exception:
            print('Failed to copy file: %s' % entry.path)
            pass
        return data
    else:
        return False

def scan_single(target):
    results = []
    for entry in os.scandir(target):
        if entry.is_dir() and entry.name != 'Keyword_Results':
            for sub_entry in scan_tree(entry.path):
                try:
                    if sub_entry.is_file() and sub_entry.stat().st_size <= 104857600: # only read files under 100mb:
                        try:
                            data = scan_file(KWDS, entry.name, sub_entry)
                            if data:
                                results.extend(data)
                        except Exception as err:
                            print('Error reading: %s' % sub_entry.name)
                            print('Error text: %s' % str(err))
                            pass
                except Exception:
                    pass
                try:
                    if sub_entry.is_file():
                        try:
                            data = scan_header(sub_entry)
                            if data:
                                results.extend(data)
                        except Exception as err:
                            print('Error reading: %s' % sub_entry.name)
                            print('Error text: %s' % str(err))
                            pass
                except Exception:
                    pass
    return results
    
def scan():
    results = {
        'target': os.path.splitext(os.path.split(sys.argv[1])[1])[0],
        'data': []
    }
    for entry in os.scandir(sys.argv[1]):
        print('Working in: %s' % entry.name)
        results['data'].extend(scan_single(entry))
    return results

def print_results(data):
    SCORE = 0
    for match in data:
        for result in match['results']:
            SCORE += result['value']
    print('Process completed successfully!')
    print('Final score: %s' % SCORE)
    
def save_csv(results):
    with open(os.path.join(output, 'keyword_results.csv'), 'w', encoding='utf-8-sig', errors='replace') as f:
        writer = csv.writer(f)
        writer.writerows(results['data'])

def main():
    global KWDS, output
    output = os.getcwd()
    KWDS = get_kwds_filenames()
    
    results = scan()
    if results['data']:
        print_results(results['data'])
        save_csv(results)
    else:
        print('Process completed successfully but no keyword hits were found!')

if __name__ == '__main__':
    
    main()