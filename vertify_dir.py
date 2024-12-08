import argparse, re
import os
import json,yaml

windows_env_mapping = {
    "%PROGRAMFILES%"        : os.getenv("PROGRAMFILES"),
    "%PROGRAMFILES(X86)%"   : os.getenv("PROGRAMFILES(X86)"),
    "%WINDIR%"              : os.getenv("WINDIR"),
    "%USERPROFILE%"         : os.getenv("USERPROFILE"),
    "%HOMEPATH%"            : os.getenv("HOMEPATH"),
    "%HOMEDRIVE%"           : os.getenv("HOMEDRIVE"),
    "%APPDATA%"             : os.getenv("APPDATA"),
    "%LOCALAPPDATA%"        : os.getenv("LOCALAPPDATA"),
    "%TEMP%"                : os.getenv("TEMP"),
    "%PUBLIC%"              : os.getenv("PUBLIC"),
    "%SYSTEMDRIVE%"         : os.getenv("SystemDrive"),
    "%ALLUSERSPROFILE%"     : os.getenv("ALLUSERSPROFILE"),
    "%SYSTEMROOT%"          : os.getenv("SystemRoot"),
    "%SYSTEM32%"            : os.path.join(os.getenv("SystemRoot"), "System32"),
    "%SYSWOW64%"            : os.path.join(os.getenv("SystemRoot"), "SysWOW64"),
}

root_dir = os.path.dirname(os.path.abspath(__file__))

hijacklib_dir        = os.path.join(root_dir, "hijacklib")
json_yaml_file_path  = os.path.join(root_dir, "yaml_files_path.json")
dll_legimate_path  = os.path.join(root_dir, "dll_legimate.json")

def find_dir_rule_path(dll_name):
    try:
        with open(json_yaml_file_path, 'r') as f:
            yaml_files = json.load(f)
            
        for yaml_file in yaml_files:
            if yaml_file['name'].lower().startswith(dll_name.lower()):
                return os.path.join(hijacklib_dir, yaml_file['path'])
        print(f"Error: No YAML file found for DLL: {dll_name}")
        return False
        
    except FileNotFoundError:
        print(f"Error: Could not find yaml_files_path.json at {json_yaml_file_path}")
        return False
    except json.JSONDecodeError:
        print("Error: decoding yaml_files_path.json")
        return False
    

def create_regex(string, opt = True):
    pattern = re.escape(string.lower())
    pattern ='.' + pattern[1:]
    pattern = re.sub(r'\d+', r'\\d+', pattern)
    pattern = re.sub(r'%[^%]*%', r'[^\\\\]*', pattern)
    if opt: return pattern + r'\\[^\\]*\.dll'
    return pattern

def replace_env_variables(path):
    for env_var, value in windows_env_mapping.items():
        if value:
            path = path.replace(env_var, value)
    return path

def check_dll_location(legitimate_location, dll_path):
    for location in legitimate_location:
        location = replace_env_variables(location)
        pattern = create_regex(location)
        if re.match(pattern, dll_path.lower()):
            return True
    return False


def check_parent_process(vulnerable_exes, parent_process_path):
    for exe in vulnerable_exes:
        exe = replace_env_variables(exe)
        pattern = create_regex(exe, False)
        if re.match(pattern, parent_process_path.lower()):
            return True
    return False

def verify_correctness(dll_path, parent_process_path):
    dll_name = dll_path.split('\\')[-1]
    path = find_dir_rule_path(dll_name.replace(".dll", ""))
    if not path:
        print("result: invalid path")
        return

    try:
        with open(path, 'r') as f:
            yaml_data = yaml.safe_load(f)
            
        # Get expected locations
        legitimate_location = yaml_data.get('ExpectedLocations', [])
        vulnerable_exes = yaml_data.get('VulnerableExecutables', [])
        vulnerable_exes_paths = [exe['Path'] for exe in vulnerable_exes if 'Path' in exe]
        if not check_dll_location(legitimate_location,dll_path) or \
            not check_parent_process(vulnerable_exes_paths, parent_process_path):
            print ('result: invalid dll')
            return
        
        print ('result: valid dll')
    
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")

def check_hash(hash_sha1):
    try:
        with open(dll_legimate_path, 'r') as f:
            json_files = json.load(f)
        
        sha1_dict = {dll.get('sha1'): dll for dll in json_files}
        
        if hash_sha1 in sha1_dict:
            print("result: valid hash")
            return True
        
        print(f"result: invalid hash")
        return False
        
    except FileNotFoundError:
        print(f"Error: Could not find dll_legimate.json at {json_yaml_file_path}")
        return False
    except json.JSONDecodeError:
        print("Error: decoding dll_legimate.json")
        return False

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Example script")
    parser.add_argument("-d","--dllpath", help="DLL path", required=False)
    parser.add_argument("-p","--parentprocesspath", help="Parent Process Path", required=False)
    parser.add_argument("-sha1","--hashSHA1", help="SHA1 hash")
    args = parser.parse_args()
    if args.hashSHA1:
        check_hash(args.hashSHA1)
    elif args.parentprocesspath and args.dllpath: 
        verify_correctness(args.dllpath, args.parentprocesspath)
    else:
        print("Error: Please provide the DLL path and parent process path")
