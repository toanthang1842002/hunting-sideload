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


hijacklib_dir        = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hijacklib")
json_yaml_file_path  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yaml_files_path.json")

def find_dir_rule_path(dll_name):
    try:
        with open(json_yaml_file_path, 'r') as f:
            yaml_files = json.load(f)
            
        for yaml_file in yaml_files:
            if yaml_file['name'].lower().startswith(dll_name.lower()):
                return os.path.join(hijacklib_dir, yaml_file['path'])
        print(f"No YAML file found for DLL: {dll_name}")
        return False
        
    except FileNotFoundError:
        print(f"Could not find yaml_files_path.json at {json_yaml_file_path}")
        return False
    except json.JSONDecodeError:
        print("Error decoding yaml_files_path.json")
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
        print("invalid path")
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
            print ('invalid dll')
            return
        
        print ('valid dll')
    
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Example script")
    parser.add_argument("-d","--dllpath", help="DLL path")
    parser.add_argument("-p","--parentprocesspath", help="Parent Process Path")
    args = parser.parse_args()
    verify_correctness(args.dllpath, args.parentprocesspath)
    # # verify_correctness(args.input)
    # verify_correctness("C:\\Program Files\\Kingsoft\\WPS Office\\10.012.14\\office6\\krpt.dll", 
    #                    "C:\\Program Files\\Kingsoft\\WPS Office\\10.012.14\\office6\\12345678.exe")
    
