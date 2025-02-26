import os, pefile, re, subprocess

def find_all_py():
    py_list = []
    p = subprocess.Popen(["py", "-0p"], universal_newlines = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    p.wait()
    try:
        out, err = p.communicate(timeout = 10)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    if err == "":
        out.splitlines()
        for l in out.splitlines():
            py = re.findall(r"^.*-V:([0-9.]+)[\* ]*(.*)$", l)
            if (len(py)):
                py_dir = os.path.dirname(os.path.abspath(py[0][1]));
                py_dll = 'python' + py[0][0].replace(".","") + ".dll"
                py_all_files = os.listdir(py_dir)
                if py_dll in py_all_files:
                    py_list.append((py[0][0], os.path.join(py_dir, py_dll)))
                else:
                    sys_dir = os.path.join(os.environ.get("SystemRoot"), "system32")
                    py_all_files = os.listdir(sys_dir)
                    if py_dll in py_all_files:
                        py_list.append((py[0][0], os.path.join(sys_dir, py_dll)))
    return py_list

def main():
    sys_py_list = find_all_py()
    print("Installed Python Interpreter:")
    print(*sys_py_list, sep='\n')
    dir_work = os.path.dirname(os.path.abspath(__file__))

    for pyi in sys_py_list:
        print(f"Processing {pyi[0]} ...")
        pe =  pefile.PE(pyi[1], fast_load = True)
        if (not pe.is_dll()):
            print(f"{pyi[1]} is not a valid DLL")
        else:
            py_dll_exports = []
            pe.parse_data_directories()
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                py_dll_exports.append(exp.name.decode('ascii'))

            py_capi_used = []
            py_interpret = (os.path.join(os.path.dirname(__file__), 'pyinterpret.cpp'))
            if os.path.isfile(py_interpret):
                with open(py_interpret, 'r') as f_py_interpret:
                    lines = f_py_interpret.readlines()
                    for line in lines:
                        find_exports = re.findall(r"^.*GetProcAddress\(.*\"(.*)\".*$", line.strip())
                        if (len(find_exports)):
                            py_capi_used.append(find_exports[0])

            f_res = os.path.join(dir_work, "py" + pyi[0].replace(".", "") + ".txt")
            with open(f_res, 'w', newline = '') as f_py_capi_res:
                f_py_capi_res.writelines(f"Python Interpreter {pyi[1]}\n")
                f_py_capi_res.writelines(f"List of C API calls not found in Python {pyi[0]} exports:\n")
                for capi_call in py_capi_used:
                    if capi_call not in py_dll_exports:
                        f_py_capi_res.writelines(capi_call + "\n")

if __name__== "__main__":
    main()