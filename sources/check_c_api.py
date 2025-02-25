import sys, os, pefile, re

def main():
    if(len(sys.argv) == 2) and (os.path.isfile(sys.argv[1])):
        pe =  pefile.PE(sys.argv[1], fast_load = True)
        if (not pe.is_dll()):
            print(f"{sys.argv[1]} is not a valid DLL")
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

            print(f"List of C API calls not found in {sys.argv[1]} exports")
            for capi_call in py_capi_used:
                if capi_call not in py_dll_exports:
                    print(f"{capi_call}")
    else:
        print("Need a valid PE file")

if __name__== "__main__":
    main()