import os
import json

def module_cpp_preprocess(origin_path, output_file):
    """preprocess module.cpp"""
    pattern="libgcrypt::Op"
    module_file=os.path.join(origin_path, "module.cpp")

    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    stop=0
    func_code=""
    module_content=module_content.splitlines()

    for line in module_content:
        
        #line_format='{"messages": [{"role": "system", "content": "You are a code generator specialized in cryptographic libraries."}, {"role": "user", "content": <user_content> }, {"role": "assistant", "content": <assistant_content> }]}'
        if pattern in line: 
            print("[+] Recognized func header")
            if stop:
                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for module.cpp"
                        },
                        {
                            "role": "assistant",
                            "content": func_code+"\n"
                        }
                    ]
                }
                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n')
                func_code=line+"\n"
                algorithm_name=line.split(" ")[1].split("(")[0].split(":")[2].split("Op")[1]
                stop=1
                continue
            else:
                algorithm_name=line.split(" ")[1].split("(")[0].split(":")[2].split("Op")[1]
                func_code += line+"\n"
                stop=1
        else:
            #print(f"line: {line}")
            func_code += line+"\n"
    if func_code:
        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for module.cpp"
                },
                {
                    "role": "assistant",
                    "content": func_code
                }
            ]
        }
        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n') 
    print("[+] End of preprocess module.cpp dataset")

def libgcrypt_module_h_preprocess(origin_path, output_file):
    """preprocess libgcrypt_module.h"""
    pattern="> Op"
    module_file=os.path.join(origin_path, "libgcrypt_module.h")
    
    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    module_content=module_content.splitlines()

    for line in module_content:
        #line_format='{"messages": [{"role": "system", "content": "You are a code generator specialized in cryptographic libraries."}, {"role": "user", "content": <user_content> }, {"role": "assistant", "content": <assistant_content> }]}'
        if pattern in line:
            print(f"line: {line}")
            print("[+] Recognized func header")
            algorithm_name = line.split()[1].split("(")[0].split("Op")[1]
            print(f"algorithm: {algorithm_name}")

            line_format = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a code generator specialized in cryptographic libraries."
                    },
                    {
                        "role": "user",
                        "content": f"Generate {algorithm_name} code for libgcrypt_module.h"
                    },
                    {
                        "role": "assistant",
                        "content": line
                    }
                ]
            }

            with open(output_file, 'a', encoding='utf-8') as file:
                json_str = json.dumps(line_format, ensure_ascii=False)
                file.write(json_str + '\n')
            continue    
    print("[+] End of preprocess libgcrypt_module.h and save to dataset")

def gen_repository_preprocess(origin_path, output_file):
    """preprocess gen_repository.py"""
    module_file=os.path.join(origin_path, "gen_repository.py")
    
    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    module_content=module_content.splitlines()

    for line in module_content:
        print(f"line: {line}")
        algorithm_name = line.split()[1].split('"')[1]
        print(f"algorithm: {algorithm_name}")

        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for gen_repository.py"
                },
                {
                    "role": "assistant",
                    "content": line
                }
            ]
        }

        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n')
        continue        
    print("[+] End of preprocess gen_repository.py and save to dataset")

def tests_h_preprocess(origin_path, output_file):
    """preprocess tests.h"""
    module_file=os.path.join(origin_path, "tests.h")
    
    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    module_content=module_content.splitlines()

    for line in module_content:
        print(f"line: {line}")
        algorithm_name = line.split()[2].split('::')[1].split('&')[0]
        print(f"algorithm: {algorithm_name}")

        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for tests.h"
                },
                {
                    "role": "assistant",
                    "content": line
                }
            ]
        }

        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n')
        continue        
    print("[+] End of preprocess tests.h and save to dataset")

def tests_cpp_preprocess(origin_path, output_file):
    """preprocess tests.cpp"""
    module_file=os.path.join(origin_path, "tests.cpp")
    
    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    module_content=module_content.splitlines()
    func_code=""
    test_func=dict()
    test_func_bool=0
    test_code=""
    pattern1="void test("
    pattern2="void test_"

    for line in module_content:
        if pattern2 in line:
            if test_func_bool:
                test_func[test_algorithm_name] = test_code
                test_code=""
                test_func_bool=0
            else:
                test_func_bool=1
                test_code = line+"\n"
                if "static" in line: test_algorithm_name = line.split()[2].split('(')[0]
                else: test_algorithm_name = line.split()[1].split('(')[0]
            continue
        elif pattern1 in line: 
            if test_func_bool:
                test_func[test_algorithm_name] = test_code
                test_code=""
                test_func_bool=0
            if func_code:
                for key,item in test_func.items():
                    if key in func_code:
                        func_code += "\n" + item  + "\n"

                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for tests.cpp"
                        },
                        {
                            "role": "assistant",
                            "content": func_code
                        }
                    ]
                }       

                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n')
                if "static" in line: 
                    algorithm_name = line.split()[3].split('::')[1].split('&')[0]
                else: 
                    algorithm_name = line.split()[2].split('::')[1].split('&')[0]
                func_code = line+"\n"                       
            else:
                if "static" in line: 
                    algorithm_name = line.split()[3].split('::')[1].split('&')[0]
                else: 
                    algorithm_name = line.split()[2].split('::')[1].split('&')[0]
                func_code = line+"\n"
            continue 
        else:
            if test_func_bool:
                test_code += line+"\n"
            else:
                func_code += line+"\n"
    if func_code:
        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for tests.cpp"
                },
                {
                    "role": "assistant",
                    "content": func_code
                }
            ]
        }
        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n')        
    print("[+] End of preprocess tests.cpp and save to dataset")

def operations_h_preprocess(origin_path, output_file):
    """preprocess operations.h"""
    pattern="class"
    module_file=os.path.join(origin_path, "operations.h")
    
    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    module_content=module_content.splitlines()
    class_code=""

    for line in module_content:
        if pattern in line:

            if class_code:

                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for operations.h"
                        },
                        {
                            "role": "assistant",
                            "content": class_code
                        }
                    ]
                }

                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n')

            print("[+] Recognized func header")
            algorithm_name = line.split()[1]
            print(f"algorithm: {algorithm_name}")
            class_code=line+"\n"
        else:
            class_code += line+"\n"
    if class_code:
        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for operations.h"
                },
                {
                    "role": "assistant",
                    "content": class_code
                }
            ]
        }
        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n')   
    print("[+] End of preprocess operations.h and save to dataset")

def module_h_preprocess(origin_path, output_file):
    """preprocess module.h"""
    pattern="Op"
    module_file=os.path.join(origin_path, "module.h")
    
    with open(module_file, 'r', encoding='utf-8') as file:
        module_content=file.read()

    module_content=module_content.splitlines()

    virtual_code=""

    for line in module_content:
        if pattern in line:

            if virtual_code:

                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for module.h"
                        },
                        {
                            "role": "assistant",
                            "content": virtual_code
                        }
                    ]
                }

                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n')

            print("[+] Recognized func header")
            algorithm_name = line.split()[2].split('Op')[1].split('(')[0]
            print(f"algorithm: {algorithm_name}")
            virtual_code=line+"\n"
        else:
            virtual_code += line+"\n"
    if virtual_code:
        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for module.h"
                },
                {
                    "role": "assistant",
                    "content": virtual_code
                }
            ]
        }
        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n')       
    print("[+] End of preprocess module.h and save to dataset")

def operation_cpp_preprocess(origin_path, output_file):
    """preprocess operation.cpp"""
    pattern="::Name"
    operation_file=os.path.join(origin_path, "operation.cpp")
    with open(operation_file, 'r', encoding='utf-8') as file:
        operation_content=file.read()
    operation_content=operation_content.splitlines()
    func_codes=""
    for line in operation_content:
        if pattern in line:
            if func_codes:
                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for operation.cpp"
                        },
                        {
                            "role": "assistant",
                            "content": func_codes
                        }
                    ]
                }
                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n')

            func_codes=line
            algorithm_name=line.split()[1].split('::')[0]
            print(f"algorithm_name: {algorithm_name}")
        else:
            func_codes += line + "\n"
    if func_codes:
        line_format = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code generator specialized in cryptographic libraries."
                },
                {
                    "role": "user",
                    "content": f"Generate {algorithm_name} code for operation.cpp"
                },
                {
                    "role": "assistant",
                    "content": func_codes
                }
            ]
        }
        with open(output_file, 'a', encoding='utf-8') as file:
            json_str = json.dumps(line_format, ensure_ascii=False)
            file.write(json_str + '\n')        
    print("[+] End of preprocess operation.cpp and save to dataset")

def executor_h_preprocess(origin_path, output_file):
    """preprocess executor.h"""
    pattern1="class Executor"
    pattern2="using"

    with open(os.path.join(origin_path, "executor.h"), 'r', encoding='utf-8') as file:
        executor_content=file.read()
    executor_content=executor_content.splitlines()
    class_code=""
    for line in executor_content:
        if pattern1 in line:
            if class_code:
                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for executor.h"
                        },
                        {
                            "role": "assistant",
                            "content": class_code
                        }
                    ]
                }
                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n')
            class_code=line
            algorithm_name=line.split()[1].split('Executor')[1]
            print(f"algorithm_name: {algorithm_name}")
        elif pattern2 in line:
            if class_code:
                line_format = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a code generator specialized in cryptographic libraries."
                        },
                        {
                            "role": "user",
                            "content": f"Generate {algorithm_name} code for executor.h"
                        },
                        {
                            "role": "assistant",
                            "content": class_code
                        }
                    ]
                }
                with open(output_file, 'a', encoding='utf-8') as file:
                    json_str = json.dumps(line_format, ensure_ascii=False)
                    file.write(json_str + '\n') 
                class_code="" 
            
            algorithm_name=line.split()[1].split('Executor')[1]
            line_format = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a code generator specialized in cryptographic libraries."
                    },
                    {
                        "role": "user",
                        "content": f"Generate {algorithm_name} code for executor.h"
                    },
                    {
                        "role": "assistant",
                        "content": line + "\n"
                    }
                ]
            }
            with open(output_file, 'a', encoding='utf-8') as file:
                json_str = json.dumps(line_format, ensure_ascii=False)
                file.write(json_str + '\n')                            
        else:
            class_code += line + "\n"      
    print("[+] End of preprocess executor.h and save to dataset")

def executor_cpp_preprocess(origin_path, output_file):
    """preprocess executor.cpp"""
    pattern1="/* Specialization for "
    pattern2="template class "
    executor_path=os.path.join(origin_path, "executor.cpp")
    with open(executor_path, 'r', encoding='utf-8') as file:
        executor_content=file.read()
    executor_content=executor_content.splitlines()
    executor_dict=dict()
    codes=""
    for line in executor_content:
        if pattern1 in line:
            if codes:
                executor_dict[algorithm_name] = codes
            algorithm_name=line.split()[3].split('::')[1]
            #line=executor_content.next()
            codes=line 
        elif pattern2 in line:
            if codes:
                executor_dict[algorithm_name] = codes
                codes=""
            algorithm_name=line.split()[3].split('::')[1].split('>')[0]
            executor_dict[algorithm_name] = executor_dict[algorithm_name] + "\n" + line
        else:
            codes += line + "\n"
    for key,item in executor_dict.items():
            line_format = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a code generator specialized in cryptographic libraries."
                    },
                    {
                        "role": "user",
                        "content": f"Generate {key} code for executor.cpp"
                    },
                    {
                        "role": "assistant",
                        "content": item
                    }
                ]
            }
            with open(output_file, 'a', encoding='utf-8') as file:
                json_str = json.dumps(line_format, ensure_ascii=False)
                file.write(json_str + '\n')                      
    print("[+] End of preprocess executor.cpp and save to dataset")

def driver_cpp_preprocess(origin_path, output_file):
    """preprocess driver.cpp"""
    pattern1="static Executor"
    pattern2="case CF_OPERATION"

    driver_dict=dict()
    codes=""
    driver_path=os.path.join(origin_path, "driver.cpp")
    with open(driver_path, 'r', encoding='utf-8') as file:
        driver_content=file.read()
    driver_content=driver_content.splitlines()

    for line in driver_content:
        if pattern1 in line:
            algorithm_name=line.split()[2].split('"')[1]
            driver_dict[algorithm_name] = line
        elif pattern2 in line:
            if codes:
                driver_dict[algorithm_name] = driver_dict[algorithm_name] + "\n" + codes
            algorithm_name=line.split()[1].split('"')[1]
            codes=line
        else:
            codes += line + "\n"
    if codes:
        driver_dict[algorithm_name] = driver_dict[algorithm_name] + "\n" + codes
    for key,item in driver_dict.items():
            line_format = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a code generator specialized in cryptographic libraries."
                    },
                    {
                        "role": "user",
                        "content": f"Generate {key} code for driver.cpp"
                    },
                    {
                        "role": "assistant",
                        "content": item
                    }
                ]
            }
            with open(output_file, 'a', encoding='utf-8') as file:
                json_str = json.dumps(line_format, ensure_ascii=False)
                file.write(json_str + '\n')         
    print("[+] End of preprocess driver.cpp and save to dataset")

def mutator_cpp_preprocess(origin_path, output_file):
    """preprocess mutator.cpp"""
    pattern="case    CF_OPERATION"
    with open(os.path.join(origin_path, "mutator.cpp"), 'r', encoding='utf-8') as file:
        mutator_content=file.read()
    mutator_content=mutator_content.splitlines()
    codes=""
    mutator_dict=dict()
    for line in mutator_content:
        if pattern in line:
            if codes:
                mutator_dict[algorithm_name] = codes 
            algorithm_name=line.split()[1].split('"')[1]
            codes=line
        else:
            codes += line + "\n"
    if codes:
        mutator_dict[algorithm_name] = codes 
    for key,item in mutator_dict.items():
            line_format = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a code generator specialized in cryptographic libraries."
                    },
                    {
                        "role": "user",
                        "content": f"Generate {key} code for mutator.cpp"
                    },
                    {
                        "role": "assistant",
                        "content": item
                    }
                ]
            }
            with open(output_file, 'a', encoding='utf-8') as file:
                json_str = json.dumps(line_format, ensure_ascii=False)
                file.write(json_str + '\n')            
    print("[+] End of preprocess mutator.cpp and save to dataset")

def start():
    origin_path=os.path.join(os.getcwd(), "data", "cryptofuzz", "libgcrypt")
    output_path=os.path.join(os.getcwd(), "data", "preprocess", "libgcrypt")
    os.makedirs(output_path, exist_ok=True)  
    output_file=os.path.join(output_path, "output.jsonl")

    module_cpp_preprocess(origin_path, output_file)
    libgcrypt_module_h_preprocess(origin_path, output_file)
    gen_repository_preprocess(origin_path, output_file)
    tests_h_preprocess(origin_path, output_file)
    tests_cpp_preprocess(origin_path, output_file)
    operations_h_preprocess(origin_path, output_file)
    module_h_preprocess(origin_path, output_file)
    operation_cpp_preprocess(origin_path, output_file)
    executor_h_preprocess(origin_path, output_file)
    executor_cpp_preprocess(origin_path, output_file)
    driver_cpp_preprocess(origin_path, output_file)
    mutator_cpp_preprocess(origin_path, output_file)

    
if __name__ == "__main__":
    start()