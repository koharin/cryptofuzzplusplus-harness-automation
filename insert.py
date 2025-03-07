import os

def insert_content_to_file(file_to_insert_path, file_path, pattern, algorithm_name):
    with open(file_to_insert_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    with open(file_path, 'r', encoding='utf-8') as file:
        content_to_insert_lines=file.readlines()
    new_lines=list()   

    for line in lines:
        if algorithm_name in line:
            content_to_insert_lines=[]
        if pattern in line:
            for content in content_to_insert_lines:
                new_lines.append(content)
            new_lines.append("\n")
        new_lines.append(line)

    with open(file_to_insert_path, 'w', encoding='utf-8') as file:
            file.writelines(new_lines)
    
    print(f"[+] Insert to {file_to_insert_path} completed")


def insertion(output_path, file_to_create, cryptofuzz_dir, library_name, algorithm_name):
    file_path=""
    if file_to_create == f"{library_name}_module.cpp":
        file_path=os.path.join("modules", library_name, "module.cpp")
    elif file_to_create == f"{library_name}_module.h":
        file_path=os.path.join("modules", library_name, "module.h")
    elif file_to_create == "module.h" or file_to_create == "operations.h":
        file_path=os.path.join("include", "cryptofuzz",file_to_create)
    else:
        file_path=file_to_create
    
    file_to_insert_path=os.path.join(cryptofuzz_dir, file_path)

    if file_to_create == f"{library_name}_module.cpp":
        pattern="} /* namespace module */"
    elif file_to_create == "module.h":
        pattern="};"    
    elif file_to_create == "gen_repository.py":
        pattern='ciphers = CipherTable()'
    elif file_to_create == "tests.h":
        pattern="} /* namespace tests */"
    elif file_to_create == "tests.cpp":
        pattern="} /* namespace tests */"
    elif file_to_create == "operations.h":
        pattern="} /* namespace operation */"
    elif file_to_create == "operation.cpp":
        pattern="} /* namespace operation */"
    elif file_to_create == "executor.h":
        pattern="} /* namespace cryptofuzz */"
    elif file_to_create == "executor.cpp":
        pattern="/* Explicit template instantiation */"
    elif file_to_create == "driver.cpp":
        pattern='case CF_OPERATION("Digest"):'
    elif file_to_create == "mutator.cpp":
        pattern='case    CF_OPERATION("RSA_generate_key_ex"):'
    elif file_to_create == f"{library_name}_module.h":
        pattern='};'
    
    insert_content_to_file(file_to_insert_path, output_path, pattern, algorithm_name)
    
