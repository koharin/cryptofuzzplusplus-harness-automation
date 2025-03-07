import os

def prepare_prompt2(current_path,algorithm_name,documentation,algorithm_code,file_to_create,argument):
    # path to cryptofuzz document file
    cryptofuzz_file = os.path.join(os.getcwd(), "documentation", "cryptofuzz.txt")
    with open(cryptofuzz_file, "r") as file:
        cryptofuzz_content = file.read()  
    # path of file of algorithm description
    algorithm_file_path = os.path.join(current_path, documentation)
    with open(algorithm_file_path, 'r', encoding='utf-8') as file:
        algorithm_description = file.read()
    # path of file to algorithm example code
    algorithm_code_path = os.path.join(current_path, algorithm_code)
    with open(algorithm_code_path, 'r', encoding='utf-8') as file:
        algorithm_code_content = file.read()   

    #replace string in prompt
    with open(os.path.join(current_path,"prompt","finetuned-prompt.txt"),'r', encoding='utf-8') as file:
        prompt=file.read()

    prompt=prompt.replace("{cryptofuzz}",cryptofuzz_content)
    prompt=prompt.replace("{algorithm_description}", algorithm_description)
    prompt=prompt.replace("{algorithm_code}", algorithm_code)
    prompt=prompt.replace("{arguments}",argument)   
    prompt=prompt.replace("{cryptofuzz_file_name}", file_to_create)
    prompt=prompt.replace("{algorithm}",algorithm_name)

    return prompt

def prepare_prompt(current_path,mode, algorithm_name, documentation, example_code_path, argument, output_dir, file_to_create, algorithm_code,dependency, library_name):
    global file_path, algorithm

    # path to cryptofuzz document file
    cryptofuzz_file = os.path.join(os.getcwd(), "documentation", "cryptofuzz.txt")
    with open(cryptofuzz_file, "r") as file:
        cryptofuzz_content = file.read()
    
    # path of file of algorithm description
    algorithm_file_path = os.path.join(current_path, documentation)
    with open(algorithm_file_path, 'r', encoding='utf-8') as file:
        algorithm_description = file.read()

    # path of file to algorithm example code
    algorithm_code_path = os.path.join(current_path, algorithm_code)
    with open(algorithm_code_path, 'r', encoding='utf-8') as file:
        algorithm_code_content = file.read()

    # path of files to reference
    dependency_content=""
    if dependency:
        for i in range(len(dependency)):
            with open(os.path.join(output_dir,dependency[i]), 'r') as file:
                dependency_content += file.read()
                dependency_content += "\n"

    with open(os.path.join(example_code_path, file_to_create), 'r', encoding='utf-8') as file:
        file_content = file.read()
    
    if mode is "update":
        exist_file = os.path.join(output_dir, file_to_create)
        with open(exist_file, 'r', encoding='utf-8') as file:
            exist_content = file.read()
        
        prompt = build_prompt_update(current_path, exist_content, algorithm_name, algorithm_description, file_content,argument,cryptofuzz_content, algorithm_code_content)
        
        
    else:
        if dependency_content is not None:

            prompt = build_prompt_new_1(current_path, algorithm_name, algorithm_description, file_content, dependency_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create, library_name)
            
        else:
            prompt = build_prompt_new_2(current_path, algorithm_name, algorithm_description, file_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create)

    return prompt

def build_prompt_update(current_path, exist_content, algorithm, algorithm_description, file_content,argument,cryptofuzz_content, algorithm_code_content):
    prompt_file = os.path.join(current_path, "prompt", "update1.txt")
    with open(prompt_file, "r") as file:
        prompt = file.read()
    
    prompt=prompt.replace('{algorithm}', algorithm)
    prompt=prompt.replace('{algorithm_description}', algorithm_description)
    prompt=prompt.replace('{exist_content}', exist_content)
    prompt=prompt.replace('{file_content}', file_content)
    prompt=prompt.replace('{arguments}', argument)
    prompt=prompt.replace('{cryptofuzz}', cryptofuzz_content)
    prompt=prompt.replace('{algorithm_code}', algorithm_code_content)

    return prompt

def build_prompt_new_1(current_path, algorithm, algorithm_description, file_content, dependency_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create, library_name):
    if file_to_create == f'{library_name}_module.cpp':
        prompt_file = os.path.join(current_path, "prompt", "new1-module.txt")
    else:
        prompt_file = os.path.join(current_path, "prompt", "new1-copy.txt")
    with open(prompt_file, 'r') as file:
        prompt = file.read()
    
    prompt=prompt.replace('{algorithm}', algorithm)
    prompt=prompt.replace('{algorithm_description}', algorithm_description)
    prompt=prompt.replace('{file_content}', file_content)
    prompt=prompt.replace('{reference_content}', dependency_content)
    prompt=prompt.replace('{arguments}', argument)
    prompt=prompt.replace('{cryptofuzz}', cryptofuzz_content)
    prompt=prompt.replace('{algorithm_code}', algorithm_code_content)
    prompt=prompt.replace('{filename}',file_to_create)

    return prompt


def build_prompt_new_2(current_path, algorithm, algorithm_description, file_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create):
    prompt_file = os.path.join(current_path, "prompt", "new2-copy.txt")
    with open(prompt_file, 'r') as file:
        prompt = file.read()
    
    prompt=prompt.replace('{algorithm}', algorithm)
    prompt=prompt.replace('{algorithm_description}', algorithm_description)
    prompt=prompt.replace('{file_content}', file_content)
    prompt=prompt.replace('{arguments}', argument)
    prompt=prompt.replace('{cryptofuzz}', cryptofuzz_content)
    prompt=prompt.replace('{algorithm_code}', algorithm_code_content)
    prompt=prompt.replace('{filename}',file_to_create)

    

    return prompt