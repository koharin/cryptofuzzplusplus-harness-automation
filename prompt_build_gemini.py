import os

def prepare_prompt(current_path, algorithm_name, documentation, example_code_path, argument, output_dir, file_to_create, algorithm_code,dependency):

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
        

    if dependency_content is not None:
        prompt = build_prompt_new_1(current_path, algorithm_name, algorithm_description, file_content, dependency_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create)
            
    else:
        prompt = build_prompt_new_2(current_path, algorithm_name, algorithm_description, file_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create)

    return prompt

def build_prompt_new_1(current_path, algorithm, algorithm_description, file_content, dependency_content,argument,cryptofuzz_content, algorithm_code_content,file_to_create):
    prompt_file = os.path.join(current_path, "prompt", "new1.txt")
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
    prompt_file = os.path.join(current_path, "prompt", "new2.txt")
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