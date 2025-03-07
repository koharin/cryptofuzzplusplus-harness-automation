import yaml
import os

def parse(text):
    """Parse only code from response."""
    if "```" in text:
        func = text.split("```")[1]
        if "cpp\n" in func:
            func = func.split("cpp\n")[1]
        if "c++\n" in func:
            func = func.split("c++\n")[1]
        elif "python\n" in func:
            func = func.split("python\n")[1] 
        elif "plaintext\n" in func:
            func = func.split("plaintext\n")[1] 
        elif "c\n" in func:
            func = func.split("c\n")[1]   
        return func
    else:
        return text

def load_config_file(current_path, library_name, filepath):
    """Load the config file."""
    config_path = os.path.join(current_path, "config", library_name, filepath)
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)

    return config