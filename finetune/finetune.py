import openai
import argparse
import os

def get_argument():
    parser = argparse.ArgumentParser(description="python finetune.py -i training_data.jsonl")
    parser.add_argument("-i", "--input", help="python finetune.py [-h] [-i FILE_PATH]")

    args = parser.parse_args()

    if args:
        return args 
    else:
        return None

def start():
    args = get_argument()
    training_file = args.input
    training_file = os.path.join(os.getcwd(), "data", "preprocess", training_file)

    client = openai.OpenAI(
        api_key = ""
    )

    # uploading training file. file ID is returned when the training file was uploaded to the OpenAI API
    print("[+] upload training data to OPENAI API")
    training_file = client.files.create(
        file=open(training_file, "rb"),
        purpose="fine-tune"
    )
    print(f"training_file: {training_file}")
    training_file_id=str(training_file).split("'")[1]

    print(f"training_file_id: {training_file_id}")

    # create fine-tuned model. fine-tuning.job object is returned
    print("[+] finetune")
    finetune_job = client.fine_tuning.jobs.create(
        training_file=training_file_id,
        model="gpt-4o-2024-08-06"
    )

    # when a job has succeeded, use fine-tuned model as normal
    print(f"{finetune_job}")

if __name__ == "__main__":
    start()