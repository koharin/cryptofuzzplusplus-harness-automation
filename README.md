# cryptofuzz-harness

python3.7 is required.

## Install requirements
```bash
python3.7 -m pip install -r requirements.txt
```

## Usage
1. Write yaml file which is a configuration for cryptographic library API.
2. run api_request.py
```bash
python3.7 api_request.py -c X509_STORE_CTX_verify.yaml -l openssl
```

### fine-tune GPT model
- prepare training data with:
```bash
python3 data_preprocess.py
```
- dataset result: data/preprocess/output.jsonl
- make train and valid dataset with:
```bash
python3 make_train_valid_data.py -i output.jsonl
```
- train dataset: data/preprocess/train.jsonl
- valid dataset: data/preprocess/valid.jsonl
- finetune with training data:
```bash
python3 finetune.py -i output.jsonl
```
- finetune with training data and valid data:
```bash
python3 finetune2.py -t train.jsonl -v valid.jsonl -l openssl
```
