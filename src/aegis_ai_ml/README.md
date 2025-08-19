# Machine Learning (ML) only model generation

**IMPORTANT**: _this is an experimental area! there be dragons ...._

ML only means that we use classification/prediction algorithms, which are not based on Large Language Model (LLM).

## setup

To install the dependencies, run the following command in the top-level directory:
```commandline
make install-ml-deps
```

Set Hugging Face token (only needed for non-public models):
```commandline
export HF_TOKEN=INSERT_HF_TOKEN
```

# classifiers

## SecBERT Fine-Tuning for Severity Classification

This script fine-tunes a SecBERT model to classify the severity impact of software vulnerabilities (CVEs) based on their textual descriptions. It provides a complete end-to-end pipeline, from data loading and preprocessing to model training, evaluation, and prediction.

## Key Features

* Local Data Loading: Ingests CVE data from a nested directory of JSON files.
* Text Preprocessing: Cleans and normalizes raw CVE text by combining title and description fields for a richer input.
* Model Fine-Tuning: Uses the Hugging Face Trainer API to fine-tune the jackaduma/SecBERT model, a BERT variant specialized for security text. It includes a fallback to bert-base-uncased if SecBERT is unavailable.
* Hardware Optimization: Automatically detects and utilizes the best available hardware, with specific optimizations for CUDA GPUs and Apple Silicon (MPS).
* Evaluation: Measures model performance using standard metrics like accuracy, a detailed classification report, and a visual confusion matrix.
* Prediction: Includes a simple interface to predict the severity of new, unseen vulnerability descriptions.

## Process flow

* Load & Preprocess: The script recursively scans a specified directory for .json files, loading each as a CVE record. It then cleans the data, combines text fields, and standardizes the severity labels (e.g., "Critical", "Important").
* Prepare Datasets: The preprocessed data is split into training, validation, and test sets, maintaining the original distribution of severity classes.
* Train: The SecBERT model is fine-tuned on the training set. The process includes early stopping to prevent overfitting and saves the best-performing model.
* Evaluate: The trained model's accuracy and per-class performance are calculated against the unseen test set. A confusion matrix is saved as secbert_confusion_matrix.png.
* Save & Predict: The final model, tokenizer, and label encoder are saved to the ./secbert_model directory, ready for inference on new data.

## Extension

The experiment has been extended to train a classifier for each of the basic CVSS3 metrics separately and to predict the flaw impact based on the predicted CVSS3 vector.  This significantly helped to classify Critical and Important flaws (which is the main purpose of the automation we are developing) even though we train the classifier on imbalanced data sets.  Moreover, we get a CVSS3 vector along with each predicted impact class.  If the predicted impact class does not match analyst's expectations, we can easily check which of the predicted CVSS3 metrics caused the difference between the expected and actual prediction.

## Training of the classifier

1. Install the ML dependencies as described in the `setup` section.

2. To download training/evaluation data from OSIDB, run the following command in the top-level directory:

```commandline
export AEGIS_OSIDB_SERVER_URL="https://osidb.prodsec.redhat.com/"
export AEGIS_ML_CVE_DATA_DIR="${PWD}/src/aegis_ai_ml/cve_data"
uv run python src/aegis_ai_ml/src/osidb_retrieve.py
```

3. Run the training and evaluation:

```commandline
cd src/aegis_ai_ml
make classifier
```
