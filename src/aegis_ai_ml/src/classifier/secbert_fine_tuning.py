# inspired by https://github.com/sidhpurwala-huzaifa/redhat-sev-classifier

import cvss
import json
import os
from pathlib import Path

import pandas as pd
import numpy as np
import pickle
import torch
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm.auto import tqdm

from aegis_ai_ml.src.util import normalize_text


CVSS3_BASIC_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def find_rh_cvss3(cvss_scores):
    """find RH CVSS3 in the cvss_scores list in per-CVE data from OSIDB"""
    for item in cvss_scores:
        if item["cvss_version"] != "V3":
            continue

        if item["issuer"] != "RH":
            continue

        cvss3_str = item["vector"]
        return cvss.CVSS3(cvss3_str)


def extract_cvss3_metric(cvss_scores, cvss3_metric):
    """extract value of a single RH CVSS3 metric from the cvss_scores cell"""
    try:
        rh_cvss = find_rh_cvss3(cvss_scores)
        return rh_cvss.get_value_description(cvss3_metric)
    except Exception:
        # failed to get cvss3_metric
        return None


def impact_by_cvss3_score(cvss3_score):
    # we cannot use cvss3.severities() because it uses incompatible labels
    if cvss3_score <= 4.0:
        return "LOW"
    elif cvss3_score <= 7.0:
        return "MODERATE"
    elif cvss3_score <= 9.0:
        return "IMPORTANT"
    else:
        return "CRITICAL"


def check_cvss3_impact(row):
    """check whether impact_clean matches CVSS3 score"""
    cvss3 = find_rh_cvss3(row["cvss_scores"])
    cvss3_score = cvss3.scores()[0]
    expected_impact = impact_by_cvss3_score(cvss3_score)
    actual_impact = row["impact_clean"]
    if actual_impact == expected_impact:
        return actual_impact

    cve_id_aligned = row["cve_id"].ljust(14)
    exp_imp_aligned = expected_impact.ljust(len("IMPORTANT"))
    print(
        f"dropping {cve_id_aligned}"
        f"  cvss3={cvss3.vector}  score={cvss3_score}"
        f"  expected_impact={exp_imp_aligned}  actual_impact={actual_impact}"
    )
    return None


def compute_pred_impact(row, classifier_by_metric):
    """compute impact based on predicted CVSS3 base metrics"""
    cvss3_str = "CVSS:3.1"
    text_input = row["text_input"]
    for cvss3_metric in CVSS3_BASIC_METRICS:
        classifier = classifier_by_metric[cvss3_metric]
        value, _ = classifier.predict_severity(normalize_text(text_input))
        cvss3_str += f"/{cvss3_metric}:{value[0]}"

    cvss3 = cvss.CVSS3(cvss3_str)
    cvss3_score = cvss3.scores()[0]
    return impact_by_cvss3_score(cvss3_score)


def load_and_preprocess_data_from_local(data_directory: str):
    """Load and preprocess CVE data from a local directory of JSON CVE files."""
    print(f"Loading CVE data from local directory: {data_directory}...")

    cve_data = []
    path = Path(data_directory)
    json_files = list(path.rglob("*.json"))

    if not json_files:
        raise FileNotFoundError(f"No JSON files found in directory: {data_directory}")

    # Loop through all found JSON files with a progress bar
    for file_path in tqdm(json_files, desc="Reading JSON files"):
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                # Assuming each file contains a single CVE object
                # If a file contains a list, you would loop through `data` here
                cve_data.append(data)
            except json.JSONDecodeError:
                print(f"Warning: Skipping malformed JSON file: {file_path}")

    # Convert the list of dictionaries to a pandas DataFrame
    df = pd.DataFrame(cve_data)

    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    df = df.dropna(subset=["impact", "title", "cve_description"])

    df["text_input"] = df["title"].astype(str) + " " + df["cve_description"].astype(str)
    df["text_input"] = df["text_input"].apply(normalize_text)

    # Remove empty text inputs
    df = df[df["text_input"].str.len() > 0]

    # Clean impact labels - map to standard format
    severity_mapping = {
        "Critical": "CRITICAL",
        "Important": "IMPORTANT",
        "Moderate": "MODERATE",
        "Low": "LOW",
        "critical": "CRITICAL",
        "important": "IMPORTANT",
        "moderate": "MODERATE",
        "low": "LOW",
        "LOW": "LOW",
        "MODERATE": "MODERATE",
        "IMPORTANT": "IMPORTANT",
        "CRITICAL": "CRITICAL",
    }

    df["impact_clean"] = df["impact"].map(severity_mapping)
    df = df.dropna(subset=["impact_clean"])

    print("\nImpact distribution:")
    severity_counts = df["impact_clean"].value_counts()
    print(severity_counts)
    print(f"\nTotal samples: {len(df)}")

    return df


def evaluate_model(y_pred, y_true, target_names, show_plots=True, file_prefix=""):
    """Evaluate the trained model"""

    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    print(f"Test Accuracy: {accuracy:.4f} ({accuracy:.1%})")

    # Classification report
    report = classification_report(y_true, y_pred, target_names=target_names)
    print("\nClassification Report:")
    print(report)

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)

    # Create plot with confusion matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=target_names,
        yticklabels=target_names,
    )
    plt.title("SecBERT Security Severity Classification - Confusion Matrix")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    file_name = f"{file_prefix}secbert_confusion_matrix.png"
    plt.savefig(file_name, dpi=300, bbox_inches="tight")
    print(f"Confusion matrix saved as '{file_name}'")

    if show_plots:
        plt.show()

    return accuracy, report, cm


class SecurityDataset(Dataset):
    """Custom dataset for security vulnerability data"""

    def __init__(self, texts, labels, tokenizer, max_length=512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        # Handle both pandas Series and numpy arrays safely
        try:
            text = str(self.texts.iloc[idx])
            label = self.labels.iloc[idx]
        except (AttributeError, TypeError):
            text = str(self.texts[idx])
            label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].flatten(),
            "attention_mask": encoding["attention_mask"].flatten(),
            "labels": torch.tensor(label, dtype=torch.long),
        }


class SecBERTClassifier:
    """SecBERT-based classifier for security severity prediction"""

    def __init__(self, num_labels, model_name="jackaduma/SecBERT"):
        self.model_name = model_name
        self.num_labels = num_labels
        self.tokenizer = None
        self.model = None
        self.label_encoder = LabelEncoder()
        self.trainer = None
        self.device = self._setup_device()
        print(f"Using device: {self.device}")

    def _setup_device(self):
        """Setup optimal device for Apple Silicon"""
        # Disable logging integrations
        os.environ["WANDB_DISABLED"] = "true"
        os.environ["WANDB_MODE"] = "disabled"
        os.environ["TENSORBOARD_DISABLED"] = "true"
        os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
        os.environ["TOKENIZERS_PARALLELISM"] = "false"

        if torch.cuda.is_available():
            device = torch.device("cuda")
            print("Using CUDA GPU")
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = torch.device("mps")
            print("Using Apple Silicon MPS")
        else:
            device = torch.device("cpu")
            print("Using CPU")
            # Optimize CPU for Apple Silicon
            torch.set_num_threads(8)

        return device

    def prepare_model_and_tokenizer(self):
        """Initialize SecBERT tokenizer and model"""
        print(f"Loading {self.model_name} tokenizer and model...")

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name, num_labels=self.num_labels
            )
        except Exception as e:
            print(f"Error loading SecBERT: {e}")
            print("Falling back to BERT...")
            self.model_name = "bert-base-uncased"
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name, num_labels=self.num_labels
            )

        # Add padding token if not present
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        # Move model to device
        self.model = self.model.to(self.device)
        print(f"Model loaded and moved to {self.device}")

    def prepare_datasets(self, df, column, test_size=0.2, val_size=0.1):
        """Split data into train/validation/test sets"""
        print("Preparing train/validation/test splits...")

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(df[column])
        print(f"Label classes: {self.label_encoder.classes_}")

        # Split data - stratified to maintain class distribution
        X_temp, X_test, y_temp, y_test = train_test_split(
            df["text_input"].reset_index(drop=True),
            y_encoded,
            test_size=test_size,
            random_state=42,
            stratify=y_encoded,
        )

        X_train, X_val, y_train, y_val = train_test_split(
            X_temp,
            y_temp,
            test_size=val_size / (1 - test_size),
            random_state=42,
            stratify=y_temp,
        )

        # Ensure proper data types
        X_train = pd.Series(X_train).reset_index(drop=True)
        X_val = pd.Series(X_val).reset_index(drop=True)
        X_test = pd.Series(X_test).reset_index(drop=True)

        y_train = np.array(y_train)
        y_val = np.array(y_val)
        y_test = np.array(y_test)

        print(f"Train size: {len(X_train)} ({len(X_train) / len(df):.1%})")
        print(f"Validation size: {len(X_val)} ({len(X_val) / len(df):.1%})")
        print(f"Test size: {len(X_test)} ({len(X_test) / len(df):.1%})")

        # Create datasets
        train_dataset = SecurityDataset(X_train, y_train, self.tokenizer)
        val_dataset = SecurityDataset(X_val, y_val, self.tokenizer)
        test_dataset = SecurityDataset(X_test, y_test, self.tokenizer)

        return train_dataset, val_dataset, test_dataset

    def compute_metrics(self, eval_pred):
        """Compute metrics for evaluation"""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        return {"accuracy": accuracy_score(labels, predictions)}

    def train_model(
        self, train_dataset, val_dataset, output_dir="etc/models/secbert_model"
    ):
        """Train the SecBERT classification model"""
        print("Starting SecBERT fine-tuning...")

        # Force CPU mode for maximum compatibility with AdamW
        print("Using CPU mode for AdamW compatibility...")
        self.device = torch.device("cpu")
        self.model = self.model.to(self.device)

        # CPU optimized settings
        train_batch_size = 4  # Smaller batch for stability
        eval_batch_size = 8
        dataloader_num_workers = 0  # Avoid multiprocessing issues

        print(f"Batch sizes - Train: {train_batch_size}, Eval: {eval_batch_size}")
        print("Note: Using CPU mode avoids AdamW/MPS compatibility issues")

        # Create training arguments with stable optimizer settings
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=train_batch_size,
            per_device_eval_batch_size=eval_batch_size,
            warmup_steps=100,  # Reduced warmup steps
            weight_decay=0.01,
            learning_rate=2e-5,  # Explicit learning rate
            logging_dir=f"{output_dir}/logs",
            logging_steps=50,  # More frequent logging
            eval_strategy="steps",
            eval_steps=200,  # More frequent evaluation
            save_strategy="steps",
            save_steps=200,
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            greater_is_better=True,
            save_total_limit=2,
            report_to=[],  # No online logging
            remove_unused_columns=False,
            fp16=False,  # Disable mixed precision
            bf16=False,  # Disable bfloat16
            dataloader_num_workers=dataloader_num_workers,
            dataloader_pin_memory=False,  # Disable for CPU
            optim="adamw_torch",  # Use PyTorch AdamW
            seed=42,  # Set seed for reproducibility
            data_seed=42,
            use_cpu=True,  # Force CPU usage
        )

        # Put model in training mode before creating trainer
        self.model.train()

        # Create trainer with error handling
        try:
            self.trainer = Trainer(
                model=self.model,
                args=training_args,
                train_dataset=train_dataset,
                eval_dataset=val_dataset,
                compute_metrics=self.compute_metrics,
                callbacks=[EarlyStoppingCallback(early_stopping_patience=3)],
            )

            print(f"Training {self.model_name} on {self.device}...")

            # Train the model with error handling
            train_result = self.trainer.train()

            # Save everything
            print("Saving trained model...")
            self.trainer.save_model()
            self.tokenizer.save_pretrained(output_dir)

            # Save label encoder
            with open(os.path.join(output_dir, "label_encoder.pkl"), "wb") as f:
                pickle.dump(self.label_encoder, f)

            print(f"Training completed! Model saved to {output_dir}")
            return train_result

        except Exception as e:
            error_msg = str(e)
            print(f"Training error: {error_msg}")

            if "'AdamW' object has no attribute 'train'" in error_msg:
                print("\nAdamW Compatibility Issue Detected")
                print("This is a known issue with certain transformers versions")
                print("Trying fallback training configuration...")

                # Retry with even more conservative settings
                return self._train_with_fallback(train_dataset, val_dataset, output_dir)
            else:
                raise e

    def _train_with_fallback(
        self, train_dataset, val_dataset, output_dir="etc/models/secbert_model"
    ):
        """Fallback training method for AdamW issues"""
        print("Attempting fallback training with conservative settings...")

        # Even more conservative settings
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=2,  # Reduced epochs
            per_device_train_batch_size=2,  # Very small batch
            per_device_eval_batch_size=4,
            warmup_steps=50,
            weight_decay=0.01,
            learning_rate=5e-5,  # Higher learning rate for faster training
            logging_steps=25,
            eval_strategy="epoch",  # Evaluate per epoch instead
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            greater_is_better=True,
            save_total_limit=1,
            report_to=[],
            remove_unused_columns=False,
            fp16=False,
            bf16=False,
            dataloader_num_workers=0,
            dataloader_pin_memory=False,
            optim="sgd",  # Use SGD instead of AdamW
            seed=42,
            data_seed=42,
            use_cpu=True,
        )

        # Create new trainer with fallback settings
        self.trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self.compute_metrics,
        )

        print("Starting fallback training with SGD optimizer...")
        train_result = self.trainer.train()

        # Save everything
        self.trainer.save_model()
        self.tokenizer.save_pretrained(output_dir)

        with open(os.path.join(output_dir, "label_encoder.pkl"), "wb") as f:
            pickle.dump(self.label_encoder, f)

        print(f"Fallback training completed! Model saved to {output_dir}")
        return train_result

    def get_predictions(self, test_dataset):
        # Get predictions
        predictions = self.trainer.predict(test_dataset)
        y_pred = np.argmax(predictions.predictions, axis=1)
        y_true = predictions.label_ids

        target_names = self.label_encoder.classes_
        return y_pred, y_true, target_names

    def predict_severity(self, text):
        """Predict severity for new text"""
        if self.model is None or self.tokenizer is None:
            raise ValueError("Model not trained or loaded!")

        self.model.eval()
        with torch.no_grad():
            inputs = self.tokenizer(
                text, truncation=True, padding=True, max_length=512, return_tensors="pt"
            ).to(self.device)

            outputs = self.model(**inputs)
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
            predicted_class = torch.argmax(predictions, dim=-1).item()
            confidence = torch.max(predictions).item()

        severity = self.label_encoder.inverse_transform([predicted_class])[0]
        return severity, confidence


def main():
    data_dir = os.getenv("AEGIS_ML_CVE_DATA_DIR")
    if not data_dir or not os.path.isdir(data_dir):
        raise FileNotFoundError(
            f"No valid directory provided in ${{AEGIS_ML_CVE_DATA_DIR}}: {data_dir}"
        )

    df = load_and_preprocess_data_from_local(data_dir)

    # add columns for CVSS3 base metrics
    for cvss3_metric in CVSS3_BASIC_METRICS:
        df[cvss3_metric] = df["cvss_scores"].apply(
            extract_cvss3_metric, cvss3_metric=cvss3_metric
        )

    # drop rows where CVSS3_BASIC_METRICS fields are not available
    df = df.dropna(subset=CVSS3_BASIC_METRICS)

    # drop rows where assigned impact does not match CVSS3 score
    df["impact_clean"] = df.apply(check_cvss3_impact, axis=1)
    df = df.dropna(subset=["impact_clean"])

    # enforce meaningful ordering
    impact_labels = ["LOW", "MODERATE", "IMPORTANT", "CRITICAL"]
    label_encoder = LabelEncoder()
    label_encoder.classes_ = np.array(impact_labels)

    # Split data - stratified to maintain class distribution
    y_encoded = label_encoder.transform(df["impact_clean"])
    df, df_test, _, _ = train_test_split(
        df,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    classifier_by_metric = {}

    for cvss3_metric in CVSS3_BASIC_METRICS:
        # Initialize classifier
        num_labels = df[cvss3_metric].nunique()
        classifier = SecBERTClassifier(num_labels)

        print(
            f"\n\nTraining {cvss3_metric}, num_labels = {num_labels}, rows = {len(df)}"
        )
        print(f"Impact distribution: {df[cvss3_metric].value_counts()}")

        classifier.prepare_model_and_tokenizer()
        train_dataset, val_dataset, test_dataset = classifier.prepare_datasets(
            df, cvss3_metric
        )

        classifier.train_model(
            train_dataset,
            val_dataset,
            output_dir=f"./etc/models/secbert_model/{cvss3_metric}",
        )

        print("Evaluating model on test set...")
        y_pred, y_true, target_names = classifier.get_predictions(test_dataset)
        evaluate_model(
            y_pred,
            y_true,
            target_names,
            show_plots=False,
            file_prefix=f"./etc/{cvss3_metric}-",
        )
        classifier_by_metric[cvss3_metric] = classifier

    # create a new column with the predicted impact based on the predicted CVSS3 base metrics
    df_test["pred_impact"] = df_test.apply(
        compute_pred_impact, axis=1, classifier_by_metric=classifier_by_metric
    )

    # Prepare expected/actual output
    y_pred = label_encoder.transform(df_test["pred_impact"])
    y_true = label_encoder.transform(df_test["impact_clean"])

    # Overall evaluation
    accuracy, report, cm = evaluate_model(y_pred, y_true, impact_labels)

    # Test sample predictions
    print("SAMPLE PREDICTIONS:")
    print("=" * 60)

    # Pick 4 random inputs from df_test
    sample_texts = df_test["text_input"].sample(n=4)

    for i, text in enumerate(sample_texts, 1):
        print(f"\n{i}. Text: {text}")
        cvss3_str = "CVSS:3.1"
        for cvss3_metric in CVSS3_BASIC_METRICS:
            classifier = classifier_by_metric[cvss3_metric]
            value, confidence = classifier.predict_severity(normalize_text(text))
            print(
                f"   Predicted {cvss3_metric}: {value} (confidence: {confidence:.3f})"
            )
            cvss3_str += f"/{cvss3_metric}:{value[0]}"

        print(f"   Predicted CVSS3 vector: {cvss3_str}")
        cvss3 = cvss.CVSS3(cvss3_str)
        cvss3_score = cvss3.scores()[0]
        print(f"   Predicted CVSS3 score: {cvss3_score}")
        print(f"   Predicted impact: {impact_by_cvss3_score(cvss3_score)}")

    # Final results
    print(f"\n{'=' * 60}")
    print("FINAL RESULTS")
    print("=" * 60)
    print(f"Model: {classifier.model_name}")
    print(f"Test Accuracy: {accuracy:.4f} ({accuracy:.1%})")
    print(f"Target Classes: {list(classifier.label_encoder.classes_)}")

    print("\n Output files:")
    print("  • ./etc/models/secbert_model/ - Trained model and tokenizer")
    print("  • secbert_confusion_matrix.png - Performance visualization")


if __name__ == "__main__":
    main()
