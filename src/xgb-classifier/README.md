# CVE Severity XGBoost Classifier

XGBoost classifier for predicting Linux kernel CVE severity levels based on patch analysis and feature engineering.

## Overview

This classifier predicts CVE severity into three categories:
- **IMPORTANT (0)**: High severity vulnerabilities requiring immediate attention
- **MODERATE (1)**: Medium severity vulnerabilities  
- **LOW (2)**: Low severity vulnerabilities

## Data Pipeline & Feature Engineering

The training data is constructed through a multi-step process:

1. **CVE Data Collection**: Scrapes Linux kernel CVE metadata from security repositories
2. **Commit & Patch Retrieval**: Fetches actual commit patches and details from the Linux kernel Git repository
3. **Feature Engineering**: Analyzes patch content and commit messages to extract 48 binary features:
   - **File Path Analysis**: Detects component types (networking, hardware, disk, etc.)
   - **Patch Content Analysis**: Scans for security indicators (kasan, uaf, nullptr, danger, etc.)
   - **Code Pattern Analysis**: Examines code changes (lock, memory, timer, init patterns)
   - **Metadata Features**: CVE timing, author info, and fix detection patterns

The result is a structured dataset where each CVE becomes a row with 48 binary features + severity label, ready for ML training.

## Training Process

The XGBoost classifier:
1. Loads the engineered feature dataset
2. Converts TRUE/FALSE values to binary (1/0)
3. Trains on all available data using balanced class weights
4. Saves the trained model, metadata, and feature importance rankings

## Usage

```bash
# Train the model (from project root)
uv run python src/xgb-classifier/xgboost-train.py
```

## Model Outputs

Training generates files in the `models/` directory:
- `cve_severity_model.pkl` - Trained XGBoost model
- `model_metadata.json` - Model configuration and feature list
- `feature_importance.csv` - Feature importance rankings

## Model Configuration

- **Algorithm**: XGBoost Classifier
- **Estimators**: 200 trees
- **Max depth**: 6
- **Learning rate**: 0.1
- **Class weights**: Balanced (handles severity imbalance)
- **Features**: 48 binary features from patch analysis

## Sample Data

`sample_data/sample_data.csv` contains 5 example CVEs showing the expected data format after feature engineering. For production training, update the `data_path` in the script to point to your full engineered dataset.
