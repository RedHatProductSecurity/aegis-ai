PYTHON ?= python

all: check test test-web

install:
	pip install . --force

run-web:
	uv run uvicorn aegis_ai_web.src.main:app --port 9000 --reload --loop uvloop --http httptools

run-vllm:
	vllm serve RedHatAI/Mistral-Small-24B-Instruct-2501-quantized.w4a16 --max_model_len 4048 --enable-auto-tool-choice --tool-call-parser mistral --enable-reasoning  --dtype auto --gpu-memory-utilization .96 --quantization compressed-tensors

run-otel:
	podman run --rm -it -p 4318:4318 --name otel-tui ymtdzzz/otel-tui:latest

############################################################################
# dev
############################################################################
lint:
	uvx ruff check

format:
	uvx ruff format

check-type: fetch-deps
	uvx ty check --exclude src/aegis_ai_ml
    
check: format lint check-type

clean:
	uv clean

eval:
	uv run pytest -vv -s --show-capture=no evals

# The eval-debug target enforces single-job concurrency for debugging purposes
# by setting AEGIS_LLM_MAX_JOBS=1. This ensures only one job runs at a time.
eval-debug:
	AEGIS_LLM_MAX_JOBS=1 uv run pytest -vv -s -o log_cli_level=DEBUG --show-capture=no evals

eval-in-parallel:
	uv run pytest -vv -n auto evals

test:
	uv run pytest tests

test-web:
	uv run pytest src/aegis_ai_web/tests

fetch-deps:
	uv sync --frozen

upgrade-deps:
	uv sync --upgrade

install-ml-deps: upgrade-deps
	uv pip install .[ml_deps]

build-dist:
	uv run $(PYTHON) -m build

publish-dist:
	uv run $(PYTHON) -m twine upload dist/*


############################################################################
# kernel classifier
############################################################################
KERNEL_CLF_DIR = src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier

retrain-kernel:
	cd $(KERNEL_CLF_DIR) && uv run python cve_data_scraper.py
	cd $(KERNEL_CLF_DIR) && uv run python cve_feature_extraction.py
	cd $(KERNEL_CLF_DIR) && uv run python fetch_cvss_cwe.py
	cd $(KERNEL_CLF_DIR) && uv run python split_datasets_for_train_test.py
	cd $(KERNEL_CLF_DIR) && uv run python cve_smote_balancer.py
	cd $(KERNEL_CLF_DIR) && uv run python xgboost_train.py
	cd $(KERNEL_CLF_DIR) && uv run python test_cve_model.py

test-kernel:
	cd $(KERNEL_CLF_DIR) && uv run python test_cve_model.py


############################################################################
# container
############################################################################
build-container: Containerfile
	podman build --build-arg PIP_INDEX_URL="${PIP_INDEX_URL}" \
		     --build-arg RH_CERT_URL=${RH_CERT_URL} \
		     --tag aegis-ai .

run-container:
	podman run --rm -it -v /etc/krb5.conf:/etc/krb5.conf -p 9000:9000 localhost/aegis-ai:latest scripts/run_web_service.sh

