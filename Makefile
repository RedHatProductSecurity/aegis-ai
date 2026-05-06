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

generate-kernel-eval:
	uv run python evals/features/cve/generate_kernel_eval_csv.py

refresh-kernel-osidb-cache:
	uv run python evals/features/cve/generate_kernel_eval_csv.py --refresh-cache

# populate-kernel-caches reads CVE IDs from eval-kernel-cves.csv (output of
# generate-kernel-eval).  Run prepare-kernel-eval instead of calling this
# target directly to ensure the CSV is generated first.
populate-kernel-caches:
	uv run python evals/utils/populate_kernel_cve_cache.py --from-eval-csv

prepare-kernel-eval: generate-kernel-eval populate-kernel-caches

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
	$(MAKE) -C $(KERNEL_CLF_DIR) retrain $(if $(RETUNE),RETUNE=1)

test-kernel:
	$(MAKE) -C $(KERNEL_CLF_DIR) test


############################################################################
# container
############################################################################
build-container: Containerfile
	podman build --build-arg PIP_INDEX_URL="${PIP_INDEX_URL}" \
		     --build-arg RH_CERT_URL=${RH_CERT_URL} \
		     --tag aegis-ai .

run-container:
	podman run --rm -it -v /etc/krb5.conf:/etc/krb5.conf -p 9000:9000 localhost/aegis-ai:latest scripts/run_web_service.sh

