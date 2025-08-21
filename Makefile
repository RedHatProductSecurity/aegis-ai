PYTHON ?= python

all: check test test-web

install:
	pip install . --force

run-chat:
	uv run uvicorn aegis_ai_chat.src.chat_app:app --port 9001 --reload

run-web:
	uv run uvicorn aegis_ai_web.src.main:app --port 9000 --reload

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

check-type:
	uvx ty check
    
check: format lint check-type

clean:
	uv clean

eval:
	LOGFIRE_IGNORE_NO_CONFIG=1 uv run pytest -vv -s evals

eval-in-parallel:
	LOGFIRE_IGNORE_NO_CONFIG=1 uv run pytest -vv -n auto evals

test:
	uv run pytest tests

test-web:
	uv run pytest src/aegis_ai_web/tests

upgrade-deps:
	uv sync --upgrade

install-ml-deps:
	uv pip install .[ml_deps]
	uv run $(PYTHON) -c 'from src.aegis_ai_ml.src import util; util.install_nltk_deps()'

build-dist:
	uv run $(PYTHON) -m build

publish-dist:
	uv run $(PYTHON) -m twine upload dist/*


############################################################################
# container
############################################################################
build-container: Containerfile
	podman build --build-arg REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE}" \
					--build-arg PIP_INDEX_URL="${PIP_INDEX_URL}" \
					--build-arg ROOT_CA_URL="${ROOT_CA_URL}" \
					--tag localhost/aigest .
run-container:
	podman run --privileged -it -v /etc/krb5.conf:/etc/krb5.conf -p 5000:5000 localhost/aigest
