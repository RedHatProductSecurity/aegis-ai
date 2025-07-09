all: check test

install:
	pip install . --force

run-chat:
	uv run uvicorn aegis_chat.chat_app:app --port 9001 --reload

run-web:
	uv run uvicorn aegis_web.main:app --port 9000 --reload

run-vllm:
	vllm serve RedHatAI/Mistral-Small-24B-Instruct-2501-quantized.w4a16 --max_model_len 4048 --enable-auto-tool-choice --tool-call-parser mistral --enable-reasoning  --dtype auto --gpu-memory-utilization .96 --quantization compressed-tensors

run-pgvector:
	cd etc/deploy && podman-compose up --build

############################################################################
# dev
############################################################################
lint:
	uvx ruff check

format:
	uvx ruff format

check: format lint

clean:
	uv clean

test:
	uv run pytest

upgrade-deps:
	uv sync --upgrade

############################################################################
# container
############################################################################
build-container: Containerfile
	podman build --build-arg REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE}" \
					--build-arg PIP_INDEX_URL="${PIP_INDEX_URL}" \
					--build-arg ROOT_CA_URL="${ROOT_CA_URL}" \
					--tag localhost/aidest .
run-container:
	podman run --privileged -it -v /etc/krb5.conf:/etc/krb5.conf -p 5000:5000 localhost/aidest
