from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aegis.agents import feature_agent, component_feature_agent
from aegis.features import cve, component
from . import AEGIS_REST_API_VERSION
from aegis.rag import add_fact_to_vector_store
from aegis.rag.data_models import FactInput

app = FastAPI(
    title="Aegis REST API",
    description="A simple web console for building and testing LLM prompts with Jinja2 templating.",
    version=AEGIS_REST_API_VERSION,
)

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Setup  for serving HTML
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/console", response_class=HTMLResponse)
async def console(request: Request):
    return templates.TemplateResponse("console.html", {"request": request})


@app.post("/generate_response")
async def generate_response(request: Request):
    """
    Handles the submission of a prompt, simulates an LLM response,
    and re-renders the console with the results.
    """
    user_prompt = request.form().__dict__.get("user_prompt")

    # --- Simulate LLM Response ---
    # In a real application, you would make an API call to an LLM here.
    # For this simple example, we'll just echo the prompt and add a prefix.
    if user_prompt:
        llm_response = f"Simulated LLM Response: You asked '{user_prompt}'. This is a placeholder response."
    else:
        llm_response = "Please enter a prompt."

    # Render the template again, passing the user's prompt and the simulated response
    return templates.TemplateResponse(
        "console.html",
        {"request": request, "user_prompt": user_prompt, "llm_response": llm_response},
    )


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/cve/suggest/impact/{{cve_id}}",
    response_class=JSONResponse,
)
async def cve_suggest_impact(cve_id: str):
    feature = cve.SuggestImpact(feature_agent)
    result = await feature.exec(cve_id)
    if result:
        return result.output
    return {}


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/cve/suggest/cwe/{{cve_id}}",
    response_class=JSONResponse,
)
async def cve_suggest_cwe(cve_id: str):
    feature = cve.SuggestCWE(feature_agent)
    result = await feature.exec(cve_id)
    if result:
        return result.output
    return {}


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/cve/identify/pii/{{cve_id}}",
    response_class=JSONResponse,
)
async def cve_identify_pii(cve_id: str):
    feature = cve.IdentifyPII(feature_agent)
    result = await feature.exec(cve_id)
    if result:
        return result.output
    return {}


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/cve/rewrite/description/{{cve_id}}",
    response_class=JSONResponse,
)
async def cve_rewrite_description(cve_id: str):
    feature = cve.RewriteDescriptionText(feature_agent)
    result = await feature.exec(cve_id)
    if result:
        return result.output
    return {}


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/cve/rewrite/statement/{{cve_id}}",
    response_class=JSONResponse,
)
async def cve_rewrite_statement(cve_id: str):
    feature = cve.RewriteStatementText(feature_agent)
    result = await feature.exec(cve_id)
    if result:
        return result.output
    return {}


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/cve/explain_cvss_diff/{{cve_id}}",
    response_class=JSONResponse,
)
async def cve_explain_diff(cve_id: str):
    feature = cve.CVSSDiffExplainer(feature_agent)
    result = await feature.exec(cve_id)
    if result:
        return result.output
    return {}


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/component/intelligence/{{component_name}}",
    response_class=JSONResponse,
)
async def component_intelligence(component_name: str):
    feature = component.ComponentIntelligence(component_feature_agent)
    result = await feature.exec(component_name)
    if result:
        return result.output
    return {}


@app.post(f"/api/{AEGIS_REST_API_VERSION}/kb/add-fact")
async def kb_add_fact(fact_data: FactInput):
    try:
        add_fact_to_vector_store(fact_data)
        return {"message": "Fact added successfully to Aegis."}
    except Exception as e:
        return {"error": f"Failed to add fact: {str(e)}"}, 500


@app.post(f"/api/{AEGIS_REST_API_VERSION}/kb/add-document")
async def kb_add_document(fact: str):
    add_fact_to_vector_store(FactInput(fact=fact, metadata={"source": "aegis"}))
