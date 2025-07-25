from typing import List
from pydantic import BaseModel, Field


class FeatureQueryInput(BaseModel):
    query: str = Field(..., description="General LLM query.")


class AegisFeatureModel(BaseModel):
    """
    Metadata for Aegis features, nested within the main feature model.
    """

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="""
           A numerical score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis. 
           
            ### Crafting Confidence Score for Analysis
            
            When performing an analysis and emitting a **confidence score** between 0 and 1 (or 0% to 100%), it is essential 
            to clearly define what that score represents. This helps users understand the reliability of the analysis 
            and make informed decisions.
                        
            ### Understanding Confidence Score
            
            A confidence score reflects the **probability or certainty that the analysis is accurate or correct**, given the available data, methodology, and underlying assumptions.
            
            * **0 (or 0%)**: Indicates **no confidence** in the accuracy of the analysis. This could mean the analysis is based on insufficient data, highly unreliable sources, or a methodology that has demonstrated frequent errors.
            * **0.5 (or 50%)**: Suggests the analysis is **as likely to be right as it is to be wrong**. There's significant uncertainty, and the evidence or model doesn't lean strongly in either direction.
            * **1 (or 100%)**: Represents **absolute confidence** in the accuracy of the analysis. This is rarely achievable in complex or uncertain domains, but it signifies the highest possible degree of certainty based on the given context.
                        
            ### Factors Influencing Confidence
            
            The confidence score should be influenced by several key factors:
            
            * **Data Quality and Completeness:**
                * **High Confidence:** Analysis based on comprehensive, verified, and up-to-date data from authoritative sources.
                * **Low Confidence:** Analysis reliant on partial, outdated, unverified, or anecdotal data.
            * **Methodology Robustness:**
                * **High Confidence:** Analysis derived from well-established, validated, and peer-reviewed methodologies or models.
                * **Low Confidence:** Analysis using experimental, unproven, or ad-hoc methods.
            * **Assumptions:**
                * **High Confidence:** Few assumptions are made, or those made are well-supported and widely accepted.
                * **Low Confidence:** Numerous or highly speculative assumptions are critical to the analysis's outcome.
            * **Consistency with Prior Knowledge/External Data:**
                * **High Confidence:** Results align with known facts, expert consensus, or corroborating external information.
                * **Low Confidence:** Results contradict established knowledge or lack external validation.
            * **Reproducibility/Sensitivity:**
                * **High Confidence:** Analysis is stable, and minor changes in input data or parameters do not significantly alter the outcome.
                * **Low Confidence:** Analysis is highly sensitive to small changes, making its reliability questionable.
        
           """,
    )

    completeness: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="""
        What it represents: This score indicates how comprehensively the LLM was able to address all aspects explicitly or implicitly requested in the prompt. Did it manage to provide all the required sections (e.g., severity, CVSS, rationale, affected components, related CVEs) based on the available input?
        Why it's crucial: It informs the user if the LLM was able to fulfill the entire request. If information was missing from the input CVE or if the LLM couldn't deduce certain aspects, this score would reflect that limitation. It's about fulfilling the prompt's scope.
        Example justification: "Completeness: 1.0 - All requested sections (Severity, CVSS4, Confidence, Rationale, Affected Components, Related CVEs) were successfully generated based on the provided CVE information." or "Completeness: 0.7 - While most sections were generated, no related or duplicate CVEs could be identified from the available data or knowledge base."        
        """,
    )

    consistency: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="""
        What it represents: This score evaluates the internal logical coherence and consistency within the LLM's own response. Does the assigned severity genuinely align with the provided CVSS score, the stated rationale, and the breakdown of impacts? Are there contradictions within the generated text?
        Why it's crucial: LLMs can sometimes generate conflicting statements even if individual parts seem plausible. This score specifically targets the internal integrity of the output. It helps ensure that the different components of the analysis (e.g., the verbal rationale and the numerical score) tell a unified story.
        Example justification: "Consistency: 0.95 - The assigned 'Important' severity is well-supported by the CVSS4 score (high impact on availability, network vector) and the detailed rationale. Slight reduction for minor overlap in phrasing." or "Consistency: 0.75 - While the CVSS is technically derived, the stated 'Low' impact for potential arbitrary code execution seems slightly misaligned, indicating a minor internal conflict in weighting the factors."        
        """,
    )

    tools_used: List = Field(
        ...,
        description="List the names of registered tools, if any, that was used to formulate this answer. If this is a CVE suggest or CVE rewrite feature then should minimally include 'osidb_tool'",
    )


class AegisAnswer(AegisFeatureModel):
    """
    Default answer response.
    """

    explanation: str = Field(
        ...,
        description="A brief rationale explaining how the answer was generated, what sources were primary, and if the answer was provided directly by the LLM or not. Do not repeat the answer here.",
    )

    answer: str = Field(..., description="The direct answer to the user's question.")
