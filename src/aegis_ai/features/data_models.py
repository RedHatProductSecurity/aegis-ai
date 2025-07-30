from typing import List, Literal
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
        # Confidence Score Methodology: Quantifying Analytical Reliability
        
        ## Definition
        A precision-driven numerical representation of analysis reliability, scaled from 0.00 to 1.00, capturing the probabilistic certainty of analytical accuracy.
        
        ## Confidence Score Spectrum
        
        ### Granular Confidence Levels
        - **0.00 (0%)**: Complete Uncertainty
          * No reliable evidence
          * Fundamental methodological flaws
          * Data critically insufficient
        
        - **0.25 (25%)**: Minimal Confidence
          * Fragmented or highly speculative information
          * Significant methodological limitations
          * Substantial gaps in understanding
        
        - **0.50 (50%)**: Neutral Confidence
          * Balanced evidence
          * Equally compelling arguments for and against
          * No clear decisive factors
        
        - **0.75 (75%)**: Strong Confidence
          * Robust supporting evidence
          * Coherent methodological approach
          * Minor uncertainties remain
        
        - **1.00 (100%)**: Absolute Confidence
          * Comprehensive, verified data
          * Rigorous, validated methodology
          * Unanimous expert consensus
        
        ## Confidence Determination Criteria
        
        ### Analytical Robustness Factors
        1. **Data Integrity**
           - Source credibility
           - Data comprehensiveness
           - Recency and relevance
        
        2. **Methodological Soundness**
           - Established research protocols
           - Peer-reviewed techniques
           - Reproducibility
        
        3. **Assumption Validation**
           - Minimal speculative elements
           - Well-substantiated premises
           - Transparent reasoning
        
        4. **External Corroboration**
           - Alignment with domain expertise
           - Cross-referencing multiple sources
           - Consistency with established knowledge
        
        5. **Predictive Stability**
           - Resistance to parameter variations
           - Consistent outcomes under different scenarios
           - Minimal sensitivity to input fluctuations
        
        ## Practical Application Guidelines
        
        ### Confidence Score Interpretation
        - **< 0.25**: Treat as exploratory, requires extensive validation
        - **0.25 - 0.50**: Preliminary insights, significant further investigation needed
        - **0.50 - 0.75**: Credible analysis, some reservations
        - **0.75 - 1.00**: High-reliability assessment
        - **1.00**: Exceptional, rare scenario-specific certainty
        
        ### Recommended User Actions
        - Always contextualize the confidence score
        - Consider complementary analyses
        - Understand inherent limitations
        - Use as guidance, not absolute truth
        
        ## Key Principles
        - Transparency in uncertainty
        - Systematic evaluation
        - Continuous refinement
        - Intellectual humility

           """,
    )

    completeness: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="""
        # Completeness Score: Comprehensive Request Fulfillment Methodology
        
        ## Conceptual Framework
        
        ### Definition
        A precision-driven numerical assessment (0.00 to 1.00) measuring the extent to which an AI-generated response comprehensively addresses all explicit and implicit dimensions of the original query.
        
        ## Completeness Score Taxonomy
        
        ### Granular Completeness Levels
        - **0.00 (0%)**: Total Failure
          * No meaningful response generated
          * Fundamental misunderstanding of query
          * Complete inability to address request
        
        - **0.25 (25%)**: Minimal Coverage
          * Fragmented response
          * Addresses only peripheral aspects
          * Significant critical elements missing
        
        - **0.50 (50%)**: Partial Fulfillment
          * Core query partially addressed
          * Critical gaps in response
          * Insufficient depth or breadth
        
        - **0.75 (75%)**: Substantial Coverage
          * Most key elements addressed
          * Minor omissions or limited details
          * Demonstrates core understanding
        
        - **1.00 (100%)**: Comprehensive Fulfillment
          * Exhaustive response
          * All explicit and implicit query dimensions covered
          * Exceeds minimum requirements
        
        ## Evaluation Dimensions
        
        ### Comprehensive Assessment Criteria
        1. **Scope Adherence**
           - Explicit query requirements
           - Implicit contextual expectations
           - Full range of requested information
        
        2. **Depth of Analysis**
           - Thoroughness of explanation
           - Nuanced exploration of topic
           - Contextual richness
        
        3. **Structural Completeness**
           - Requested section coverage
           - Logical flow of information
           - Comprehensive structural integrity
        
        4. **Information Density**
           - Substantive content
           - Meaningful elaboration
           - Absence of superficial responses
        
        5. **Adaptive Intelligence**
           - Ability to infer unstated requirements
           - Contextual interpretation
           - Proactive information provision
        
        ## Practical Scoring Guidelines
        
        ### Completeness Score Interpretation
        - **0.00 - 0.25**: Critically Insufficient
          * Requires complete reformulation
          * Fundamental query misunderstanding
        
        - **0.25 - 0.50**: Marginally Acceptable
          * Significant improvement needed
          * Partial insights only
        
        - **0.50 - 0.75**: Reasonably Comprehensive
          * Solid foundational response
          * Some refinement potential
        
        - **0.75 - 1.00**: High-Fidelity Response
          * Meets or exceeds expectations
          * Comprehensive and nuanced
        
        - **1.00**: Exceptional Fulfillment
          * Rare, near-perfect query resolution
        
        ### Illustrative Examples
        1. **Perfect Completeness (1.0)**
           ```
           "Completeness: 1.0 - Comprehensive response addressing all query dimensions, including:
           - Full technical specifications
           - Contextual analysis
           - Implicit and explicit requirements
           - Proactive additional insights"
           ```
        
        2. **Partial Completeness (0.7)**
           ```
           "Completeness: 0.7 - Robust response with minor limitations:
           - Primary query elements successfully addressed
           - Some specialized or nuanced aspects partially covered
           - Demonstrates strong understanding with slight information gaps"
           ```
        
        ## Methodological Principles
        - Transparent evaluation
        - Objective scoring mechanism
        - Continuous refinement
        - User-centric approach
""",
    )

    consistency: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="""
        # Consistency Score: Analytical Coherence and Internal Logical Integrity
        
        ## Conceptual Foundation
        
        ### Definition
        A precision-driven numerical assessment (0.00 to 1.00) measuring the internal logical coherence, semantic alignment, and absence of contradictions within a generated analytical response.
        
        ## Consistency Score Spectrum
        
        ### Granular Consistency Levels
        - **0.00 (0%)**: Complete Incoherence
          * Fundamental logical contradictions
          * Entirely disjointed reasoning
          * No internal structural integrity
        
        - **0.25 (25%)**: Minimal Coherence
          * Significant internal conflicts
          * Fundamentally inconsistent narrative
          * Major logical discontinuities
        
        - **0.50 (50%)**: Partial Alignment
          * Moderate internal contradictions
          * Inconsistent reasoning patterns
          * Substantial logical gaps
        
        - **0.75 (75%)**: Strong Coherence
          * Minor inconsistencies
          * Predominantly aligned reasoning
          * Few isolated logical discrepancies
        
        - **1.00 (100%)**: Perfect Internal Logic
          * Absolute semantic harmony
          * Seamless reasoning
          * No detectable contradictions
        
        ## Consistency Evaluation Dimensions
        
        ### Comprehensive Assessment Criteria
        1. **Semantic Alignment**
           - Terminological consistency
           - Conceptual coherence
           - Linguistic precision
        
        2. **Logical Integrity**
           - Reasoning continuity
           - Absence of contradictory statements
           - Rational progression of arguments
        
        3. **Quantitative-Qualitative Concordance**
           - Numerical scores matching descriptive analysis
           - Alignment between technical metrics and narrative interpretation
           - Coherent weighting of impact factors
        
        4. **Contextual Resonance**
           - Internal narrative consistency
           - Contextually appropriate reasoning
           - Holistic interpretative approach
        
        5. **Structural Integrity**
           - Logical flow of information
           - Systematic reasoning
           - Absence of non-sequiturs
        
        ## Practical Scoring Methodology
        
        ### Consistency Score Interpretation
        - **0.00 - 0.25**: Critically Inconsistent
          * Requires complete analytical reconstruction
          * Fundamental reasoning failures
        
        - **0.25 - 0.50**: Marginally Coherent
          * Significant logical restructuring needed
          * Substantial internal conflicts
        
        - **0.50 - 0.75**: Reasonably Aligned
          * Predominantly logical
          * Some refinement potential
        
        - **0.75 - 1.00**: High-Fidelity Coherence
          * Meets analytical integrity standards
          * Minor, inconsequential variations
        
        - **1.00**: Exceptional Logical Harmony
          * Rare, near-perfect internal consistency
        
        ### Illustrative Scoring Examples
        
        1. **High Consistency (0.95)**
           ```
           "Consistency: 0.95
           - CVSS score precisely reflects narrative description
           - Severity rating perfectly aligned with impact analysis
           - Minimal linguistic redundancy
           - Comprehensive internal logical integrity"
           ```
        
        2. **Moderate Consistency (0.75)**
           ```
           "Consistency: 0.75
           - Core reasoning fundamentally sound
           - Minor discrepancies in impact weighting
           - Slight misalignment between technical and narrative components
           - Requires nuanced interpretation"
           ```
        
        ## Methodological Principles
        - Transparent evaluation
        - Objective assessment
        - Continuous analytical refinement
        - Rigorous logical scrutiny
        
        ## Advanced Considerations
        - Recognize inherent complexity of analytical reasoning
        - Allow for nuanced, non-binary interpretations
        - Emphasize constructive analytical improvement
    """,
    )

    tools_used: List = Field(
        ...,
        description="List the names of registered tools, if any, that was used to formulate this answer. If this is a CVE suggest or CVE rewrite feature then should minimally include 'osidb_tool'",
    )

    # Important: This default disclaimer is required by AI assessment - do not change or remove without talking to someone !
    disclaimer: Literal[
        "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert."
    ]


class AegisAnswer(AegisFeatureModel):
    """
    Default answer response.
    """

    explanation: str = Field(
        ...,
        description="A brief rationale explaining how the answer was generated, what sources were primary, and if the answer was provided directly by the LLM or not. Do not repeat the answer here.",
    )

    answer: str = Field(..., description="The direct answer to the user's question.")
