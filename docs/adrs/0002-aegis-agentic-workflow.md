# ADR 00002: Aegis Agentic Workflow

**Date:** 2025-07-07

## Status

Accepted

## Context

Agentic workflows can span across a wide range of complexity:

* Single agent workflow — simple, linear, single model, with or without tooling
* Agent delegation — Multiple subagents using with or without tooling 
* Programmatic hand-off— one agent runs, then application code calls another agent 
* Graph based control flow — for the most complex cases, a graph-based state machine can be used to control the execution of multiple agents

One example of a simple, linear workflow using multiple subagents which use different LLM models and tool calls is as follows.

![img.png](workflow.png)

### Requirements

Our Aegis workflows **SHOULD** enable simple workflows with each step running independent to the other, orchestrated by a top level 
workflow agent.

A simple _feature_ workflow might look like:

1. Aegis Feature agent(s) perform analysis with tool calling
   1. run subagents with specific model and access to set of tools
   2. aggregate results
2. Aegis workflow agent performs PII analysis  
3. Aegis workflow agent aggregates/composites results

Where the **workflow agent** is in control of the overall 'execution loop' of the workflow. Ideally this agent (and underlying LLM)
should be mediated with internal assets (internal tools, context, LLM).

Each stage/step of the workflow **SHOULD** be free to invoke a different subagent suited for the step task.

* Internal tooling could be only invoked by an internal subagent
* External tooling could be only invoked by an external subagent
* We can choose which context 'bleeds' over to which steps (or not)

## Decision

When required we **SHOULD** consider implementing simple agentic workflow abstraction such as the following:

```python
class StepStatus(str, Enum):
    """
    Define possible statuses for an individual workflow step.
    """

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowStatus(str, Enum):
    """
    Define possible statuses for an Aegis workflow.
    """

    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkflowStep(BaseModel):
    """
    Defines a single step in agentic workflow.
    """

    name: str = Field(
        ...,
        description="A human-readable name for the step (e.g., 'Gather Initial Data', 'Perform Data Analysis').",
    )
    description: str = Field(
        ..., description="A detailed description of the objective for this step."
    )
    responsible_agent: object = Field(
        ..., description="The agent responsible for executing this step."
    )
    feature: object = Field(..., description="Feature to be run by step agent.")
    status: StepStatus = Field(
        StepStatus.PENDING, description="The current status of the workflow step."
    )
    output: Any = Field(
        None,
        description="Workflow final output.",
    )


class Workflow(BaseModel):
    """
    The top-level agentic workflow object, controlled by the Aegis agent orchestrator.
    """

    name: str = Field(
        "Aegis Workflow", description="The name of the overall agentic workflow."
    )
    description: str = Field(
        ...,
        description="A high-level description of what this workflow aims to achieve.",
    )

    aegis_agent: object = Field(
        ...,
        description="The top-level 'Aegis' orchestrating agent responsible for managing the workflow execution.",
    )

    steps: List[WorkflowStep] = Field(
        ..., description="An ordered list of steps that constitute this workflow."
    )

    shared_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="A dictionary to hold shared data and state across all workflow steps.",
    )

    current_step_index: int = Field(
        0,
        description="The index of the current step being executed in the workflow_steps list.",
    )

    status: WorkflowStatus = Field(
        WorkflowStatus.INITIALIZED,
        description="The overall status of the Aegis workflow.",
    )

    output: Any = Field(
        None,
        description="Workflow final output.",
    )


async def process_workflow_step(input, step: WorkflowStep) -> Any:
    """
    Process single workflow step.
    """
    logger.info(f"Workflow Step: {step.name} ---")
    logger.info(f"Workflow Step Agent: {step.responsible_agent.name}")
    logger.info(f"Workflow Step Description: {step.description}")
    try:
        return await step.feature(step.responsible_agent).exec(input)
    except Exception as e:
        logger.error(f"Step {step.name} FAILED, {e}")
        return StepStatus.FAILED


async def process_workflow(workflow: Workflow, starting_input) -> Workflow:
    """
    Process workflow.
    """

    logger.info(f"Workflow: {workflow.name} ---")
    logger.info(f"Workflow Agent: {workflow.aegis_agent.name}")
    workflow.status = WorkflowStatus.RUNNING

    # We cannot use 'await' with functools.reduce so we use the lowly loop
    for index, step in enumerate(workflow.steps):
        step.status = StepStatus.IN_PROGRESS
        if index == 0:
            output = starting_input
        output = await process_workflow_step(output, step)
        step.status = StepStatus.COMPLETED
        if output is StepStatus.FAILED:
            step.status = StepStatus.FAILED

    workflow.output = output
    workflow.status = WorkflowStatus.COMPLETED
    return workflow


async def process_feature_workflow(feature, starting_input) -> Workflow:
    """
    Process feature workflow.
    """
    feature_step = WorkflowStep(
        name="feature",
        description="Perform feature",
        responsible_agent=context_agent,
        feature=feature,
    )
    eval_step = WorkflowStep(
        name="pii_analysis",
        description="Perform PII analysis",
        responsible_agent=workflow_agent,
        feature=evaluation.IdentifyPII,
    )

    feature_workflow = Workflow(
        name="FeatureWorkflow",
        description="Feature workflow.",
        aegis_agent=workflow_agent,
        steps=[feature_step, eval_step],
    )
    return await process_workflow(feature_workflow, starting_input)
```
Which allow us to define steps with different agents (which have different models and available tooling).

Steps are free to invoke other functions or other machine learning methods (not necc LLM queries).

Conditions (including branching) determining how we transition from step to step should be driven by actual workflows.

Tests for the above might look like:
```python
async def test_workflow(allow_model_requests):
    feature_step = WorkflowStep(
        name="component_intelligence",
        description="Perform component intelligence feature",
        responsible_agent=context_agent,
        feature=component.ComponentIntelligence,
    )
    eval_step = WorkflowStep(
        name="pii_analysis",
        description="Perform PII analysis",
        responsible_agent=workflow_agent,
        feature=evaluation.IdentifyPII,
    )

    feature_workflow = Workflow(
        name="FeatureWorkflow",
        description="Feature workflow.",
        aegis_agent=workflow_agent,
        steps=[feature_step, eval_step],
    )

    feature_workflow.shared_context["date"] = "01/07/2025"

    processed_workflow = await process_workflow(
        feature_workflow, {"component_name": "wget"}
    )

    logging.debug(processed_workflow)

    assert_equal(processed_workflow.status, WorkflowStatus.COMPLETED)


async def test_workflow2(allow_model_requests):
    processed_workflow = await process_feature_workflow(
        component.ComponentIntelligence, {"component_name": "wget"}
    )

    logging.debug(processed_workflow)

    assert_equal(processed_workflow.status, WorkflowStatus.COMPLETED)
```

The results of workflow processing would contain output for each step the workflow executed and final output.

## Alternative Approaches
* Instead of creating generic data abstractions representing workflow we can programatically emulate the same thing - that might be
desired if we find we do not have many different kinds of workflow
* There are plenty of good, robust pipeline/workflow python modules (ex. Prefect, Luigi and Airflow / Dagster) which we could consider using
* We could adopt other frameworks (or move on from pydantic-ai)
* We could investigate more advanced approaches like https://ai.pydantic.dev/graph/
* We might find that workflow idioms are better supported using protocols such as https://a2aprotocol.ai/

## Risks & Consequences
* We might never need workflows eg. why embark on this effort if this complexity is not needed
* Multiple agents, with calling multiple LLMs will incur a cost in tokens and time to process - we need to take advantage
of pydantic-ai Usage features
* Branching conditions may seem attractive but can incur additional complexity in workflows


