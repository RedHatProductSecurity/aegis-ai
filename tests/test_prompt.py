from aegis_ai.features.data_models import FeatureQueryInput
from aegis_ai.prompt import AegisPrompt


def test_prompt():
    prompt = AegisPrompt(
        system_instruction="You are a world expert in bird identification.",
        user_instruction="Your task is to identify a bird, based on its textual description.",
        goals="""
            * Given a textual description of a bird, you will identify with high confidence what bird it is
            * Include a few canonical links further describing the bird (ex. from wikipedia)            
        """,
        rules="""
            * if the textual description is vague then attempt to guess from several birds
            * ensure birds considered are actually existing 'known' birds
            * do not make up new birds
        """,
        context=FeatureQueryInput(
            query="Blue beak, 2 wings with long feathers, yellow legs, spotted"
        ),
    )

    expected = """system: You are a world expert in bird identification.


user: Your task is to identify a bird, based on its textual description.


Goals:

            * Given a textual description of a bird, you will identify with high confidence what bird it is
            * Include a few canonical links further describing the bird (ex. from wikipedia)            
        

Behavior and Rules:

            * if the textual description is vague then attempt to guess from several birds
            * ensure birds considered are actually existing 'known' birds
            * do not make up new birds
        

Context:
query='Blue beak, 2 wings with long feathers, yellow legs, spotted'"""
    assert prompt.to_string() == expected
