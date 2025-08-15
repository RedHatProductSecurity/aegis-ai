from collections import defaultdict

from nltk import pos_tag
from nltk.corpus import stopwords
from nltk.corpus import wordnet as wn
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize


def install_nltk_deps():
    import nltk

    nltk.download("punkt")
    nltk.download("punkt_tab")
    nltk.download("wordnet")
    nltk.download("averaged_perceptron_tagger_eng")
    nltk.download("averaged_perceptron_tagger")
    nltk.download("stopwords")


def normalize_text(text_value):
    # XXX: This transformation is currently disabled.
    return text_value

    description = word_tokenize(text_value)

    # identify each token as a noun, verb, adjective, adverb
    tag_map = defaultdict(lambda: wn.NOUN)
    tag_map["J"] = wn.ADJ
    tag_map["V"] = wn.VERB
    tag_map["R"] = wn.ADV

    # reduce variations by lemmatizing
    words = []
    word_Lemmatized = WordNetLemmatizer()
    for word, tag in pos_tag(description):
        if word not in stopwords.words("english"):
            word_final = word_Lemmatized.lemmatize(word, tag_map[tag[0]])
            words.append(word_final)

    output = " ".join(words)
    print(f'<-- "{text_value}"\n')
    print(f'--> "{output}"\n\n')
    return output
