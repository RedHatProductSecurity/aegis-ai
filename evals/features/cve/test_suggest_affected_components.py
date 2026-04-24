"""
Suggest affected components evaluation suite.

Uses osidb_cache CVE data. Input: cve_id. The feature uses exclude_osidb_fields=["components"]
so the model infers from title, description, etc. (no cheating).
Runnable: pytest evals/features/cve/test_suggest_affected_components.py
Optional: --sample N or AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE=N
"""

import logging
import os
import random
from pathlib import Path
from typing import Any, cast

import pytest

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestAffectedComponents
from aegis_ai.features.cve.data_models import SuggestAffectedComponentsModel
from aegis_ai.toolsets.tools.osidb import CVE

from evals.features.common import (
    FeatureMetricsEvaluator,
    ToolsUsedEvaluator,
    reflect_confidence,
    run_evaluation,
)
from evals.utils.osidb_cache import OSIDB_CACHE_DIR

logger = logging.getLogger(__name__)

SAMPLE_SEED = int(
    os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE_SEED", "42")
)

# CVE IDs added in aegis-371 component intelligence eval (evals/osidb_cache).
# Used when AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS env is not set.
# Excludes CVEs with cpython as expected (model tends to suggest 'python' instead).
# Excludes CVE-2025-23083 (nodejs): model often returns 'Node.js', causing flaky evals.
DEFAULT_CVE_IDS: tuple[str, ...] = (
    "CVE-2006-10002",
    "CVE-2006-10003",
    "CVE-2010-1975",
    "CVE-2011-1594",
    "CVE-2011-2920",
    "CVE-2011-2927",
    "CVE-2011-3344",
    "CVE-2011-4346",
    "CVE-2012-5625",
    "CVE-2013-0335",
    "CVE-2014-125112",
    "CVE-2017-20230",
    "CVE-2019-25695",
    "CVE-2021-47960",
    "CVE-2024-14030",
    "CVE-2024-14031",
    "CVE-2025-3416",
    "CVE-2025-5991",
    "CVE-2025-6052",
    "CVE-2025-11233",
    "CVE-2025-12863",
    "CVE-2025-13699",
    "CVE-2025-14087",
    "CVE-2025-22866",
    "CVE-2025-22868",
    "CVE-2025-23050",
    "CVE-2025-41118",
    "CVE-2025-42611",
    "CVE-2025-47911",
    "CVE-2025-47912",
    "CVE-2025-52881",
    "CVE-2025-55131",
    "CVE-2025-58183",
    "CVE-2025-58188",
    "CVE-2025-58190",
    "CVE-2025-59032",
    "CVE-2025-61726",
    "CVE-2025-61727",
    "CVE-2025-62518",
    "CVE-2025-62718",
    "CVE-2025-64329",
    "CVE-2025-65637",
    "CVE-2025-66442",
    "CVE-2026-0396",
    "CVE-2026-0397",
    "CVE-2026-0900",
    "CVE-2026-0988",
    "CVE-2026-0989",
    "CVE-2026-0990",
    "CVE-2026-0992",
    "CVE-2026-1462",
    "CVE-2026-1484",
    "CVE-2026-1485",
    "CVE-2026-1502",
    "CVE-2026-1519",
    "CVE-2026-1757",
    "CVE-2026-1839",
    "CVE-2026-2319",
    "CVE-2026-2320",
    "CVE-2026-2332",
    "CVE-2026-2370",
    "CVE-2026-3104",
    "CVE-2026-3119",
    "CVE-2026-3528",
    "CVE-2026-3590",
    "CVE-2026-3591",
    "CVE-2026-3889",
    "CVE-2026-3920",
    "CVE-2026-3925",
    "CVE-2026-3937",
    "CVE-2026-4371",
    "CVE-2026-4439",
    "CVE-2026-4440",
    "CVE-2026-4441",
    "CVE-2026-4442",
    "CVE-2026-4443",
    "CVE-2026-4444",
    "CVE-2026-4446",
    "CVE-2026-4447",
    "CVE-2026-4448",
    "CVE-2026-4449",
    "CVE-2026-4450",
    "CVE-2026-4451",
    "CVE-2026-4452",
    "CVE-2026-4453",
    "CVE-2026-4454",
    "CVE-2026-4455",
    "CVE-2026-4456",
    "CVE-2026-4457",
    "CVE-2026-4458",
    "CVE-2026-4459",
    "CVE-2026-4460",
    "CVE-2026-4461",
    "CVE-2026-4462",
    "CVE-2026-4463",
    "CVE-2026-4464",
    "CVE-2026-4660",
    "CVE-2026-4673",
    "CVE-2026-4674",
    "CVE-2026-4675",
    "CVE-2026-4676",
    "CVE-2026-4677",
    "CVE-2026-4678",
    "CVE-2026-4679",
    "CVE-2026-4680",
    "CVE-2026-4684",
    "CVE-2026-4685",
    "CVE-2026-4686",
    "CVE-2026-4687",
    "CVE-2026-4688",
    "CVE-2026-4689",
    "CVE-2026-4690",
    "CVE-2026-4691",
    "CVE-2026-4692",
    "CVE-2026-4693",
    "CVE-2026-4694",
    "CVE-2026-4695",
    "CVE-2026-4696",
    "CVE-2026-4697",
    "CVE-2026-4698",
    "CVE-2026-4699",
    "CVE-2026-4700",
    "CVE-2026-4701",
    "CVE-2026-4702",
    "CVE-2026-4704",
    "CVE-2026-4705",
    "CVE-2026-4706",
    "CVE-2026-4707",
    "CVE-2026-4708",
    "CVE-2026-4709",
    "CVE-2026-4710",
    "CVE-2026-4711",
    "CVE-2026-4712",
    "CVE-2026-4713",
    "CVE-2026-4714",
    "CVE-2026-4715",
    "CVE-2026-4716",
    "CVE-2026-4717",
    "CVE-2026-4718",
    "CVE-2026-4719",
    "CVE-2026-4721",
    "CVE-2026-4722",
    "CVE-2026-4723",
    "CVE-2026-4724",
    "CVE-2026-4727",
    "CVE-2026-4729",
    "CVE-2026-4732",
    "CVE-2026-4751",
    "CVE-2026-5107",
    "CVE-2026-5124",
    "CVE-2026-5272",
    "CVE-2026-5273",
    "CVE-2026-5274",
    "CVE-2026-5275",
    "CVE-2026-5276",
    "CVE-2026-5277",
    "CVE-2026-5278",
    "CVE-2026-5279",
    "CVE-2026-5280",
    "CVE-2026-5281",
    "CVE-2026-5282",
    "CVE-2026-5283",
    "CVE-2026-5284",
    "CVE-2026-5285",
    "CVE-2026-5286",
    "CVE-2026-5287",
    "CVE-2026-5288",
    "CVE-2026-5289",
    "CVE-2026-5290",
    "CVE-2026-5291",
    "CVE-2026-5292",
    "CVE-2026-5598",
    "CVE-2026-5659",
    "CVE-2026-5663",
    "CVE-2026-5731",
    "CVE-2026-5732",
    "CVE-2026-5733",
    "CVE-2026-5734",
    "CVE-2026-5735",
    "CVE-2026-5795",
    "CVE-2026-5858",
    "CVE-2026-5859",
    "CVE-2026-5860",
    "CVE-2026-5861",
    "CVE-2026-5862",
    "CVE-2026-5863",
    "CVE-2026-5864",
    "CVE-2026-5865",
    "CVE-2026-5866",
    "CVE-2026-5867",
    "CVE-2026-5868",
    "CVE-2026-5869",
    "CVE-2026-5870",
    "CVE-2026-5871",
    "CVE-2026-5872",
    "CVE-2026-5873",
    "CVE-2026-5874",
    "CVE-2026-5875",
    "CVE-2026-5876",
    "CVE-2026-5877",
    "CVE-2026-5878",
    "CVE-2026-5879",
    "CVE-2026-5880",
    "CVE-2026-5881",
    "CVE-2026-5882",
    "CVE-2026-5883",
    "CVE-2026-5884",
    "CVE-2026-5885",
    "CVE-2026-5886",
    "CVE-2026-5887",
    "CVE-2026-5888",
    "CVE-2026-5889",
    "CVE-2026-5890",
    "CVE-2026-5891",
    "CVE-2026-5892",
    "CVE-2026-5893",
    "CVE-2026-5894",
    "CVE-2026-5896",
    "CVE-2026-5897",
    "CVE-2026-5899",
    "CVE-2026-5900",
    "CVE-2026-5901",
    "CVE-2026-5902",
    "CVE-2026-5903",
    "CVE-2026-5904",
    "CVE-2026-5905",
    "CVE-2026-5906",
    "CVE-2026-5907",
    "CVE-2026-5908",
    "CVE-2026-5909",
    "CVE-2026-5910",
    "CVE-2026-5911",
    "CVE-2026-5912",
    "CVE-2026-5913",
    "CVE-2026-5914",
    "CVE-2026-5915",
    "CVE-2026-5918",
    "CVE-2026-5919",
    "CVE-2026-6231",
    "CVE-2026-6296",
    "CVE-2026-6297",
    "CVE-2026-6298",
    "CVE-2026-6299",
    "CVE-2026-6300",
    "CVE-2026-6301",
    "CVE-2026-6302",
    "CVE-2026-6303",
    "CVE-2026-6304",
    "CVE-2026-6305",
    "CVE-2026-6306",
    "CVE-2026-6307",
    "CVE-2026-6308",
    "CVE-2026-6309",
    "CVE-2026-6310",
    "CVE-2026-6311",
    "CVE-2026-6312",
    "CVE-2026-6313",
    "CVE-2026-6314",
    "CVE-2026-6315",
    "CVE-2026-6316",
    "CVE-2026-6317",
    "CVE-2026-6318",
    "CVE-2026-6319",
    "CVE-2026-6358",
    "CVE-2026-6359",
    "CVE-2026-6360",
    "CVE-2026-6361",
    "CVE-2026-6362",
    "CVE-2026-6363",
    "CVE-2026-6364",
    "CVE-2026-6414",
    "CVE-2026-6437",
    "CVE-2026-6491",
    "CVE-2026-6494",
    "CVE-2026-6654",
    "CVE-2026-6746",
    "CVE-2026-6747",
    "CVE-2026-6748",
    "CVE-2026-6749",
    "CVE-2026-6750",
    "CVE-2026-6751",
    "CVE-2026-6752",
    "CVE-2026-6753",
    "CVE-2026-6754",
    "CVE-2026-6755",
    "CVE-2026-6756",
    "CVE-2026-6757",
    "CVE-2026-6758",
    "CVE-2026-6759",
    "CVE-2026-6760",
    "CVE-2026-6761",
    "CVE-2026-6762",
    "CVE-2026-6763",
    "CVE-2026-6764",
    "CVE-2026-6765",
    "CVE-2026-6766",
    "CVE-2026-6767",
    "CVE-2026-6768",
    "CVE-2026-6769",
    "CVE-2026-6770",
    "CVE-2026-6771",
    "CVE-2026-6772",
    "CVE-2026-6773",
    "CVE-2026-6774",
    "CVE-2026-6775",
    "CVE-2026-6776",
    "CVE-2026-6777",
    "CVE-2026-6778",
    "CVE-2026-6779",
    "CVE-2026-6780",
    "CVE-2026-6781",
    "CVE-2026-6782",
    "CVE-2026-6783",
    "CVE-2026-6784",
    "CVE-2026-6785",
    "CVE-2026-6786",
    "CVE-2026-7335",
    "CVE-2026-7347",
    "CVE-2026-21998",
    "CVE-2026-22001",
    "CVE-2026-22002",
    "CVE-2026-22004",
    "CVE-2026-22005",
    "CVE-2026-22009",
    "CVE-2026-22015",
    "CVE-2026-22017",
    "CVE-2026-22735",
    "CVE-2026-22815",
    "CVE-2026-23272",
    "CVE-2026-23273",
    "CVE-2026-23275",
    "CVE-2026-23277",
    "CVE-2026-23279",
    "CVE-2026-23280",
    "CVE-2026-23281",
    "CVE-2026-23282",
    "CVE-2026-23283",
    "CVE-2026-23284",
    "CVE-2026-23285",
    "CVE-2026-23286",
    "CVE-2026-23287",
    "CVE-2026-23288",
    "CVE-2026-23289",
    "CVE-2026-23290",
    "CVE-2026-23291",
    "CVE-2026-23292",
    "CVE-2026-23293",
    "CVE-2026-23294",
    "CVE-2026-23295",
    "CVE-2026-23296",
    "CVE-2026-23297",
    "CVE-2026-23298",
    "CVE-2026-23299",
    "CVE-2026-23300",
    "CVE-2026-23301",
    "CVE-2026-23302",
    "CVE-2026-23303",
    "CVE-2026-23305",
    "CVE-2026-23306",
    "CVE-2026-23307",
    "CVE-2026-23308",
    "CVE-2026-23309",
    "CVE-2026-23310",
    "CVE-2026-23311",
    "CVE-2026-23312",
    "CVE-2026-23313",
    "CVE-2026-23314",
    "CVE-2026-23315",
    "CVE-2026-23316",
    "CVE-2026-23317",
    "CVE-2026-23318",
    "CVE-2026-23319",
    "CVE-2026-23320",
    "CVE-2026-23321",
    "CVE-2026-23323",
    "CVE-2026-23324",
    "CVE-2026-23325",
    "CVE-2026-23328",
    "CVE-2026-23329",
    "CVE-2026-23330",
    "CVE-2026-23331",
    "CVE-2026-23332",
    "CVE-2026-23333",
    "CVE-2026-23334",
    "CVE-2026-23335",
    "CVE-2026-23336",
    "CVE-2026-23337",
    "CVE-2026-23338",
    "CVE-2026-23339",
    "CVE-2026-23340",
    "CVE-2026-23341",
    "CVE-2026-23342",
    "CVE-2026-23343",
    "CVE-2026-23344",
    "CVE-2026-23345",
    "CVE-2026-23346",
    "CVE-2026-23347",
    "CVE-2026-23348",
    "CVE-2026-23349",
    "CVE-2026-23350",
    "CVE-2026-23351",
    "CVE-2026-23352",
    "CVE-2026-23353",
    "CVE-2026-23354",
    "CVE-2026-23355",
    "CVE-2026-23356",
    "CVE-2026-23357",
    "CVE-2026-23358",
    "CVE-2026-23359",
    "CVE-2026-23360",
    "CVE-2026-23361",
    "CVE-2026-23362",
    "CVE-2026-23363",
    "CVE-2026-23364",
    "CVE-2026-23365",
    "CVE-2026-23366",
    "CVE-2026-23367",
    "CVE-2026-23368",
    "CVE-2026-23369",
    "CVE-2026-23370",
    "CVE-2026-23372",
    "CVE-2026-23373",
    "CVE-2026-23374",
    "CVE-2026-23375",
    "CVE-2026-23376",
    "CVE-2026-23377",
    "CVE-2026-23378",
    "CVE-2026-23379",
    "CVE-2026-23380",
    "CVE-2026-23381",
    "CVE-2026-23382",
    "CVE-2026-23383",
    "CVE-2026-23384",
    "CVE-2026-23385",
    "CVE-2026-23386",
    "CVE-2026-23387",
    "CVE-2026-23388",
    "CVE-2026-23389",
    "CVE-2026-23390",
    "CVE-2026-23391",
    "CVE-2026-23392",
    "CVE-2026-23393",
    "CVE-2026-23394",
    "CVE-2026-23395",
    "CVE-2026-23396",
    "CVE-2026-23399",
    "CVE-2026-23400",
    "CVE-2026-23401",
    "CVE-2026-23402",
    "CVE-2026-23403",
    "CVE-2026-23404",
    "CVE-2026-23405",
    "CVE-2026-23406",
    "CVE-2026-23407",
    "CVE-2026-23408",
    "CVE-2026-23409",
    "CVE-2026-23410",
    "CVE-2026-23411",
    "CVE-2026-23413",
    "CVE-2026-23414",
    "CVE-2026-23416",
    "CVE-2026-23418",
    "CVE-2026-23419",
    "CVE-2026-23420",
    "CVE-2026-23422",
    "CVE-2026-23423",
    "CVE-2026-23424",
    "CVE-2026-23425",
    "CVE-2026-23426",
    "CVE-2026-23427",
    "CVE-2026-23428",
    "CVE-2026-23430",
    "CVE-2026-23431",
    "CVE-2026-23432",
    "CVE-2026-23433",
    "CVE-2026-23434",
    "CVE-2026-23436",
    "CVE-2026-23437",
    "CVE-2026-23438",
    "CVE-2026-23440",
    "CVE-2026-23441",
    "CVE-2026-23444",
    "CVE-2026-23445",
    "CVE-2026-23446",
    "CVE-2026-23447",
    "CVE-2026-23448",
    "CVE-2026-23449",
    "CVE-2026-23450",
    "CVE-2026-23451",
    "CVE-2026-23452",
    "CVE-2026-23453",
    "CVE-2026-23454",
    "CVE-2026-23455",
    "CVE-2026-23456",
    "CVE-2026-23457",
    "CVE-2026-23458",
    "CVE-2026-23459",
    "CVE-2026-23460",
    "CVE-2026-23461",
    "CVE-2026-23462",
    "CVE-2026-23463",
    "CVE-2026-23464",
    "CVE-2026-23465",
    "CVE-2026-23466",
    "CVE-2026-23467",
    "CVE-2026-23468",
    "CVE-2026-23469",
    "CVE-2026-23470",
    "CVE-2026-23471",
    "CVE-2026-23472",
    "CVE-2026-23474",
    "CVE-2026-23475",
    "CVE-2026-23555",
    "CVE-2026-23666",
    "CVE-2026-23869",
    "CVE-2026-23950",
    "CVE-2026-24028",
    "CVE-2026-24029",
    "CVE-2026-24842",
    "CVE-2026-25542",
    "CVE-2026-25645",
    "CVE-2026-25833",
    "CVE-2026-25834",
    "CVE-2026-25835",
    "CVE-2026-26961",
    "CVE-2026-26962",
    "CVE-2026-27140",
    "CVE-2026-27447",
    "CVE-2026-27651",
    "CVE-2026-27769",
    "CVE-2026-27784",
    "CVE-2026-27854",
    "CVE-2026-27855",
    "CVE-2026-27856",
    "CVE-2026-27858",
    "CVE-2026-27880",
    "CVE-2026-28291",
    "CVE-2026-28684",
    "CVE-2026-28741",
    "CVE-2026-28755",
    "CVE-2026-29145",
    "CVE-2026-30836",
    "CVE-2026-31389",
    "CVE-2026-31390",
    "CVE-2026-31391",
    "CVE-2026-31392",
    "CVE-2026-31393",
    "CVE-2026-31394",
    "CVE-2026-31395",
    "CVE-2026-31396",
    "CVE-2026-31399",
    "CVE-2026-31400",
    "CVE-2026-31401",
    "CVE-2026-31402",
    "CVE-2026-31403",
    "CVE-2026-31404",
    "CVE-2026-31405",
    "CVE-2026-31407",
    "CVE-2026-31409",
    "CVE-2026-31410",
    "CVE-2026-31411",
    "CVE-2026-31412",
    "CVE-2026-31413",
    "CVE-2026-31417",
    "CVE-2026-31420",
    "CVE-2026-31421",
    "CVE-2026-31422",
    "CVE-2026-31423",
    "CVE-2026-31424",
    "CVE-2026-31425",
    "CVE-2026-31426",
    "CVE-2026-31427",
    "CVE-2026-31428",
    "CVE-2026-31430",
    "CVE-2026-31431",
    "CVE-2026-31432",
    "CVE-2026-31433",
    "CVE-2026-31434",
    "CVE-2026-31435",
    "CVE-2026-31436",
    "CVE-2026-31437",
    "CVE-2026-31438",
    "CVE-2026-31439",
    "CVE-2026-31441",
    "CVE-2026-31442",
    "CVE-2026-31443",
    "CVE-2026-31444",
    "CVE-2026-31445",
    "CVE-2026-31446",
    "CVE-2026-31447",
    "CVE-2026-31448",
    "CVE-2026-31449",
    "CVE-2026-31451",
    "CVE-2026-31452",
    "CVE-2026-31453",
    "CVE-2026-31454",
    "CVE-2026-31455",
    "CVE-2026-31457",
    "CVE-2026-31458",
    "CVE-2026-31460",
    "CVE-2026-31461",
    "CVE-2026-31462",
    "CVE-2026-31463",
    "CVE-2026-31464",
    "CVE-2026-31465",
    "CVE-2026-31466",
    "CVE-2026-31468",
    "CVE-2026-31469",
    "CVE-2026-31470",
    "CVE-2026-31471",
    "CVE-2026-31472",
    "CVE-2026-31473",
    "CVE-2026-31474",
    "CVE-2026-31475",
    "CVE-2026-31476",
    "CVE-2026-31477",
    "CVE-2026-31478",
    "CVE-2026-31479",
    "CVE-2026-31481",
    "CVE-2026-31482",
    "CVE-2026-31483",
    "CVE-2026-31484",
    "CVE-2026-31485",
    "CVE-2026-31486",
    "CVE-2026-31487",
    "CVE-2026-31489",
    "CVE-2026-31490",
    "CVE-2026-31491",
    "CVE-2026-31492",
    "CVE-2026-31493",
    "CVE-2026-31494",
    "CVE-2026-31495",
    "CVE-2026-31496",
    "CVE-2026-31497",
    "CVE-2026-31498",
    "CVE-2026-31499",
    "CVE-2026-31500",
    "CVE-2026-31501",
    "CVE-2026-31502",
    "CVE-2026-31503",
    "CVE-2026-31504",
    "CVE-2026-31505",
    "CVE-2026-31506",
    "CVE-2026-31509",
    "CVE-2026-31510",
    "CVE-2026-31511",
    "CVE-2026-31512",
    "CVE-2026-31513",
    "CVE-2026-31514",
    "CVE-2026-31515",
    "CVE-2026-31516",
    "CVE-2026-31517",
    "CVE-2026-31518",
    "CVE-2026-31519",
    "CVE-2026-31520",
    "CVE-2026-31521",
    "CVE-2026-31522",
    "CVE-2026-31524",
    "CVE-2026-31525",
    "CVE-2026-31526",
    "CVE-2026-31527",
    "CVE-2026-31528",
    "CVE-2026-31529",
    "CVE-2026-31532",
    "CVE-2026-31788",
    "CVE-2026-31842",
    "CVE-2026-32144",
    "CVE-2026-32178",
    "CVE-2026-32226",
    "CVE-2026-32282",
    "CVE-2026-32285",
    "CVE-2026-32286",
    "CVE-2026-32289",
    "CVE-2026-32623",
    "CVE-2026-32748",
    "CVE-2026-32871",
    "CVE-2026-32874",
    "CVE-2026-32875",
    "CVE-2026-32935",
    "CVE-2026-32946",
    "CVE-2026-32948",
    "CVE-2026-33022",
    "CVE-2026-33023",
    "CVE-2026-33056",
    "CVE-2026-33069",
    "CVE-2026-33131",
    "CVE-2026-33132",
    "CVE-2026-33155",
    "CVE-2026-33168",
    "CVE-2026-33186",
    "CVE-2026-33227",
    "CVE-2026-33230",
    "CVE-2026-33231",
    "CVE-2026-33236",
    "CVE-2026-33256",
    "CVE-2026-33257",
    "CVE-2026-33258",
    "CVE-2026-33259",
    "CVE-2026-33260",
    "CVE-2026-33261",
    "CVE-2026-33262",
    "CVE-2026-33298",
    "CVE-2026-33306",
    "CVE-2026-33307",
    "CVE-2026-33414",
    "CVE-2026-33416",
    "CVE-2026-33487",
    "CVE-2026-33551",
    "CVE-2026-33554",
    "CVE-2026-33595",
    "CVE-2026-33596",
    "CVE-2026-33597",
    "CVE-2026-33599",
    "CVE-2026-33600",
    "CVE-2026-33601",
    "CVE-2026-33701",
    "CVE-2026-33753",
    "CVE-2026-33762",
    "CVE-2026-33815",
    "CVE-2026-33816",
    "CVE-2026-33870",
    "CVE-2026-33891",
    "CVE-2026-33894",
    "CVE-2026-33895",
    "CVE-2026-33896",
    "CVE-2026-33898",
    "CVE-2026-33936",
    "CVE-2026-34070",
    "CVE-2026-34073",
    "CVE-2026-34155",
    "CVE-2026-34165",
    "CVE-2026-34197",
    "CVE-2026-34267",
    "CVE-2026-34270",
    "CVE-2026-34271",
    "CVE-2026-34272",
    "CVE-2026-34276",
    "CVE-2026-34278",
    "CVE-2026-34293",
    "CVE-2026-34303",
    "CVE-2026-34304",
    "CVE-2026-34308",
    "CVE-2026-34444",
    "CVE-2026-34445",
    "CVE-2026-34475",
    "CVE-2026-34477",
    "CVE-2026-34478",
    "CVE-2026-34479",
    "CVE-2026-34480",
    "CVE-2026-34483",
    "CVE-2026-34513",
    "CVE-2026-34514",
    "CVE-2026-34515",
    "CVE-2026-34516",
    "CVE-2026-34517",
    "CVE-2026-34518",
    "CVE-2026-34519",
    "CVE-2026-34520",
    "CVE-2026-34525",
    "CVE-2026-34531",
    "CVE-2026-34591",
    "CVE-2026-34601",
    "CVE-2026-34610",
    "CVE-2026-34742",
    "CVE-2026-34743",
    "CVE-2026-34785",
    "CVE-2026-34871",
    "CVE-2026-34872",
    "CVE-2026-34873",
    "CVE-2026-34874",
    "CVE-2026-34875",
    "CVE-2026-34876",
    "CVE-2026-34877",
    "CVE-2026-34978",
    "CVE-2026-34986",
    "CVE-2026-35093",
    "CVE-2026-35204",
    "CVE-2026-35205",
    "CVE-2026-35206",
    "CVE-2026-35234",
    "CVE-2026-35235",
    "CVE-2026-35236",
    "CVE-2026-35237",
    "CVE-2026-35238",
    "CVE-2026-35239",
    "CVE-2026-35240",
    "CVE-2026-35339",
    "CVE-2026-35340",
    "CVE-2026-35341",
    "CVE-2026-35342",
    "CVE-2026-35343",
    "CVE-2026-35344",
    "CVE-2026-35345",
    "CVE-2026-35346",
    "CVE-2026-35347",
    "CVE-2026-35348",
    "CVE-2026-35350",
    "CVE-2026-35351",
    "CVE-2026-35352",
    "CVE-2026-35354",
    "CVE-2026-35355",
    "CVE-2026-35356",
    "CVE-2026-35357",
    "CVE-2026-35359",
    "CVE-2026-35360",
    "CVE-2026-35361",
    "CVE-2026-35362",
    "CVE-2026-35363",
    "CVE-2026-35364",
    "CVE-2026-35365",
    "CVE-2026-35366",
    "CVE-2026-35367",
    "CVE-2026-35368",
    "CVE-2026-35369",
    "CVE-2026-35370",
    "CVE-2026-35371",
    "CVE-2026-35372",
    "CVE-2026-35373",
    "CVE-2026-35374",
    "CVE-2026-35375",
    "CVE-2026-35376",
    "CVE-2026-35377",
    "CVE-2026-35378",
    "CVE-2026-35379",
    "CVE-2026-35380",
    "CVE-2026-35381",
    "CVE-2026-35515",
    "CVE-2026-35537",
    "CVE-2026-39324",
    "CVE-2026-39377",
    "CVE-2026-39378",
    "CVE-2026-39860",
    "CVE-2026-39892",
    "CVE-2026-39946",
    "CVE-2026-39984",
    "CVE-2026-40046",
    "CVE-2026-40087",
    "CVE-2026-40091",
    "CVE-2026-40097",
    "CVE-2026-40161",
    "CVE-2026-40192",
    "CVE-2026-40193",
    "CVE-2026-40200",
    "CVE-2026-40224",
    "CVE-2026-40225",
    "CVE-2026-40226",
    "CVE-2026-40228",
    "CVE-2026-40395",
    "CVE-2026-40490",
    "CVE-2026-40505",
    "CVE-2026-40602",
    "CVE-2026-40683",
    "CVE-2026-40906",
    "CVE-2026-40959",
    "CVE-2026-41080",
    "CVE-2026-41082",
    "CVE-2026-41564",
)


# count the corresponding evaluation cases in overall score but do not trigger
# assertion failures if the individual score is low
KNOWN_TO_FAIL_CVE_IDS: tuple[str, ...] = (
    "CVE-2025-64329",  # Aegis occasionally suggests 'containerd' while 'github.com/containerd/containerd' is expected
    "CVE-2025-6052",  # got ['glib2'], expected ['glib']
    "CVE-2026-1484",  # got ['glib2'], expected ['Glib']
    "CVE-2026-22815",  # got ['python-aiohttp'], expected ['aiohttp']
    "CVE-2026-26962",  # got ['rubygem-rack'], expected ['rack']
    "CVE-2026-34073",  # got ['cryptography'], expected ['python-cryptography']
    "CVE-2026-40200",  # got ['musl libc'], expected ['musl']
)


def _description_from_cve(cve: CVE) -> str:
    """Use comment_zero when non-empty, else description."""
    if cve.comment_zero and cve.comment_zero.strip():
        return cve.comment_zero.strip()
    return (cve.description or "").strip()


def _components_list(cve: CVE) -> list[str]:
    """Return list of component name strings from cache."""
    raw = cve.components or []
    out = []
    for x in raw:
        if isinstance(x, str):
            out.append(x.strip())
        elif isinstance(x, dict) and "name" in x:
            out.append(str(x["name"]).strip())
        else:
            out.append(str(x).strip())
    return [c for c in out if c]


def _load_qualifying_cves(
    cve_id_filter: set[str] | None = None,
) -> list[tuple[str, CVE]]:
    """Load CVEs from osidb_cache that have title, body, and components."""
    cache_path = Path(OSIDB_CACHE_DIR)
    if not cache_path.is_dir():
        logger.warning("OSIDB_CACHE_DIR %s is not a directory", OSIDB_CACHE_DIR)
        return []

    qualifying = []
    for json_file in sorted(cache_path.glob("CVE-*.json")):
        cve_id = json_file.stem
        if cve_id_filter is not None and cve_id not in cve_id_filter:
            continue
        try:
            with open(json_file, "r") as f:
                cve = CVE.model_validate_json(f.read())
        except Exception as e:
            logger.debug("Skip %s: %s", cve_id, e)
            continue

        title = (cve.title or "").strip()
        body = _description_from_cve(cve)
        components = _components_list(cve)

        if not title or not body or not components:
            continue
        qualifying.append((cve_id, cve))

    return qualifying


def _build_cases(
    sample_size: int | None = None,
    seed: int = SAMPLE_SEED,
    cve_id_filter: set[str] | None = None,
) -> list["SuggestAffectedComponentsCase"]:
    """Build cases from osidb_cache; optionally sample N."""
    qualifying = _load_qualifying_cves(cve_id_filter=cve_id_filter)
    cases = []

    for cve_id, cve in qualifying:
        expected_components = _components_list(cve)
        metadata: dict[str, Any] = {"cve_id": cve_id}
        if cve_id in KNOWN_TO_FAIL_CVE_IDS:
            # annotate known-to-fail evaluation cases
            metadata["known_to_fail_evaluators"] = ["ComponentsOverlapEvaluator"]

        case = SuggestAffectedComponentsCase(
            name=f"suggest-affected-components-{cve_id}",
            inputs=cve_id,
            expected_output=expected_components,
            metadata=metadata,
        )
        cases.append(case)

    if sample_size is not None and sample_size < len(cases):
        rng = random.Random(seed)
        cases = rng.sample(cases, sample_size)
        logger.info(
            "Sampled %d cases from %d qualifying (seed=%d)",
            sample_size,
            len(qualifying),
            seed,
        )

    return cases


class SuggestAffectedComponentsCase(Case):
    """Evaluation case: inputs = cve_id, expected_output = list of component names."""

    inputs: str  # cve_id
    expected_output: list[str]


def _normalized_component_sets(names: list[str]) -> set[str]:
    """Normalize component names for comparison (lowercase, strip)."""
    return {n.lower().strip() for n in names if n and isinstance(n, str)}


class ComponentsOverlapEvaluator(Evaluator[str, SuggestAffectedComponentsModel]):
    """Scores overlap between suggested and expected components.

    Prefers identical matches over partial overlap: exact set equality yields 1.0,
    while partial overlap (e.g. expected ['python','cpython'], got ['python']) scores
    lower using Jaccard on exact set intersection.
    """

    def evaluate(
        self, ctx: EvaluatorContext[str, SuggestAffectedComponentsModel]
    ) -> EvaluationReason:
        expected = cast(list[str], ctx.expected_output or [])
        suggested = getattr(ctx.output, "components", None) or []
        exp_set = _normalized_component_sets(expected)
        got_set = _normalized_component_sets(suggested)

        # Empty expected (edge case: insufficient data to infer): full score if
        # model also returns empty (correctly refrains from guessing), else 0.
        if not exp_set:
            score = 1.0 if not got_set else 0.0
            reason = None if score == 1.0 else f"got {suggested}, expected {expected}"
            return EvaluationReason(value=score, reason=reason)

        # Identical match: full score
        if exp_set == got_set:
            return EvaluationReason(value=reflect_confidence(ctx, 1.0), reason=None)

        # Partial overlap: use exact set intersection for Jaccard so we
        # differentiate identical vs partial (e.g. got ['python'] when
        # expected ['python','cpython'] scores < 1.0)
        inter = len(exp_set & got_set)
        union = len(exp_set | got_set)
        jaccard = inter / union if union else 0.0

        precision = inter / len(got_set) if got_set else 0.0
        primary_bonus = (
            precision
            if (expected and exp_set and expected[0].lower().strip() in got_set)
            else 0.0
        )

        score = 0.5 * jaccard + 0.5 * primary_bonus
        reason = f"got {suggested}, expected {expected}"
        score = reflect_confidence(ctx, score)
        return EvaluationReason(value=score, reason=reason)


async def suggest_affected_components(cve_id: CVEID) -> SuggestAffectedComponentsModel:
    """Run SuggestAffectedComponents for the given CVE (no static_context)."""
    feature = SuggestAffectedComponents(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


evals = [
    FeatureMetricsEvaluator(),
    ToolsUsedEvaluator(),
    ComponentsOverlapEvaluator(),
]


@pytest.fixture(scope="session")
def suggest_affected_components_cases(request):
    """Build cases from osidb_cache."""
    sample_size = request.config.getoption("sample", default=None)
    if sample_size is None:
        env_val = os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE")
        if env_val:
            try:
                sample_size = int(env_val)
            except ValueError:
                sample_size = None

    raw = os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS", "").strip()
    if raw:
        cve_id_filter = {cve_id.strip() for cve_id in raw.split(",") if cve_id.strip()}
    else:
        cve_id_filter = set(DEFAULT_CVE_IDS) if DEFAULT_CVE_IDS else None
    return _build_cases(
        sample_size=sample_size,
        seed=SAMPLE_SEED,
        cve_id_filter=cve_id_filter,
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_eval_suggest_affected_components(suggest_affected_components_cases):
    """Suggest affected components evaluation entry point."""
    if not suggest_affected_components_cases:
        pytest.skip(
            "No qualifying cases in osidb_cache (need title, description, components). "
            "Set OSIDB_CACHE_DIR if needed."
        )
    report = await run_evaluation(
        suggest_affected_components_cases,
        evals,
        suggest_affected_components,
        agent=rh_feature_agent,
    )
    # When ComponentsOverlapEvaluator fails, assert the reason includes both
    # expected and suggested components (per Sourcery review feedback).
    for ecase in report.cases:
        expected = ecase.expected_output or []
        suggested = getattr(ecase.output, "components", None) or []
        for result in ecase.scores.values():
            if (
                result.reason
                and "got " in result.reason
                and "expected " in result.reason
            ):
                for comp in expected:
                    assert comp in result.reason, (
                        f"Expected component '{comp}' in evaluation reason: {result.reason!r}"
                    )
                for comp in suggested:
                    assert comp in result.reason, (
                        f"Suggested component '{comp}' in evaluation reason: {result.reason!r}"
                    )
                break
