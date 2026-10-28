"""Guards for SQL generation prompt rules.

These tests keep the template-level fixes for common PostgreSQL and
aggregation mistakes in place:

1. PostgreSQL ROUND/division on double precision must cast to numeric.
2. Identifiers containing a percent sign keep a single ``%``.
3. Ratio and average fields are re-aggregated from numerator/denominator
   instead of being averaged or summed directly.
"""

import os

import yaml

_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"
)


def _load(relative_path):
    with open(os.path.join(_TEMPLATES_DIR, relative_path), encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_postgres_round_rule_requires_numeric_cast():
    template = _load(os.path.join("sql_examples", "PostgreSQL.yaml"))["template"]
    other_rule = template["other_rule"]

    assert 'id="postgres-numeric-cast"' in other_rule
    assert "::numeric" in other_rule
    assert "ROUND(double precision, integer)" in other_rule


def test_postgres_examples_cast_before_round():
    examples = _load(os.path.join("sql_examples", "PostgreSQL.yaml"))["template"][
        "basic_example"
    ]

    assert 'ROUND(("t1"."折扣率" * 100)::numeric, 2)' in examples
    assert 'ROUND(("u"."active_ratio" * 100)::numeric, 2)' in examples
    # The uncast form may only appear as a labelled counter-example.
    bad_line = next(
        line
        for line in examples.splitlines()
        if 'ROUND("t1"."折扣率" * 100, 2)' in line
    )
    assert "错误" in bad_line


def test_generic_rules_cover_identifier_percent_and_ratio_aggregation():
    rules = _load("template.yaml")["template"]["sql"]["generate_rules"]

    assert 'id="identifier-special-char"' in rules
    assert '"就业率(%)"' in rules
    assert '"就业率(%%)"' in rules
    assert 'id="aggregate-ratio-and-average"' in rules
    assert "NULLIF(SUM(数量), 0)" in rules


def test_templates_format_without_placeholder_errors():
    base = _load("template.yaml")["template"]
    postgres = _load(os.path.join("sql_examples", "PostgreSQL.yaml"))["template"]

    postgres["other_rule"].format(
        multi_table_condition=base["sql"]["multi_table_condition"]
    )
    rules = base["sql"]["generate_rules"].format(
        lang="简体中文",
        sqlbot_name="SQLBot",
        base_sql_rules="",
        basic_sql_examples="",
        example_engine="PostgreSQL",
        example_answer_1="",
        example_answer_2="",
        example_answer_3="",
    )
    assert "identifier-special-char" in rules
