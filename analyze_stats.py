from argparse import ArgumentParser
import csv
import re
import sys


class BrowserVersionTerm:
    engine: str
    """Browser engine name (eg. "Chrome")"""

    version: int
    """Browser engine version."""

    relation: str
    """Match relation: >, >=, ==, <= or >"""

    def __init__(self, engine: str, version: int, relation: str):
        self.engine = engine
        self.version = version
        self.relation = relation

    def matches(self, engine: str, version: int) -> bool:
        if self.engine.lower() != engine.lower():
            return False

        match self.relation:
            case ">":
                return version > self.version
            case ">=":
                return version >= self.version
            case "==":
                return version == self.version
            case "<=":
                return version <= self.version
            case "<":
                return version < self.version
            case _:
                return False


def parse_query(query: str) -> list[BrowserVersionTerm]:
    """
    Parse queries of the form "{engine}{relation}{version}, ...".
    """
    matchers = []
    for term in query.split(","):
        match = re.match("(\\w+)\\s*(<|<=|==|>=|>)\\s*(\\d+)", term)
        if not match:
            raise ValueError(f'Unable to parse query "{term}"')
        engine, relation, version = match.groups()
        version = int(version)
        matchers.append(BrowserVersionTerm(engine, version, relation))
    return matchers


def main():
    parser = ArgumentParser(
        description="""
Match user agent details against a browser version query.
"""
    )
    parser.add_argument("csv_file", help="CSV file produced by parse_access_log.py")
    parser.add_argument(
        "query",
        help="Query to match each row against. eg. 'chrome>=90,safari>=14,firefox>=90'",
    )
    args = parser.parse_args()

    terms = parse_query(args.query)

    n_skipped_rows = 0
    n_valid_rows = 0
    n_matches = 0

    with open(args.csv_file) as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            try:
                browser, browser_version, engine, engine_version, user_agent = row
            except ValueError:
                # Number of columns doesn't match expected count
                n_skipped_rows += 1
                continue

            if not engine or not engine_version:
                # Browser engine or version could not be identified
                n_skipped_rows += 1
                continue

            try:
                engine_version = int(engine_version)
            except ValueError:
                # Engine version is not a number
                n_skipped_rows += 1
                continue

            n_valid_rows += 1
            if any(term.matches(engine, engine_version) for term in terms):
                n_matches += 1

    if n_valid_rows == 0:
        print("CSV file is empty", file=sys.stderr)

    total_rows = n_valid_rows + n_skipped_rows
    valid_percent = (n_valid_rows / total_rows) * 100
    print(
        f"{total_rows} rows, {n_valid_rows} valid ({valid_percent:.1f}%), {n_skipped_rows} skipped"
    )
    match_percent = (n_matches / n_valid_rows) * 100
    print(f"{match_percent:.2f}% of rows match query")


if __name__ == "__main__":
    main()
