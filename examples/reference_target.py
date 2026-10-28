"""JSON command protocol example backed by real local client threads."""

import json
import sys

from traceweaver.runtime import threaded_target


def main():
    request = json.load(sys.stdin)
    case = request["case"]
    by_id = {event["id"]: event for event in case["operations"]}
    schedule = [by_id[key] for key in request["schedule"]]
    _, history = threaded_target(case.get("adapter_overlap", 2))(case, schedule)
    json.dump({"history": history}, sys.stdout, allow_nan=False)


if __name__ == "__main__":
    main()
