from __future__ import annotations

import re
from typing import Any


FACEPLATE_VARIANTS: list[dict[str, Any]] = [
    {
        "key": "ex3300-48p",
        "match": ("ex3300-48", "ex-3300-48"),
        "image": "img/ex3300-48p-front-high.jpg",
        "display_image": "img/ex3300-48p-front-high-cropped.jpg",
        "dimensions": (1500, 161),
        "display_dimensions": (1492, 153),
        "coordinate_dimensions": (1500, 161),
        "alt": "Juniper EX3300 48-port front panel",
        "groups": {
            "ge": {
                "pattern": re.compile(r"^ge-\d+/\d+/(\d+)$"),
                "group_size": 12,
                "group_left": 2.35,
                "group_step": 20.15,
                "column_step": 3.15,
                "row_tops": (29.2, 57.1),
                "width": 2.8,
                "height": 21.0,
            },
            "xe": {
                "pattern": re.compile(r"^(?:xe|et)-\d+/\d+/(\d+)$"),
                "group_size": 4,
                "group_left": 82.25,
                "group_step": 3.15,
                "column_step": 0,
                "row_tops": (53.8,),
                "width": 2.85,
                "height": 22.0,
            },
        },
    },
    {
        "key": "ex3300-24p",
        "match": ("ex3300-24", "ex-3300-24"),
        "image": "img/juniper-ex3300-photo.png",
        "display_image": "img/juniper-ex3300-photo-cropped.png",
        "dimensions": (1500, 452),
        "display_dimensions": (1409, 156),
        "coordinate_dimensions": (1500, 452),
        "alt": "Juniper EX3300 24-port front panel",
        "groups": {
            "ge": {
                "pattern": re.compile(r"^ge-\d+/\d+/(\d+)$"),
                "group_size": 12,
                "group_left": 43.35,
                "group_step": 18.15,
                "column_step": 3.05,
                "row_tops": (34.35, 44.55),
                "width": 2.45,
                "height": 7.9,
            },
            "xe": {
                "pattern": re.compile(r"^(?:xe|et)-\d+/\d+/(\d+)$"),
                "group_size": 4,
                "group_left": 79.35,
                "group_step": 3.0,
                "column_step": 0,
                "row_tops": (43.9,),
                "width": 2.65,
                "height": 8.2,
            },
        },
    },
]

DEFAULT_FACEPLATE = FACEPLATE_VARIANTS[-1]


def get_faceplate(model: str | None) -> dict[str, Any]:
    normalized = (model or "").lower().replace("_", "-")
    for variant in FACEPLATE_VARIANTS:
        if any(token in normalized for token in variant["match"]):
            return variant
    return DEFAULT_FACEPLATE


def _group_for_port(name: str, faceplate: dict[str, Any]) -> tuple[dict[str, Any] | None, int | None]:
    for group in faceplate["groups"].values():
        match = group["pattern"].match(name)
        if match:
            return group, int(match.group(1))
    return None, None


def port_position(name: str, model: str | None = None) -> tuple[float, float, float, float]:
    faceplate = get_faceplate(model)
    group, port_number = _group_for_port(name, faceplate)
    if group is None or port_number is None:
        return (0.0, 0.0, 0.0, 0.0)

    group_size = group["group_size"]
    group_number, local_number = divmod(port_number, group_size)
    columns = len(group["row_tops"]) and group_size // len(group["row_tops"])
    row, column = divmod(local_number, columns)
    left = group["group_left"] + group_number * group["group_step"] + column * group["column_step"]
    top = group["row_tops"][row]
    source_width, source_height = faceplate["coordinate_dimensions"]
    display_width, display_height = faceplate["display_dimensions"]
    return (
        left * source_width / display_width,
        top * source_height / display_height,
        group["width"] * source_width / display_width,
        group["height"] * source_height / display_height,
    )


def port_is_inverted(name: str, model: str | None = None) -> bool:
    group, port_number = _group_for_port(name, get_faceplate(model))
    if group is None or port_number is None:
        return False
    row_count = len(group["row_tops"])
    if row_count < 2:
        return False
    columns = group["group_size"] // row_count
    return (port_number % group["group_size"]) // columns == 1
