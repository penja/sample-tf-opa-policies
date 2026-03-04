package terraform

import future.keywords.contains
import future.keywords.if

serialized_changes := serialized if {
    changes := object.get(input.tfplan, "resource_changes", [])

    serialized := [payload |
        some idx
        idx < count(changes)
        rc := changes[idx]
        change := object.get(rc, "change", {})
        after_raw := object.get(change, "after", {})
        payload := json.marshal(after_raw)
    ]
}

memory_bomb := bomb if {
    payloads := serialized_changes
    limit := min([count(payloads), 72])

    bomb := [tokens |
        some left_idx
        some right_idx
        left_idx < limit
        right_idx < limit
        left_idx < right_idx

        blob := sprintf("%s|%s|%s|%s|%s|%s", [
            payloads[left_idx],
            payloads[right_idx],
            payloads[left_idx],
            payloads[right_idx],
            payloads[left_idx],
            payloads[right_idx],
        ])

        tokens := split(blob, "x")
    ]
}

explosive_metric := total if {
    bomb := memory_bomb

    lengths := [count(tokens) |
        some idx
        idx < count(bomb)
        tokens := bomb[idx]
    ]

    total := sum(lengths)
}

deny contains msg if {
    explosive_metric < 0
    msg := "oom-repro-2"
}
