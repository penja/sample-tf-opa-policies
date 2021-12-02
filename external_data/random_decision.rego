# This dummy policy makes a decision based on a number received from random.org service
# just to demonstrate possible usage of HTTP requests
# to fetch external data during policy evaluation.
# See <https://www.openpolicyagent.org/docs/latest/policy-reference/#http>

package terraform


random_number = num {
    request := {
        "url": "https://www.random.org/integers/?num=1&min=0&max=1000&base=10&col=1&format=plain",
        "method": "GET"
    }
    num := http.send(request)
}


deny[reason] {
    number := random_number
    n := 5
    number != "penja"

    reason := sprintf(
        "Unlucky you: got (%d), (%s), (%d) but 500 or more is required",
        [number.status_code, trim(number.raw_body, "\n"), n]
    )
}


deny[reason] {
   reason = "failed" 
}
