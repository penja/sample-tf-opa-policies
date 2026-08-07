# Simple check that the cost estimate is below a threshold.

package terraform

import input.tfrun as tfrun

max_monthly_cost := 5

deny contains reason if {
	cost := tfrun.cost_estimate.proposed_monthly_cost
	cost > max_monthly_cost

	reason := sprintf(
		"Plan is too expensive: $%.2f, while up to $%d is allowed",
		[cost, max_monthly_cost],
	)
}
