package aggregadantur

const (
	XAggregatorScopesHeader   = "X-Aggregator-Scopes"
	XAggregatorUsernameHeader = "X-Aggregator-Username"
	XAggregatorModeHeader     = "X-Aggregator-Mode"
	XAggregatorTargetsHeader  = "X-Aggregator-Targets"

	AggregateModeDefault AggregateMode = "aggregate"
)

type AggregateMode string
