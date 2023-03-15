package remfuncs

type PluggableFunctionEngine interface {
	RunFunction(funcID string, input any) (interface{}, error)
}
