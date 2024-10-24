package domain

import (
	"github.com/todennus/backend/domain/definition"
	"github.com/todennus/x/scope"
)

var Actions, actionMap = scope.DefineAction[definition.Actions]()
var Resources, resourceMap = scope.DefineResource[definition.Resource]()
var ScopeEngine = scope.NewEngine("todennus", actionMap, resourceMap)
