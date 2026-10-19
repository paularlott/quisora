package login_test

import (
	"github.com/paularlott/quisora/internal/service"
)

func actorSuper() *service.Actor { return service.System }

func userInput(active *bool) service.UserInput { return service.UserInput{Active: active} }
