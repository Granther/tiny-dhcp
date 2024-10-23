package server

import (
	"gdhcp/config"
	"gdhcp/options"
)

type OptionsHandler interface {
	
}

type OptionsManager struct {
	options
}

func NewOptionsManager(config *config.Config) (*OptionsManager, error) {
	optionsMap := options.CreateOptionMap(config)

}
