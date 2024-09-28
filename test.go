package main

import (
	"fmt"

    "github.com/spf13/viper"
)

func loadConfig(filename string) (map[string]interface{}, error) {
    viper.SetConfigFile(filename)
    err := viper.ReadInConfig()
    if err != nil {
        return nil, err
    }

    return viper.AllSettings(), nil
}

func main() {
	x, _ := loadConfig("./config.yml")
	fmt.Println(x["metal"]["port"])
}