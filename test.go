package main

import (
	"log"
    "fmt"
    "encoding/json"

    // "github.com/spf13/viper"
)

// func loadConfig(filename string) (map[string]interface{}, error) {
//     viper.SetConfigFile(filename)
//     err := viper.ReadInConfig()
//     if err != nil {
//         return nil, err
//     }

//     return viper.AllSettings(), nil
// }

// func main() {
// 	x, _ := loadConfig("./config.yml")
// 	fmt.Println(x["metal"]["port"])
// }

type Server struct {
    Port 			int `json:"port"`
    ListenInterface	string `json:"listen_interface"`
    NumWorkers		int	`json:"num_workers"`
}

type DHCP struct {
    SubnetMask		string `json:"subnet_mask"`
    Router			[]string `json:"router"`
}

type Config struct {
    Server Server `json:"server"`
    DHCP   DHCP `json:"dhcp"`
}

func main() {
	// viper.SetConfigName("config") // Name of the file without extension
    // viper.SetConfigType("json")   // File format (json, yaml, etc.)
    // viper.AddConfigPath(".")      // Path to look for the file

    // // Read the config file
    // if err := viper.ReadInConfig(); err != nil {
    //     log.Fatalf("Error reading config file, %s", err)
    // }

    // // Create a config struct
    // var config Config

    // // Unmarshal the JSON data into the struct
    // err := viper.Unmarshal(&config)
    // if err != nil {
    //     log.Fatalf("Unable to unmarshal config, %v", err)
    // }

    config := Config{
        Server: Server{
            Port: 100,
            ListenInterface: "any",
            NumWorkers: 100,
        },
        DHCP: DHCP {
            SubnetMask: "255.255.255.0",
            Router: []string{"192.168.1.1"},
        },
    }


    jsonData, err := json.MarshalIndent(config, "", "    ")
    if err != nil {
        log.Fatalf("Error marshaling to JSON, %v", err)
    }

    // Output the JSON string
    fmt.Println(string(jsonData))
    // Marshal 

    // Output the config struct values
    // fmt.Printf("Server: %s\n", config.Server)
    // fmt.Printf("Port: %d\n", config.Port)
    // fmt.Printf("Database User: %s\n", config.Database.User)
    // fmt.Printf("Database Password: %s\n", config.Database.Password)
    // fmt.Printf("Database Name: %s\n", config.Database.DBName)
}