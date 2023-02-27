package chatgpt_go

import "os"

func getEnvWithDefault(env, defaultValue string) string {
	v := os.Getenv(env)
	if v == "" {
		return defaultValue
	}
	return v
}
