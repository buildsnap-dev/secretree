package app

import "github.com/buildsnap-dev/secretree/internal/gitx"

func gitxRunEnvImpl(dir string, env []string, args ...string) (string, error) {
	return gitx.RunEnv(dir, env, nil, args...)
}
