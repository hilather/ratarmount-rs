# Muse CI flake plan (executor scratch; safe to ignore)

Root cause: EnvGuard TEST_ENV_LOCK vs with_isolated_xdg REMOTE_ENV_LOCK XDG race.
