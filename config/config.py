from dynaconf import LazySettings

settings = LazySettings(
    settings_files=['settings.yaml', '.secrets.yaml'],
    envvar_prefix="DYNACONF",
    environments=True,
    env='development',
)

# `envvar_prefix` = export envvars with `export DYNACONF_FOO=bar`.
# `settings_files` = Load these files in the order.
