# install the apport exception handler if available
try:
    import apport_python_hook
except ImportError:
    pass
else:
    apport_python_hook.install()

# Cerberus runtime: execute venv sitecustomize to apply LiteLLM safe defaults if present
try:
    import runpy, os
    venv_sc = '/opt/cerberus-venv/lib/python3.13/site-packages/sitecustomize.py'
    if os.path.exists(venv_sc):
        try:
            runpy.run_path(venv_sc, run_name='__cerberus_sitecustomize__')
        except Exception:
            pass
except Exception:
    pass
