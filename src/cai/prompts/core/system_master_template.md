<%
    import os
    from cai.util import cli_print_tool_call
    try:
        from cai.rag.vector_db import get_previous_memory
    except Exception as e:
        # Silently ignore if RAG module is not available
        pass
    from cai import is_caiextensions_memory_available
    
    # Import compact summary function
    try:
        from cai.repl.commands.memory import get_compacted_summary
        # Get agent name from the agent object
        agent_name = getattr(agent, 'name', None)
        compacted_summary = get_compacted_summary(agent_name)
    except Exception as e:
        compacted_summary = None

    # Determine model name for display (try multiple possible agent model shapes)
    try:
        model_name = None
        if hasattr(agent, 'model'):
            m = getattr(agent, 'model')
            if isinstance(m, str):
                model_name = m
            elif hasattr(m, 'model'):
                model_name = getattr(m, 'model')
            elif hasattr(m, 'name'):
                model_name = getattr(m, 'name')
        # Fallback: try agent.get_model_name() if available
        if not model_name and hasattr(agent, 'get_model_name'):
            try:
                model_name = agent.get_model_name()
            except Exception:
                model_name = None
    except Exception:
        model_name = None

    # Get system prompt from the base instructions passed to the template
    # The base instructions are passed as 'ctf_instructions' in the render context
    # We use the pre-set system_prompt variable which equals base_instructions
    # Do NOT call agent.instructions here as that would create infinite recursion!

    # Get CTF_INSIDE environment variable
    ctf_inside = os.getenv('CTF_INSIDE')
    env_context = os.getenv('CEREBRO_ENV_CONTEXT', 'true').lower()
    # Get memory from vector db if RAG is enabled
    rag_enabled = os.getenv("CEREBRO_MEMORY", "?").lower() in ["episodic", "semantic", "all"]
    memory = ""
    if rag_enabled:
        if os.getenv("CEREBRO_MEMORY", "?").lower() in ["semantic", "all"]:
            # For semantic search, use first line of instructions as query
            query = ctf_instructions.split('\n')[0].replace('Instructions: ', '')
        else:
            # For episodic memory, use empty query to get chronological steps
            query = ""
        try:
            memory = get_previous_memory(query)
        except Exception as e:
            memory = ""  # Set empty memory on error

        cli_print_tool_call(tool_name="Memory",
                   tool_args={"From": "Previous Findings"},
                   tool_output=memory,
                   interaction_input_tokens=0,
                   interaction_output_tokens=0,
                   interaction_reasoning_tokens=0,
                   total_input_tokens=0,
                   total_output_tokens=0,
                   total_reasoning_tokens=0,
                   model=(model_name or agent_name or "Python Code"),
                   debug=False)
    artifacts = None
    if is_caiextensions_memory_available() and os.getenv('CTF_NAME'):
        from caiextensions.memory import get_artifacts
        artifacts = get_artifacts(os.getenv('CTF_NAME').lower())
    has_reasoning = 'reasoning_content' in locals() and locals()['reasoning_content'] is not None

%>
${system_prompt}
% if compacted_summary:

<compacted_context>
${compacted_summary}
</compacted_context>
% endif
% if rag_enabled:

<memory>
${memory}
</memory>
% endif

% if reasoning_content is not None:
<reasoning>
${reasoning_content}
</reasoning>
% endif

% if env_context.lower() == 'true':
<%
    import platform
    import socket

    # Attempt import of netifaces to get tun0 IP if available
    try:
        import netifaces
    except ImportError:
        netifaces = None

    # Gather system info
    try:
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        os_name = platform.system()
    except:
        hostname = "local0"
        ip_addr = "127.0.0.1"
        os_name = "Linux"   

    # Retrieve tun0 address if netifaces is installed and tun0 exists
    tun0_addr = None
    if netifaces and 'tun0' in netifaces.interfaces():
        addrs = netifaces.ifaddresses('tun0')
        if netifaces.AF_INET in addrs:
            tun0_addr = addrs[netifaces.AF_INET][0].get('addr', None)
%>
<environment>
os=${os_name}
host=${hostname}
ip=${ip_addr}
% if tun0_addr:
tun0=${tun0_addr}
% endif
</environment>
% endif

% if artifacts:
<artifacts>
${artifacts}
</artifacts>
% endif
