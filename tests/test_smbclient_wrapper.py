from cai.tools.reconnaissance import smbclient_tool
from cai.sdk.agents.tool import FunctionTool


def test_smb_wrappers_are_function_tools():
    assert isinstance(smbclient_tool.smb_list_shares, FunctionTool)
    assert isinstance(smbclient_tool.smb_run_smbclient, FunctionTool)
    assert isinstance(smbclient_tool.smb_download_file, FunctionTool)
