import json
import sys
import typing

from jinja2 import Template

import vyos.opmode
from vyos.ifconfig import VRRP
from vyos.ifconfig.vrrp import VRRPNoData

VRRP_AUTH_NONE = 0
VRRP_AUTH_PASS = 1
VRRP_AUTH_AH = 2

# https://github.com/acassen/keepalived/blob/59c39afe7410f927c9894a1bafb87e398c6f02be/keepalived/include/vrrp.h#L417
VRRP_STATE_INIT = 0
VRRP_STATE_BACK = 1
VRRP_STATE_MAST = 2
VRRP_STATE_FAULT = 3

VRRP_AUTH_TO_NAME = {
    VRRP_AUTH_NONE: 'NONE',
    VRRP_AUTH_PASS: 'SIMPLE_PASSWORD',
    VRRP_AUTH_AH: 'IPSEC_AH',
}

VRRP_STATE_TO_NAME = {
    VRRP_STATE_INIT: 'INIT',
    VRRP_STATE_BACK: 'BACKUP',
    VRRP_STATE_MAST: 'MASTER',
    VRRP_STATE_FAULT: 'FAULT',
}

def _get_raw_data(group_name: str = None) -> list:
    """
    Retrieve raw JSON data for all VRRP groups.

    Args:
        group_name (str, optional): If provided, filters the data to only
            include the specified vrrp group.

    Returns:
        list: A list of raw JSON data for VRRP groups, filtered by group_name
            if specified.
    """
    try:
        output = VRRP.collect('json')
    except VRRPNoData as e:
        raise vyos.opmode.DataUnavailable(f'{e}')

    data = json.loads(output)

    if not data:
        return []

    if group_name is not None:
        for rec in data:
            if rec['data'].get('iname') == group_name:
                return [rec]
        return []
    return data
def _process_field(data: dict, field: str, true_value: str, false_value: str):
    """
    Updates the given field in the data dictionary with a specified value based
        on its truthiness.

    Args:
        data (dict): The dictionary containing the field to be processed.
        field (str): The key representing the field in the dictionary.
        true_value (str): The value to set if the field's value is truthy.
        false_value (str): The value to set if the field's value is falsy.

    Returns:
        None: The function modifies the dictionary in place.
    """
    data[field] = true_value if data.get(field) else false_value

def _get_formatted_detail_output(data: list) -> list:
    """
    Prepare formatted detail information output from the given data.

    Args:
        data (list): A list of dictionaries containing vrrp grop information
            and statistics.

    Returns:
        str: Rendered detail info output based on the provided data.
    """
    instances = list()
    for instance in data:
        instance['data']['state'] = VRRP_STATE_TO_NAME.get(
            instance['data'].get('state'), 'unknown'
        )
        instance['data']['wantstate'] = VRRP_STATE_TO_NAME.get(
            instance['data'].get('wantstate'), 'unknown'
        )
        instance['data']['auth_type'] = VRRP_AUTH_TO_NAME.get(
            instance['data'].get('auth_type'), 'unknown'
        )
        _process_field(instance['data'], 'lower_prio_no_advert', 'false', 'true')
        _process_field(instance['data'], 'higher_prio_send_advert', 'true', 'false')
        _process_field(instance['data'], 'accept', 'Enabled', 'Disabled')
        _process_field(instance['data'], 'notify_deleted', 'Deleted', 'Fault')
        _process_field(instance['data'], 'smtp_alert', 'yes', 'no')
        _process_field(instance['data'], 'nopreempt', 'Disabled', 'Enabled')
        _process_field(instance['data'], 'promote_secondaries', 'Enabled', 'Disabled')
        instance['data']['vips'] = instance['data'].get('vips', False)
        instance['data']['evips'] = instance['data'].get('evips', False)
        instance['data']['vroutes'] = instance['data'].get('vroutes', False)
        instance['data']['vrules'] = instance['data'].get('vrules', False)

        instances.append(instance['data'])

    return instances

def show_detail(
    raw: bool, group_name: typing.Optional[str] = None
) -> typing.Union[list, str]:
    """
    Display detailed information about the VRRP group.

    Args:
        raw (bool): If True, return raw data instead of formatted output.
        group_name (str, optional): Filter the data by a specific group name,
            if provided.

    Returns:
        list or str: Raw data if `raw` is True, otherwise a formatted detail
            output.
    """
    data = _get_raw_data(group_name)

    if raw:
        return _get_formatted_detail_output(data)

    else:
        print("This function is intended for GraphQL Usage only. VRRP group details are not available in this version.")
        return []


def show_statistics(
    raw: bool, group_name: typing.Optional[str] = None
) -> typing.Union[list, str]:
    """
    Display VRRP group statistics.

    Args:
        raw (bool): If True, return raw data instead of formatted output.
        group_name (str, optional): Filter the data by a specific group name,
            if provided.

    Returns:
        list or str: Raw data if `raw` is True, otherwise a formatted statistic
            output.
    """
    data = _get_raw_data(group_name)

    if raw:
        return data

    else:
        print("This function is intended for GraphQL Usage only. VRRP group statistics are not available in this version.")
        return []


def show_summary(raw: bool) -> typing.Union[list, str]:
    """
    Display a summary of VRRP group.

    Args:
        raw (bool): If True, return raw data instead of formatted output.

    Returns:
        list or str: Raw data if `raw` is True, otherwise a formatted summary output.
    """
    data = _get_raw_data()

    if raw:
        return data

    else:
        print("This function is intended for GraphQL Usage only. VRRP group summary is not available in this version.")
        return []